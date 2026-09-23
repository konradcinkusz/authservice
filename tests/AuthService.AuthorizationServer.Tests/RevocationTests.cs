using System.Net;
using System.Net.Http.Json;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// Revocation (AC6): the existing global operation now ends MCP connections too, a user can end
/// one client's connection, and permanent deletion leaves nothing of the user behind in the
/// authorization server's rows, which have no foreign key.
/// </summary>
public class RevocationTests : IAsyncLifetime
{
    private AuthorizationServerFactory _factory = null!;
    private AuthorizationFlowClient _flow = null!;

    public async Task InitializeAsync()
    {
        _factory = new AuthorizationServerFactory();
        await _factory.InitializeAsync();
        _flow = new AuthorizationFlowClient(_factory);
    }

    public Task DisposeAsync()
    {
        _flow.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Logout_ends_the_users_mcp_connections()
    {
        var (email, apiTokens) = await _flow.Backchannel.RegisterAsync();
        var mcp = await _flow.ConnectAsync(email);

        using var logout = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout").WithBearer(apiTokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await _flow.Backchannel.SendAsync(logout)).StatusCode);

        await AssertRefreshRefusedAsync(mcp.RefreshToken!);
    }

    [Fact]
    public async Task A_password_change_ends_the_users_mcp_connections()
    {
        var (email, apiTokens) = await _flow.Backchannel.RegisterAsync();
        var mcp = await _flow.ConnectAsync(email);

        using var change = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/change-password")
        {
            Content = JsonContent.Create(new { currentPassword = TestAccounts.Password, newPassword = "N3w-Passw0rd!" })
        };
        Assert.Equal(HttpStatusCode.OK, (await _flow.Backchannel.SendAsync(change.WithBearer(apiTokens.AccessToken))).StatusCode);

        await AssertRefreshRefusedAsync(mcp.RefreshToken!);
    }

    [Fact]
    public async Task An_admin_revoking_sessions_ends_the_users_mcp_connections()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var mcp = await _flow.ConnectAsync(email);

        var (adminEmail, _) = await _flow.Backchannel.RegisterAsync();
        await _factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            await users.AddToRoleAsync((await users.FindByEmailAsync(adminEmail))!, "Admin");
        });
        var admin = await _flow.Backchannel.LoginAsync(adminEmail);

        using var revoke = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/admin/users/{await UserIdAsync(email)}/revoke-sessions")
            .WithBearer(admin.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await _flow.Backchannel.SendAsync(revoke)).StatusCode);

        await AssertRefreshRefusedAsync(mcp.RefreshToken!);
    }

    [Fact]
    public async Task A_user_can_disconnect_one_client_and_is_asked_to_consent_again()
    {
        var (email, apiTokens) = await _flow.Backchannel.RegisterAsync();
        var mcp = await _flow.ConnectAsync(email);

        using var disconnect = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/auth/connected-clients/{AuthorizationServerFactory.ClientId}")
            .WithBearer(apiTokens.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await _flow.Backchannel.SendAsync(disconnect)).StatusCode);

        await AssertRefreshRefusedAsync(mcp.RefreshToken!);

        // The remembered consent went with it (N2).
        var again = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "again"));
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(again, "/connect/consent"), await AuthorizationFlowClient.DescribeAsync(again));

        await _factory.WithScopeAsync(async services =>
        {
            var audit = await services.GetRequiredService<ApplicationDbContext>().AuditEvents.AsNoTracking()
                .SingleAsync(a => a.Action == AuditAction.OAuthClientRevoked);
            Assert.Equal(await UserIdAsync(email), audit.ActorUserId);
        });
    }

    [Fact]
    public async Task Disconnecting_a_client_touches_no_one_elses_connection()
    {
        var (alice, aliceApi) = await _flow.Backchannel.RegisterAsync();
        var aliceMcp = await _flow.ConnectAsync(alice);

        using var bob = new AuthorizationFlowClient(_factory);
        var (bobEmail, _) = await bob.Backchannel.RegisterAsync();
        var bobMcp = await bob.ConnectAsync(bobEmail);

        using var disconnect = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/auth/connected-clients/{AuthorizationServerFactory.ClientId}")
            .WithBearer(aliceApi.AccessToken);
        await _flow.Backchannel.SendAsync(disconnect);

        await AssertRefreshRefusedAsync(aliceMcp.RefreshToken!);
        Assert.Equal(HttpStatusCode.OK, (await bob.RefreshAsync(bobMcp.RefreshToken!)).StatusCode);
    }

    [Fact]
    public async Task Disconnecting_an_unknown_client_is_not_found()
    {
        var (_, apiTokens) = await _flow.Backchannel.RegisterAsync();

        using var disconnect = new HttpRequestMessage(HttpMethod.Delete, "/api/v1/auth/connected-clients/no-such-client").WithBearer(apiTokens.AccessToken);

        Assert.Equal(HttpStatusCode.NotFound, (await _flow.Backchannel.SendAsync(disconnect)).StatusCode);
    }

    [Fact]
    public async Task Disconnecting_requires_the_users_own_token()
    {
        var mcpTokenHolder = await _flow.Backchannel.RegisterAsync();
        var mcp = await _flow.ConnectAsync(mcpTokenHolder.Email);

        using var anonymous = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/auth/connected-clients/{AuthorizationServerFactory.ClientId}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await _flow.Backchannel.SendAsync(anonymous)).StatusCode);

        // An MCP token is for the MCP server, not for this API.
        using var withMcpToken = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/auth/connected-clients/{AuthorizationServerFactory.ClientId}")
            .WithBearer(mcp.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _flow.Backchannel.SendAsync(withMcpToken)).StatusCode);
    }

    [Fact]
    public async Task Permanent_deletion_removes_the_users_authorization_server_rows()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        await _flow.ConnectAsync(email);
        var userId = await UserIdAsync(email);

        await _factory.WithScopeAsync(async services =>
        {
            var user = await services.GetRequiredService<UserManager<ApplicationUser>>().FindByIdAsync(userId);
            user!.IsDeleted = true;
            user.DeletedAt = DateTime.UtcNow.AddDays(-31);
            user.ScheduledPermanentDeletionAt = DateTime.UtcNow.AddMinutes(-1);
            await services.GetRequiredService<UserManager<ApplicationUser>>().UpdateAsync(user);
        });

        // The reaper's step, run directly rather than waiting for its hourly loop.
        await ActivatorUtilities.CreateInstance<UserCleanupService>(_factory.Services).CleanupExpiredUsersAsync(CancellationToken.None);

        await _factory.WithScopeAsync(async services =>
        {
            Assert.Null(await services.GetRequiredService<UserManager<ApplicationUser>>().FindByIdAsync(userId));
            Assert.Empty(await ToListAsync(services.GetRequiredService<IOpenIddictAuthorizationManager>().FindBySubjectAsync(userId)));
            Assert.Empty(await ToListAsync(services.GetRequiredService<IOpenIddictTokenManager>().FindBySubjectAsync(userId)));
        });
    }

    [Fact]
    public async Task Pruning_removes_expired_interactions_and_leaves_live_grants()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var mcp = await _flow.ConnectAsync(email);

        await _factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            context.AuthorizationInteractions.Add(new AuthorizationInteraction
            {
                HandleHash = TokenHasher.Hash("expired-handle"),
                BrowserBindingHash = TokenHasher.Hash("binding"),
                ClientId = AuthorizationServerFactory.ClientId,
                RequestQuery = "?client_id=claude-test",
                Scopes = AuthorizationServerFactory.Scope,
                Resource = AuthorizationServerFactory.Resource,
                CreatedAt = DateTime.UtcNow.AddHours(-3),
                ExpiresAt = DateTime.UtcNow.AddHours(-2)
            });
            await context.SaveChangesAsync();
        });

        await ActivatorUtilities.CreateInstance<UserCleanupService>(_factory.Services).PruneAuthorizationServerAsync(CancellationToken.None);

        await _factory.WithScopeAsync(async services =>
            Assert.Empty(await services.GetRequiredService<ApplicationDbContext>().AuthorizationInteractions.ToListAsync()));
        Assert.Equal(HttpStatusCode.OK, (await _flow.RefreshAsync(mcp.RefreshToken!)).StatusCode);
    }

    private async Task AssertRefreshRefusedAsync(string refreshToken)
    {
        var response = await _flow.RefreshAsync(refreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", await AuthorizationFlowClient.ReadErrorAsync(response));
    }

    private async Task<string> UserIdAsync(string email)
    {
        string id = string.Empty;
        await _factory.WithScopeAsync(async services =>
            id = (await services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email))!.Id);
        return id;
    }

    private static async Task<List<object>> ToListAsync(IAsyncEnumerable<object> source)
    {
        var list = new List<object>();
        await foreach (var item in source)
            list.Add(item);
        return list;
    }
}
