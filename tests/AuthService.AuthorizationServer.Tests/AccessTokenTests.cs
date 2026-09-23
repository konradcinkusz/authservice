using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Data;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// MCP access tokens (AC4): signed with the existing key and kid, not encrypted, verifiable from
/// the JWKS alone, audience-bound to the resource, and carrying the claims existing tokens carry
/// under the same names (A9). Also the rolling-rotation question F8 left open.
/// </summary>
public class AccessTokenTests : IAsyncLifetime
{
    private const string NameIdentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
    private const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    private const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

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
    public async Task The_token_is_the_documented_contract_signed_with_the_published_key()
    {
        var (email, userId, organizationId) = await CreateEnrichedUserAsync();

        var tokens = await _flow.ConnectAsync(email);

        // A compact JWS, not a JWE: three segments, RS256, typed as an access token.
        using var header = TestAccounts.DecodeSegment(tokens.AccessToken, 0);
        Assert.Equal(["alg", "kid", "typ"], header.RootElement.PropertyNames());
        Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("at+jwt", header.RootElement.GetProperty("typ").GetString());

        var jwks = new JsonWebKeySet(await _flow.Backchannel.GetStringAsync("/.well-known/jwks.json"));
        Assert.Equal(Assert.Single(jwks.Keys).Kid, header.RootElement.GetProperty("kid").GetString());

        using var payload = TestAccounts.DecodeSegment(tokens.AccessToken, 1);
        var root = payload.RootElement;

        // A9: the protocol claims, and the enriched claims under the names existing tokens carry.
        // Nothing of the library's own (oi_*) and no refresh or identity material.
        string[] expected =
        [
            "iss", "aud", "sub", "client_id", "scope", "jti", "iat", "exp",
            "email", NameIdentifier, Name, Role, "organization", $"organization:{organizationId}:role"
        ];
        Assert.Equal(expected.Order(StringComparer.Ordinal), root.PropertyNames());

        Assert.Equal(AuthorizationServerFactory.Issuer, root.GetProperty("iss").GetString());
        Assert.Equal(AuthorizationServerFactory.Resource, root.GetProperty("aud").GetString());
        Assert.Equal(userId, root.GetProperty("sub").GetString());
        Assert.Equal(userId, root.GetProperty(NameIdentifier).GetString());
        Assert.Equal(AuthorizationServerFactory.ClientId, root.GetProperty("client_id").GetString());
        Assert.Equal("notes:read offline_access", root.GetProperty("scope").GetString());
        Assert.Equal("Admin", root.GetProperty(Role).GetString());
        Assert.Equal("Owner", root.GetProperty($"organization:{organizationId}:role").GetString());

        // N1: fifteen minutes.
        var lifetime = root.GetProperty("exp").GetInt64() - root.GetProperty("iat").GetInt64();
        Assert.Equal(15 * 60, lifetime);
        Assert.InRange(tokens.ExpiresIn, 15 * 60 - 60, 15 * 60); // counted from the response, not from issuance

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(tokens.AccessToken, new TokenValidationParameters
        {
            ValidIssuer = AuthorizationServerFactory.Issuer,
            ValidAudience = AuthorizationServerFactory.Resource,
            IssuerSigningKeys = jwks.GetSigningKeys()
        });
        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task Authservice_own_api_refuses_an_mcp_token()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me").WithBearer(tokens.AccessToken);
        var response = await _flow.Backchannel.SendAsync(request);

        // Its audience is the MCP server, not authservice: the :2fa precedent.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_resource_server_for_another_audience_refuses_the_token()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);

        await using var other = await TestResourceServer.StartAsync(_factory, resource: "https://other.example.test/mcp");

        Assert.Equal(HttpStatusCode.Unauthorized, (await other.CallAsync(tokens.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task A_refresh_carries_the_users_current_roles()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);

        using (var before = TestAccounts.DecodeSegment(tokens.AccessToken, 1))
            Assert.False(before.RootElement.TryGetProperty(Role, out _));

        await _factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            await users.AddToRoleAsync((await users.FindByEmailAsync(email))!, "Admin");
        });

        var refreshed = await AuthorizationFlowClient.ReadTokensAsync(await _flow.RefreshAsync(tokens.RefreshToken!));

        using var after = TestAccounts.DecodeSegment(refreshed.AccessToken, 1);
        Assert.Equal("Admin", after.RootElement.GetProperty(Role).GetString());
    }

    [Fact]
    public async Task The_database_holds_no_token_that_could_be_presented()
    {
        // IDENTITY-AND-ACCOUNTS.md §12, checked in the token mode actually used: refresh and
        // access tokens are held only by the client, with a status row here and no payload; an
        // authorization code is a reference whose hash, not value, is the lookup key.
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var redirect = await _flow.AuthorizeHostedAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, "state"), email);
        var code = AuthorizationFlowClient.Query(redirect)["code"];
        var tokens = await AuthorizationFlowClient.ReadTokensAsync(await _flow.ExchangeCodeAsync(code, pkce.Verifier));

        await _factory.WithScopeAsync(async services =>
        {
            var rows = await services.GetRequiredService<ApplicationDbContext>()
                .Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreToken>().AsNoTracking().ToListAsync();

            var issued = rows.Where(r => r.Type is "urn:ietf:params:oauth:token-type:refresh_token" or "urn:ietf:params:oauth:token-type:access_token").ToList();
            Assert.Equal(2, issued.Count);
            Assert.All(issued, row =>
            {
                Assert.Null(row.Payload);
                Assert.Null(row.ReferenceId);
            });

            var codeRow = Assert.Single(rows, r => r.Type == "urn:openiddict:params:oauth:token-type:authorization_code");
            Assert.NotEqual(code, codeRow.ReferenceId);
            Assert.DoesNotContain(code, codeRow.Payload ?? string.Empty, StringComparison.Ordinal);
            Assert.All(rows, row => Assert.DoesNotContain(tokens.RefreshToken!, row.Payload ?? string.Empty, StringComparison.Ordinal));
        });
    }

    [Fact]
    public async Task A_refresh_token_issued_before_a_key_rotation_still_refreshes_after_it()
    {
        // F8. Key A signs, and a connection is made.
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);

        // The same deployment, restarted with key B signing and key A kept for validation —
        // the rolling rotation IDENTITY-AND-ACCOUNTS.md §10 prescribes.
        using var keyB = RSA.Create(2048);
        using var rotated = new AuthorizationServerFactory(
            settings =>
            {
                settings["AuthorizationServer:Clients:0:ClientSecret"] = _factory.ClientSecret;
                settings["AuthorizationServer:EncryptionKey"] = _factory.EncryptionKey;
                settings["Jwt:PreviousPublicKeyPem"] = _factory.SigningKey.ExportSubjectPublicKeyInfoPem();
            },
            signingKey: keyB,
            sharedConnection: _factory.Connection);
        await rotated.InitializeAsync();
        using var flow = new AuthorizationFlowClient(rotated);

        var refreshed = await AuthorizationFlowClient.ReadTokensAsync(
            await flow.TokenAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = tokens.RefreshToken!,
                ["resource"] = AuthorizationServerFactory.Resource
            }, _factory.ClientSecret));

        using var header = TestAccounts.DecodeSegment(refreshed.AccessToken, 0);
        Assert.Equal(DiscoveryTests.Thumbprint(keyB), header.RootElement.GetProperty("kid").GetString());

        var published = new JsonWebKeySet(await flow.Backchannel.GetStringAsync("/.well-known/jwks.json"));
        Assert.Equal(
            new[] { DiscoveryTests.Thumbprint(_factory.SigningKey), DiscoveryTests.Thumbprint(keyB) }.Order(),
            published.Keys.Select(k => k.Kid).Order());
    }

    [Fact]
    public async Task Without_the_previous_key_a_rotation_ends_every_connection()
    {
        // The reason the runbook says to keep the previous key: its absence is not silent.
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);

        using var rotated = new AuthorizationServerFactory(
            settings =>
            {
                settings["AuthorizationServer:Clients:0:ClientSecret"] = _factory.ClientSecret;
                settings["AuthorizationServer:EncryptionKey"] = _factory.EncryptionKey;
            },
            sharedConnection: _factory.Connection);
        await rotated.InitializeAsync();
        using var flow = new AuthorizationFlowClient(rotated);

        var response = await flow.TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = tokens.RefreshToken!
        }, _factory.ClientSecret);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", await AuthorizationFlowClient.ReadErrorAsync(response));
    }

    private async Task<(string Email, string UserId, string OrganizationId)> CreateEnrichedUserAsync()
    {
        var (email, tokens) = await _flow.Backchannel.RegisterAsync();

        string userId = string.Empty;
        await _factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByEmailAsync(email);
            userId = user!.Id;
            await users.AddToRoleAsync(user, "Admin");
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/organizations")
        {
            Content = JsonContent.Create(new { name = "Acme" })
        };
        var created = await _flow.Backchannel.SendAsync(request.WithBearer(tokens.AccessToken));
        created.EnsureSuccessStatusCode();
        using var organization = JsonDocument.Parse(await created.Content.ReadAsStringAsync());

        return (email, userId, organization.RootElement.GetProperty("id").GetString()!);
    }
}
