using System.Net.Http.Json;
using System.Text.Json;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// The RS256 half of the existing access-token contract (AUTH-MCP-01, AC7), pinned before the
/// authorization server was added; the HS256 half is <c>TokenContractCharacterizationTests</c>
/// in AuthService.Tests. The host here has an MCP client configured, so these tests also prove
/// that enabling the authorization server leaves the tokens existing consumers receive alone.
/// </summary>
public class TokenContractRs256CharacterizationTests : IAsyncLifetime
{
    private const string NameIdentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
    private const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    private const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

    private AuthorizationServerFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new AuthorizationServerFactory();
        await _factory.InitializeAsync();
        _client = _factory.CreateClient();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Login_issues_the_pre_change_token_shape_signed_with_the_published_key()
    {
        var (email, userId, organizationId) = await CreateEnrichedUserAsync();

        var tokens = await _client.LoginAsync(email);

        await AssertContractAsync(tokens, userId, organizationId);
    }

    [Fact]
    public async Task Refresh_issues_the_pre_change_token_shape_signed_with_the_published_key()
    {
        var (email, userId, organizationId) = await CreateEnrichedUserAsync();
        var login = await _client.LoginAsync(email);

        var response = await _client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = login.RefreshToken });
        response.EnsureSuccessStatusCode();

        await AssertContractAsync((await response.Content.ReadFromJsonAsync<ApiTokens>(TestAccounts.Json))!, userId, organizationId);
    }

    [Fact]
    public async Task Two_factor_login_issues_the_pre_change_token_shape_signed_with_the_published_key()
    {
        var (email, userId, organizationId) = await CreateEnrichedUserAsync();
        string recoveryCode = string.Empty;
        await _factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            await userManager.ResetAuthenticatorKeyAsync(user!);
            await userManager.SetTwoFactorEnabledAsync(user!, true);
            recoveryCode = (await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user!, 1))!.Single();
        });

        var login = await _client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestAccounts.Password });
        using var challenge = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var response = await _client.PostAsJsonAsync("/api/v1/auth/2fa/login", new
        {
            challengeToken = challenge.RootElement.GetProperty("challengeToken").GetString(),
            recoveryCode
        });
        response.EnsureSuccessStatusCode();

        await AssertContractAsync((await response.Content.ReadFromJsonAsync<ApiTokens>(TestAccounts.Json))!, userId, organizationId);
    }

    private async Task AssertContractAsync(ApiTokens tokens, string userId, string organizationId)
    {
        Assert.Equal(3600, tokens.ExpiresIn);
        Assert.Equal(64, Convert.FromBase64String(tokens.RefreshToken).Length);

        var jwks = new JsonWebKeySet(await _client.GetStringAsync("/.well-known/jwks.json"));
        var publishedKid = Assert.Single(jwks.Keys).Kid;

        using var header = TestAccounts.DecodeSegment(tokens.AccessToken, 0);
        Assert.Equal(["alg", "kid", "typ"], header.RootElement.PropertyNames());
        Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(publishedKid, header.RootElement.GetProperty("kid").GetString());

        using var payload = TestAccounts.DecodeSegment(tokens.AccessToken, 1);
        var root = payload.RootElement;
        string[] expectedNames =
        [
            "sub", "email", "jti", NameIdentifier, Name, Role,
            "organization", $"organization:{organizationId}:role",
            "exp", "iss", "aud"
        ];
        Assert.Equal(expectedNames.Order(StringComparer.Ordinal), root.PropertyNames());
        Assert.Equal(userId, root.GetProperty("sub").GetString());
        Assert.Equal(userId, root.GetProperty(NameIdentifier).GetString());
        Assert.Equal("Admin", root.GetProperty(Role).GetString());
        Assert.Equal("AuthService", root.GetProperty("iss").GetString());
        Assert.Equal("AuthService", root.GetProperty("aud").GetString());

        // A consumer that knows only the JWKS can verify it.
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(tokens.AccessToken, new TokenValidationParameters
        {
            ValidIssuer = "AuthService",
            ValidAudience = "AuthService",
            IssuerSigningKeys = jwks.GetSigningKeys()
        });
        Assert.True(result.IsValid, result.Exception?.Message);
    }

    private async Task<(string Email, string UserId, string OrganizationId)> CreateEnrichedUserAsync()
    {
        var (email, tokens) = await _client.RegisterAsync();

        string userId = string.Empty;
        await _factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            userId = user!.Id;
            await userManager.AddToRoleAsync(user, "Admin");
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/organizations")
        {
            Content = JsonContent.Create(new { name = "Acme" })
        };
        var created = await _client.SendAsync(request.WithBearer(tokens.AccessToken));
        created.EnsureSuccessStatusCode();
        using var organization = JsonDocument.Parse(await created.Content.ReadAsStringAsync());

        return (email, userId, organization.RootElement.GetProperty("id").GetString()!);
    }
}
