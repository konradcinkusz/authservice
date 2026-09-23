using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The access-token contract existing consumers depend on, pinned before the authorization
/// server was added (AUTH-MCP-01, AC7). Nothing else in the suite decodes a token, so without
/// this a change to a claim name — which every consumer reads — would pass every test.
///
/// The names are exactly what <c>JwtSecurityTokenHandler</c> writes for the claims
/// <c>TokenService</c> builds: the short JWT names for <c>sub</c>, <c>email</c> and <c>jti</c>,
/// and the full <c>ClaimTypes</c> URIs for name identifier, name and role. MCP access tokens
/// carry the same names (ADR 0005), so these assertions are the reference for both.
/// </summary>
public class TokenContractCharacterizationTests : IntegrationTestBase
{
    private const string NameIdentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
    private const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    private const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

    [Fact]
    public async Task Login_issues_the_pre_change_token_shape()
    {
        var (email, userId, organizationId) = await CreateEnrichedUserAsync("Admin");

        var tokens = await LoginAsync(email);

        AssertContract(tokens, userId, organizationId, expectedRoles: ["Admin"]);
    }

    [Fact]
    public async Task Refresh_issues_the_pre_change_token_shape()
    {
        var (email, userId, organizationId) = await CreateEnrichedUserAsync("Admin");
        var login = await LoginAsync(email);

        var response = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = login.RefreshToken });
        response.EnsureSuccessStatusCode();
        var refreshed = (await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;

        AssertContract(refreshed, userId, organizationId, expectedRoles: ["Admin"]);
    }

    [Fact]
    public async Task Two_factor_login_issues_the_pre_change_token_shape()
    {
        var (email, userId, organizationId) = await CreateEnrichedUserAsync("Admin");
        var recoveryCode = await EnableTwoFactorAsync(email);

        var login = await Client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestData.ValidPassword });
        login.EnsureSuccessStatusCode();
        using var challenge = JsonDocument.Parse(await login.Content.ReadAsStringAsync());

        var response = await Client.PostAsJsonAsync("/api/v1/auth/2fa/login", new
        {
            challengeToken = challenge.RootElement.GetProperty("challengeToken").GetString(),
            recoveryCode
        });
        response.EnsureSuccessStatusCode();
        var tokens = (await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;

        AssertContract(tokens, userId, organizationId, expectedRoles: ["Admin"]);
    }

    [Fact]
    public async Task Several_roles_are_serialized_as_an_array_under_the_role_uri()
    {
        var (email, _, _) = await CreateEnrichedUserAsync("Admin", "User");

        var tokens = await LoginAsync(email);

        using var payload = DecodeSegment(tokens.AccessToken, 1);
        var roles = payload.RootElement.GetProperty(Role);
        Assert.Equal(JsonValueKind.Array, roles.ValueKind);
        Assert.Equal(["Admin", "User"], roles.EnumerateArray().Select(r => r.GetString()!).Order());
    }

    private static void AssertContract(TestTokens tokens, string userId, string organizationId, string[] expectedRoles)
    {
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.Equal(3600, tokens.ExpiresIn);

        // The refresh token is opaque: 64 bytes of CSPRNG output, base64-encoded, not a JWT.
        Assert.Equal(64, Convert.FromBase64String(tokens.RefreshToken).Length);

        var segments = tokens.AccessToken.Split('.');
        Assert.Equal(3, segments.Length);

        using var header = DecodeSegment(tokens.AccessToken, 0);
        Assert.Equal(["alg", "typ"], header.RootElement.EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal("HS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());

        using var payload = DecodeSegment(tokens.AccessToken, 1);
        var root = payload.RootElement;

        string[] expectedNames =
        [
            "sub", "email", "jti", NameIdentifier, Name, Role,
            "organization", $"organization:{organizationId}:role",
            "exp", "iss", "aud"
        ];
        Assert.Equal(expectedNames.Order(), root.EnumerateObject().Select(p => p.Name).Order());

        Assert.Equal(userId, root.GetProperty("sub").GetString());
        Assert.Equal(userId, root.GetProperty(NameIdentifier).GetString());
        Assert.Equal("AuthService", root.GetProperty("iss").GetString());
        Assert.Equal("AuthService", root.GetProperty("aud").GetString());
        Assert.Equal(organizationId, root.GetProperty("organization").GetString());
        Assert.Equal("Owner", root.GetProperty($"organization:{organizationId}:role").GetString());
        Assert.True(Guid.TryParse(root.GetProperty("jti").GetString(), out _));

        if (expectedRoles.Length == 1)
            Assert.Equal(expectedRoles[0], root.GetProperty(Role).GetString());

        // No `iat` or `nbf`: the lifetime is carried by `exp` alone, Jwt:ExpirationMinutes from now.
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(root.GetProperty("exp").GetInt64());
        var expected = DateTimeOffset.UtcNow.AddMinutes(60);
        Assert.InRange(expiresAt, expected.AddMinutes(-2), expected.AddMinutes(1));
    }

    /// <summary>A user with a global role and one organization, so every enriched claim is present.</summary>
    private async Task<(string Email, string UserId, string OrganizationId)> CreateEnrichedUserAsync(params string[] roles)
    {
        var (email, tokens) = await Client.RegisterAsync();

        string userId = string.Empty;
        await Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            userId = user!.Id;
            foreach (var role in roles)
                await userManager.AddToRoleAsync(user, role);
        });

        Client.Authenticate(tokens);
        var created = await Client.PostAsJsonAsync("/api/v1/organizations", new { name = "Acme" });
        created.EnsureSuccessStatusCode();
        using var organization = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        Client.ClearAuthentication();

        return (email, userId, organization.RootElement.GetProperty("id").GetString()!);
    }

    private async Task<TestTokens> LoginAsync(string email)
    {
        var response = await Client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestData.ValidPassword });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;
    }

    /// <summary>Turns on two-factor sign-in and returns one recovery code to complete it with.</summary>
    private async Task<string> EnableTwoFactorAsync(string email)
    {
        string code = string.Empty;
        await Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            await userManager.ResetAuthenticatorKeyAsync(user!);
            await userManager.SetTwoFactorEnabledAsync(user!, true);
            code = (await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user!, 1))!.Single();
        });
        return code;
    }

    private static JsonDocument DecodeSegment(string jwt, int index)
    {
        var segment = jwt.Split('.')[index].Replace('-', '+').Replace('_', '/');
        segment = segment.PadRight(segment.Length + (4 - segment.Length % 4) % 4, '=');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(segment)));
    }
}
