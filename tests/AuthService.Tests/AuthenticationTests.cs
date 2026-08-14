using System.Net;
using System.Net.Http.Json;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The basic authentication contract: register, sign in, use the token, and the negative
/// cases that matter (wrong password, unknown account, no credentials).
/// </summary>
public class AuthenticationTests : IntegrationTestBase
{
    [Fact]
    public async Task Register_issues_tokens_and_the_access_token_works()
    {
        var (email, tokens) = await Client.RegisterAsync();

        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));
        Assert.Equal("Bearer", tokens.TokenType);

        Client.Authenticate(tokens);
        var me = await Client.GetAsync("/api/v1/auth/me");

        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        var profile = await me.Content.ReadFromJsonAsync<MeResponse>(TestData.Json);
        Assert.Equal(email, profile!.Email);
        Assert.True(profile.HasPassword);
        Assert.False(profile.TwoFactorEnabled);
    }

    [Fact]
    public async Task Register_rejects_a_stale_terms_version()
    {
        var response = await Client.PostAsJsonAsync("/api/v1/auth/register", new
        {
            email = TestData.NewEmail(),
            password = TestData.ValidPassword,
            acceptedTermsVersion = "1999-01-01",
            acceptedPrivacyVersion = TestData.PrivacyVersion
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_succeeds_with_the_right_password()
    {
        var (email, _) = await Client.RegisterAsync();

        var response = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email,
            password = TestData.ValidPassword
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var tokens = await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
    }

    [Fact]
    public async Task Login_rejects_a_wrong_password_without_revealing_whether_the_account_exists()
    {
        var (email, _) = await Client.RegisterAsync();

        var wrongPassword = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email,
            password = "Wrong!Password1"
        });

        var unknownAccount = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = TestData.NewEmail(),
            password = TestData.ValidPassword
        });

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownAccount.StatusCode);

        // Identical bodies: the response must not distinguish "no such account" from
        // "wrong password".
        Assert.Equal(
            await wrongPassword.Content.ReadAsStringAsync(),
            await unknownAccount.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Protected_endpoints_reject_an_unauthenticated_caller()
    {
        var response = await Client.GetAsync("/api/v1/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task The_unversioned_alias_serves_the_same_endpoints()
    {
        var (_, tokens) = await Client.RegisterAsync();
        Client.Authenticate(tokens);

        var versioned = await Client.GetAsync("/api/v1/auth/me");
        var alias = await Client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.OK, versioned.StatusCode);
        Assert.Equal(HttpStatusCode.OK, alias.StatusCode);
    }

    private record MeResponse(
        string Id,
        string Email,
        string? UserName,
        bool HasPassword,
        bool EmailConfirmed,
        bool TwoFactorEnabled);
}
