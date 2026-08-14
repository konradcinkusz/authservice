using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

public class TwoFactorTests : IntegrationTestBase
{
    private async Task EnableTwoFactorAsync(string email)
    {
        await Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            await userManager.ResetAuthenticatorKeyAsync(user!);
            await userManager.SetTwoFactorEnabledAsync(user!, true);
        });
    }

    [Fact]
    public async Task Enrolment_returns_a_shared_key_and_an_otpauth_uri()
    {
        var (_, tokens) = await Client.RegisterAsync();
        Client.Authenticate(tokens);

        var response = await Client.PostAsync("/api/v1/auth/2fa/enable", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var setup = await response.Content.ReadFromJsonAsync<SetupResponse>(TestData.Json);
        Assert.False(string.IsNullOrWhiteSpace(setup!.SharedKey));
        Assert.StartsWith("otpauth://totp/", setup.AuthenticatorUri);
    }

    [Fact]
    public async Task Enrolment_is_not_active_until_a_code_is_confirmed()
    {
        var (email, tokens) = await Client.RegisterAsync();
        Client.Authenticate(tokens);

        await Client.PostAsync("/api/v1/auth/2fa/enable", null);

        var wrongCode = await Client.PostAsJsonAsync("/api/v1/auth/2fa/verify", new { code = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, wrongCode.StatusCode);

        // Still off, so an abandoned or fumbled setup cannot lock anyone out.
        await Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            Assert.False(await userManager.GetTwoFactorEnabledAsync(user!));
        });
    }

    [Fact]
    public async Task Login_returns_a_challenge_instead_of_tokens_when_two_factor_is_on()
    {
        var (email, _) = await Client.RegisterAsync();
        await EnableTwoFactorAsync(email);

        Client.ClearAuthentication();
        var response = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email,
            password = TestData.ValidPassword
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var challenge = await response.Content.ReadFromJsonAsync<ChallengeResponse>(TestData.Json);
        Assert.True(challenge!.RequiresTwoFactor);
        Assert.False(string.IsNullOrWhiteSpace(challenge.ChallengeToken));
    }

    [Fact]
    public async Task A_challenge_token_cannot_be_used_as_an_access_token()
    {
        var (email, _) = await Client.RegisterAsync();
        await EnableTwoFactorAsync(email);

        Client.ClearAuthentication();
        var login = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email,
            password = TestData.ValidPassword
        });
        var challenge = await login.Content.ReadFromJsonAsync<ChallengeResponse>(TestData.Json);

        // The whole point of the separate audience: passing the first factor must not by
        // itself grant API access.
        Client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", challenge!.ChallengeToken);

        var me = await Client.GetAsync("/api/v1/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task Completing_the_challenge_with_a_bad_code_is_refused()
    {
        var (email, _) = await Client.RegisterAsync();
        await EnableTwoFactorAsync(email);

        Client.ClearAuthentication();
        var login = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email,
            password = TestData.ValidPassword
        });
        var challenge = await login.Content.ReadFromJsonAsync<ChallengeResponse>(TestData.Json);

        var response = await Client.PostAsJsonAsync("/api/v1/auth/2fa/login", new
        {
            challengeToken = challenge!.ChallengeToken,
            code = "000000"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_invalid_challenge_token_is_refused()
    {
        var response = await Client.PostAsJsonAsync("/api/v1/auth/2fa/login", new
        {
            challengeToken = "not-a-token",
            code = "123456"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private record SetupResponse(string SharedKey, string AuthenticatorUri);
    private record ChallengeResponse(bool RequiresTwoFactor, string ChallengeToken, int ExpiresIn);
}
