using System.Net;
using System.Net.Http.Json;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Changing a password is how a user responds to "someone else has my session". These tests
/// pin the behaviour that makes that gesture mean something.
/// </summary>
public class PasswordChangeTests : IntegrationTestBase
{
    [Fact]
    public async Task Changing_the_password_revokes_other_sessions_and_reissues_the_callers_tokens()
    {
        var (email, first) = await Client.RegisterAsync();

        // A second sign-in stands in for the attacker's stolen session.
        var secondLogin = await Client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email,
            password = TestData.ValidPassword
        });
        secondLogin.EnsureSuccessStatusCode();
        var stolen = (await secondLogin.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;

        Client.Authenticate(first);
        var change = await Client.PostAsJsonAsync("/api/v1/auth/change-password", new
        {
            currentPassword = TestData.ValidPassword,
            newPassword = "NewPassw0rd!45"
        });

        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        var result = await change.Content.ReadFromJsonAsync<ChangePasswordBody>(TestData.Json);
        Assert.True(result!.SessionsRevoked);
        Assert.NotNull(result.Tokens);

        Client.ClearAuthentication();

        // The other session's refresh token is dead.
        var stolenRefresh = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = stolen.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, stolenRefresh.StatusCode);

        // The caller's replacement token still works, so the device that changed the password
        // is not signed out of itself.
        var callerRefresh = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new
        {
            refreshToken = result.Tokens!.RefreshToken
        });
        Assert.Equal(HttpStatusCode.OK, callerRefresh.StatusCode);
    }

    [Fact]
    public async Task The_new_password_is_the_one_that_works_afterwards()
    {
        var (email, tokens) = await Client.RegisterAsync();

        Client.Authenticate(tokens);
        var change = await Client.PostAsJsonAsync("/api/v1/auth/change-password", new
        {
            currentPassword = TestData.ValidPassword,
            newPassword = "NewPassw0rd!45"
        });
        change.EnsureSuccessStatusCode();

        Client.ClearAuthentication();

        var withOld = await Client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestData.ValidPassword });
        var withNew = await Client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "NewPassw0rd!45" });

        Assert.Equal(HttpStatusCode.Unauthorized, withOld.StatusCode);
        Assert.Equal(HttpStatusCode.OK, withNew.StatusCode);
    }

    [Fact]
    public async Task Logout_revokes_the_refresh_token()
    {
        var (_, tokens) = await Client.RegisterAsync();

        Client.Authenticate(tokens);
        var logout = await Client.PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        Client.ClearAuthentication();
        var refresh = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = tokens.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    private record ChangePasswordBody(string Message, bool SessionsRevoked, TestTokens? Tokens);
}
