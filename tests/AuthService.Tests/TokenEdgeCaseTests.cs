using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The edges of the token service: a refresh token past its lifetime, a token that proves only the
/// first of two factors, and a token presented where another kind belongs.
/// </summary>
public class TokenEdgeCaseTests : IntegrationTestBase
{
    private async Task<T> WithTokensAsync<T>(Func<ITokenService, UserManager<ApplicationUser>, Task<T>> action)
    {
        T result = default!;
        await Factory.WithScopeAsync(async services =>
            result = await action(services.GetRequiredService<ITokenService>(), services.GetRequiredService<UserManager<ApplicationUser>>()));

        return result;
    }

    [Fact]
    public async Task A_refresh_token_past_its_lifetime_buys_nothing()
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            foreach (var token in context.RefreshTokens.Where(t => t.UserId == account.Id))
                token.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
            await context.SaveChangesAsync();
        });

        var response = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = account.Tokens.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_token_that_proves_only_the_first_factor_cannot_authenticate_an_api_call()
    {
        var account = await Factory.CreateAccountAsync();
        var challenge = await WithTokensAsync(async (tokens, users) =>
            tokens.GenerateTwoFactorChallengeToken((await users.FindByIdAsync(account.Id))!));
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", challenge);

        var response = await Factory.ClientFor().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_access_token_is_not_a_challenge_token_and_a_challenge_token_names_its_account()
    {
        var account = await Factory.CreateAccountAsync();

        var (fromAccessToken, fromChallenge) = await WithTokensAsync(async (tokens, users) =>
        {
            var challenge = tokens.GenerateTwoFactorChallengeToken((await users.FindByIdAsync(account.Id))!);
            return (tokens.GetUserIdFromTwoFactorChallengeToken(account.Tokens.AccessToken),
                    tokens.GetUserIdFromTwoFactorChallengeToken(challenge));
        });

        Assert.Null(fromAccessToken);
        Assert.Equal(account.Id, fromChallenge);
    }

    [Fact]
    public async Task An_access_token_offered_to_complete_a_sign_in_is_refused()
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.UpdateUserAsync(account.Email, u => u.TwoFactorEnabled = true);

        var response = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/2fa/login",
            new { challengeToken = account.Tokens.AccessToken, code = "123456" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-token")]
    [InlineData("a.b.c")]
    public async Task A_blank_or_malformed_challenge_token_names_nobody(string challenge)
    {
        var userId = await WithTokensAsync((tokens, _) => Task.FromResult(tokens.GetUserIdFromTwoFactorChallengeToken(challenge)));

        Assert.Null(userId);
    }

    private const string NameIdentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

    private static ClaimsPrincipal PrincipalOf(TestTokens tokens)
    {
        using var payload = tokens.Payload();

        return Principal(
            (ClaimTypes.NameIdentifier, payload.RootElement.GetProperty(NameIdentifier).GetString()!),
            ("exp", payload.RootElement.GetProperty("exp").GetInt64().ToString()));
    }

    [Fact]
    public async Task A_session_is_alive_until_its_refresh_tokens_are_revoked()
    {
        var account = await Factory.CreateAccountAsync();
        var principal = PrincipalOf(account.Tokens);

        var before = await WithTokensAsync((tokens, _) => tokens.IsSessionAliveAsync(principal));
        await WithTokensAsync(async (tokens, _) =>
        {
            await tokens.RevokeRefreshTokensAsync(account.Id);
            return true;
        });
        var after = await WithTokensAsync((tokens, _) => tokens.IsSessionAliveAsync(principal));

        Assert.True(before);
        Assert.False(after);
    }

    [Fact]
    public async Task A_token_with_no_subject_no_expiry_or_an_expiry_that_matches_no_session_belongs_to_no_live_session()
    {
        var account = await Factory.CreateAccountAsync();
        var inThirtyMinutes = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds().ToString();

        var madeUpExpiry = await WithTokensAsync((tokens, _) => tokens.IsSessionAliveAsync(
            Principal((ClaimTypes.NameIdentifier, account.Id), ("exp", inThirtyMinutes))));
        var noSubject = await WithTokensAsync((tokens, _) => tokens.IsSessionAliveAsync(Principal(("exp", inThirtyMinutes))));
        var noExpiry = await WithTokensAsync((tokens, _) => tokens.IsSessionAliveAsync(Principal((ClaimTypes.NameIdentifier, account.Id))));
        var junkExpiry = await WithTokensAsync((tokens, _) => tokens.IsSessionAliveAsync(
            Principal((ClaimTypes.NameIdentifier, account.Id), ("exp", "soon"))));

        Assert.False(madeUpExpiry);
        Assert.False(noSubject);
        Assert.False(noExpiry);
        Assert.False(junkExpiry);
    }

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), "test"));
}
