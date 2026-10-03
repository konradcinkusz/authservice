using System.Net;
using System.Security.Claims;
using System.Text;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Whether the address a provider handed back is one the provider verified. The answer decides
/// which local account the provider identity is attached to, so anything short of a positive
/// statement from the provider is a refusal.
/// </summary>
public class ProviderEmailVerifierTests
{
    private const string Email = "user@example.test";

    private static ExternalLoginInfo Info(string provider, string? emailVerified = null, string? accessToken = null)
    {
        List<Claim> claims = [];
        if (emailVerified is not null)
            claims.Add(new Claim("email_verified", emailVerified));

        return new ExternalLoginInfo(new ClaimsPrincipal(new ClaimsIdentity(claims, provider)), provider, "provider-key", provider)
        {
            AuthenticationTokens = accessToken is null
                ? null
                : [new AuthenticationToken { Name = "access_token", Value = accessToken }]
        };
    }

    private static StubHttpHandler NoCallsExpected() =>
        new(_ => throw new InvalidOperationException("The provider's own claim is enough here; nothing should be fetched."));

    private static StubHttpHandler GitHubSays(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(_ => new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") });

    private static ProviderEmailVerifier Verifier(StubHttpHandler handler) =>
        new(new StubHttpClientFactory(handler), NullLogger<ProviderEmailVerifier>.Instance);

    // ─── Google says it in a claim ───────────────────────────────────────────

    [Theory]
    [InlineData("true")]
    [InlineData("True")]
    public async Task Google_is_trusted_when_its_claim_says_the_address_is_verified(string claim)
    {
        var result = await Verifier(NoCallsExpected()).VerifyAsync(Info("Google", claim), Email);

        Assert.True(result.IsVerified);
        Assert.Null(result.Reason);
    }

    [Theory]
    [InlineData("false")]
    [InlineData("yes")]
    [InlineData("1")]
    public async Task Google_is_refused_when_the_claim_is_anything_but_true(string claim)
    {
        var result = await Verifier(NoCallsExpected()).VerifyAsync(Info("Google", claim), Email);

        Assert.False(result.IsVerified);
        Assert.Equal("email_not_verified", result.Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task Google_is_refused_when_the_claim_never_arrived(string? claim)
    {
        var result = await Verifier(NoCallsExpected()).VerifyAsync(Info("Google", claim), Email);

        Assert.False(result.IsVerified);
        Assert.Equal("email_verified_claim_missing", result.Reason);
    }

    // ─── Anything else is refused ────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task No_address_is_nothing_to_verify(string email)
    {
        var result = await Verifier(NoCallsExpected()).VerifyAsync(Info("Google", "true"), email);

        Assert.False(result.IsVerified);
        Assert.Equal("no_email", result.Reason);
    }

    [Theory]
    [InlineData("Facebook")]
    [InlineData("Microsoft")]
    [InlineData("google")]
    public async Task A_provider_without_a_rule_here_is_not_trusted(string provider)
    {
        var result = await Verifier(NoCallsExpected()).VerifyAsync(Info(provider, "true", "token"), Email);

        Assert.False(result.IsVerified);
        Assert.Equal("provider_not_supported", result.Reason);
    }

    // ─── GitHub is asked ─────────────────────────────────────────────────────

    [Fact]
    public async Task GitHub_is_asked_for_the_accounts_addresses_with_the_users_own_token()
    {
        var handler = GitHubSays("""[{"email":"user@example.test","verified":true,"primary":true}]""");

        var result = await Verifier(handler).VerifyAsync(Info("GitHub", accessToken: "gh-token"), Email);

        Assert.True(result.IsVerified);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://api.github.com/user/emails", request.RequestUri!.ToString());
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal("gh-token", request.Headers.Authorization.Parameter);
        Assert.Contains("application/vnd.github+json", request.Headers.Accept.ToString());
        Assert.NotEmpty(request.Headers.UserAgent);
    }

    [Fact]
    public async Task GitHub_accepts_a_verified_address_that_is_not_the_primary_and_ignores_the_case()
    {
        var handler = GitHubSays("""
            [{"email":"primary@example.test","verified":true,"primary":true},
             {"email":"User@Example.Test","verified":true,"primary":false}]
            """);

        var result = await Verifier(handler).VerifyAsync(Info("GitHub", accessToken: "gh-token"), Email);

        Assert.True(result.IsVerified);
    }

    [Fact]
    public async Task GitHub_refuses_an_address_it_lists_as_unverified()
    {
        var handler = GitHubSays("""[{"email":"user@example.test","verified":false,"primary":false}]""");

        var result = await Verifier(handler).VerifyAsync(Info("GitHub", accessToken: "gh-token"), Email);

        Assert.False(result.IsVerified);
        Assert.Equal("email_not_verified", result.Reason);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("""[{"email":"someone-else@example.test","verified":true,"primary":true}]""")]
    public async Task GitHub_refuses_an_address_that_is_not_on_the_account(string json)
    {
        var result = await Verifier(GitHubSays(json)).VerifyAsync(Info("GitHub", accessToken: "gh-token"), Email);

        Assert.False(result.IsVerified);
        Assert.Equal("email_not_on_account", result.Reason);
    }

    [Fact]
    public async Task GitHub_without_the_users_token_is_refused_without_asking()
    {
        var handler = NoCallsExpected();

        var result = await Verifier(handler).VerifyAsync(Info("GitHub"), Email);

        Assert.False(result.IsVerified);
        Assert.Equal("no_access_token", result.Reason);
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task GitHub_failing_to_answer_is_a_refusal_not_a_pass(HttpStatusCode status)
    {
        var result = await Verifier(GitHubSays("{}", status)).VerifyAsync(Info("GitHub", accessToken: "gh-token"), Email);

        Assert.False(result.IsVerified);
        Assert.Equal("emails_endpoint_failed", result.Reason);
    }

    [Fact]
    public async Task GitHub_being_unreachable_or_answering_nonsense_is_a_refusal_not_a_pass()
    {
        var unreachable = new StubHttpHandler(_ => throw new HttpRequestException("connection refused"));

        var down = await Verifier(unreachable).VerifyAsync(Info("GitHub", accessToken: "gh-token"), Email);
        var nonsense = await Verifier(GitHubSays("<html>not json</html>")).VerifyAsync(Info("GitHub", accessToken: "gh-token"), Email);

        Assert.Equal("verification_error", down.Reason);
        Assert.Equal("verification_error", nonsense.Reason);
        Assert.False(down.IsVerified || nonsense.IsVerified);
    }
}
