using System.Net;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// What the Hosted pages do with what they should not have been given: a request that did not come from
/// an application, a form left blank, a second factor missing or wrong or too often wrong, a provider that
/// is not set up, a consent request for something the client may not have. The flows themselves are in
/// <see cref="AuthorizationFlowTests"/>.
/// </summary>
public class HostedPageErrorTests : IAsyncLifetime
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

    private async Task<Uri> SignInPageAsync(AuthorizationFlowClient? flow = null)
    {
        var authorize = await (flow ?? _flow).Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "page"));
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(authorize, "/connect/signin"));

        return authorize.Headers.Location!;
    }

    private static async Task<string> ReadErrorAsync(HttpResponseMessage response, string testId)
    {
        var html = await response.Content.ReadAsStringAsync();
        var match = System.Text.RegularExpressions.Regex.Match(html, $"data-testid=\"{testId}\">([^<]*)<");
        Assert.True(match.Success, await AuthorizationFlowClient.DescribeAsync(response));

        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    private Task WithUserAsync(string email, Func<UserManager<ApplicationUser>, ApplicationUser, Task> action) =>
        _factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            await action(users, (await users.FindByEmailAsync(email))!);
        });

    // ─── Where the pages may be reached from ─────────────────────────────────

    [Theory]
    [InlineData("/connect/signin")]
    [InlineData("/connect/2fa")]
    [InlineData("/connect/signin?returnUrl=/connect/authorize")]
    [InlineData("/connect/2fa?returnUrl=%2Fsomewhere-else%3Fclient_id%3Dx")]
    public async Task The_sign_in_and_second_factor_pages_are_reached_only_from_an_authorization_request(string url)
    {
        var response = await _flow.Browser.GetAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("sign-in request", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    // ─── The sign-in page ────────────────────────────────────────────────────

    [Theory]
    [InlineData("", "")]
    [InlineData("someone@example.test", "")]
    [InlineData("   ", "Passw0rd!23")]
    public async Task A_form_left_blank_asks_for_both_the_address_and_the_password(string email, string password)
    {
        var response = await _flow.SignInAsync(await SignInPageAsync(), email, password);

        Assert.Equal("Enter your email address and password.", await ReadErrorAsync(response, "signin-error"));
    }

    [Fact]
    public async Task A_provider_that_is_not_set_up_is_refused_on_the_sign_in_page()
    {
        var signIn = (await SignInPageAsync()).OriginalString;
        var returnUrl = QueryHelpers.ParseQuery(signIn[signIn.IndexOf('?')..])["returnUrl"].ToString();

        var response = await _flow.Browser.GetAsync($"/connect/signin?handler=External&provider=Google&returnUrl={Uri.EscapeDataString(returnUrl)}");

        Assert.Equal("That sign-in provider is not available.", await ReadErrorAsync(response, "signin-error"));
    }

    // ─── Consent ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Consent_asked_for_without_a_session_goes_to_sign_in_first()
    {
        var consent = AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state").Replace("/connect/authorize", "/connect/consent");

        var response = await _flow.Browser.GetAsync(consent);

        Assert.True(AuthorizationFlowClient.IsLocalRedirect(response, "/connect/signin"), await AuthorizationFlowClient.DescribeAsync(response));
    }

    [Theory]
    [InlineData("client_id", "some-other-client")]
    [InlineData("redirect_uri", "https://attacker.example/callback")]
    [InlineData("scope", "notes:read notes:admin")]
    public async Task Consent_is_not_shown_for_a_client_redirect_or_scope_the_client_is_not_allowed(string parameter, string value)
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var authorize = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state"));
        var afterSignIn = await _flow.SignInAsync(authorize.Headers.Location!, email, TestAccounts.Password);
        var toConsent = await _flow.Browser.GetAsync(afterSignIn.Headers.Location);
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(toConsent, "/connect/consent"), await AuthorizationFlowClient.DescribeAsync(toConsent));
        var consentLocation = toConsent.Headers.Location!.OriginalString;
        var query = QueryHelpers.ParseQuery(consentLocation[consentLocation.IndexOf('?')..])
            .ToDictionary(q => q.Key, q => (string?)q.Value.ToString());
        query[parameter] = value;

        var response = await _flow.Browser.GetAsync(QueryHelpers.AddQueryString("/connect/consent", query));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("not valid", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    // ─── The second factor ───────────────────────────────────────────────────

    /// <summary>An account with a second factor, taken through the password step; returns it with the page the password led to.</summary>
    private async Task<(string Email, string RecoveryCode, Uri TwoFactorPage)> ThroughThePasswordStepAsync()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var recoveryCode = string.Empty;
        await WithUserAsync(email, async (users, user) =>
        {
            await users.ResetAuthenticatorKeyAsync(user);
            await users.SetTwoFactorEnabledAsync(user, true);
            recoveryCode = (await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 1))!.Single();
        });

        var authorize = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "2fa"));
        var afterPassword = await _flow.SignInAsync(authorize.Headers.Location!, email, TestAccounts.Password);
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(afterPassword, "/connect/2fa"), await AuthorizationFlowClient.DescribeAsync(afterPassword));

        return (email, recoveryCode, afterPassword.Headers.Location!);
    }

    /// <summary>Opens the page, lets <paramref name="meanwhile"/> happen, then posts what was typed.</summary>
    private async Task<HttpResponseMessage> PostSecondFactorAsync(
        Uri page, string code, string recoveryCode, Func<Task>? meanwhile = null)
    {
        var form = HtmlForm.Parse(await _flow.Browser.GetStringAsync(page), "twofactor-form");
        if (meanwhile is not null)
            await meanwhile();

        form["Code"] = code;
        form["RecoveryCode"] = recoveryCode;

        using var content = new FormUrlEncodedContent(form);
        return await _flow.Browser.PostAsync(page, content);
    }

    [Fact]
    public async Task Neither_a_code_nor_a_recovery_code_asks_for_one_and_costs_no_strike()
    {
        var (email, _, page) = await ThroughThePasswordStepAsync();

        var response = await PostSecondFactorAsync(page, "", "");

        Assert.Equal("Enter the code from your authenticator app, or a recovery code.", await ReadErrorAsync(response, "twofactor-error"));
        await WithUserAsync(email, (_, user) =>
        {
            Assert.Equal(0, user.AccessFailedCount);
            return Task.CompletedTask;
        });
    }

    [Fact]
    public async Task Wrong_codes_are_refused_until_the_fifth_locks_the_account_and_then_the_page_says_so()
    {
        var (_, _, page) = await ThroughThePasswordStepAsync();

        for (var i = 0; i < 5; i++)
            Assert.Equal("That code is not valid.", await ReadErrorAsync(await PostSecondFactorAsync(page, "000000", ""), "twofactor-error"));
        var afterwards = await PostSecondFactorAsync(page, "000000", "");

        Assert.Contains("temporarily locked after too many failed attempts", await ReadErrorAsync(afterwards, "twofactor-error"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_the_challenge_from_the_password_step_the_page_starts_sign_in_again()
    {
        using var otherBrowser = new AuthorizationFlowClient(_factory);
        var (_, _, page) = await ThroughThePasswordStepAsync();

        var response = await otherBrowser.Browser.GetAsync(page);

        Assert.True(AuthorizationFlowClient.IsLocalRedirect(response, "/connect/signin"), await AuthorizationFlowClient.DescribeAsync(response));
    }

    [Fact]
    public async Task An_account_deleted_between_the_two_steps_is_sent_back_to_the_start()
    {
        var (email, recoveryCode, page) = await ThroughThePasswordStepAsync();

        var response = await PostSecondFactorAsync(page, "", recoveryCode, meanwhile: () => WithUserAsync(email, async (users, user) =>
        {
            user.IsDeleted = true;
            await users.UpdateAsync(user);
        }));

        Assert.True(AuthorizationFlowClient.IsLocalRedirect(response, "/connect/signin"), await AuthorizationFlowClient.DescribeAsync(response));
    }

    [Fact]
    public async Task Terms_that_changed_between_the_two_steps_stop_the_sign_in_after_a_correct_second_factor()
    {
        var (email, recoveryCode, page) = await ThroughThePasswordStepAsync();
        await _factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            foreach (var consent in await context.UserConsents.Where(c => c.User!.Email == email).ToListAsync())
                consent.Version = "2020-01-01";
            await context.SaveChangesAsync();
        });

        var response = await PostSecondFactorAsync(page, "", recoveryCode);

        Assert.Contains("terms have changed", await ReadErrorAsync(response, "twofactor-error"), StringComparison.Ordinal);
    }
}
