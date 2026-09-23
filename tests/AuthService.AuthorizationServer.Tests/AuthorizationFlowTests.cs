using System.Net;
using System.Text.Json;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// The whole connection a Claude user makes, in Hosted mode (AC8): discovery, authorization with
/// sign-in and consent, the code, the token exchange with PKCE, a call to an MCP server that
/// validates the token through the JWKS, and two refreshes — then everything that must be refused.
/// </summary>
public class AuthorizationFlowTests : IAsyncLifetime
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
    public async Task A_user_connects_a_client_and_it_reaches_the_resource_and_keeps_refreshing()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        await using var resource = await TestResourceServer.StartAsync(_factory);

        // 1. Discovery, as Claude does it: RFC 8414 first.
        var metadata = await _flow.Backchannel.GetAsync("/.well-known/oauth-authorization-server");
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);

        // 2-3. Authorize: sign in, consent, and back to the client with a code and the issuer.
        var pkce = Pkce.Create();
        var redirect = await _flow.AuthorizeHostedAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, "state-123"), email);
        Assert.Equal(AuthorizationServerFactory.RedirectUri, redirect.GetLeftPart(UriPartial.Path));

        var response = AuthorizationFlowClient.Query(redirect);
        Assert.Equal("state-123", response["state"]);
        Assert.Equal(AuthorizationServerFactory.Issuer, response["iss"]);
        Assert.False(response.ContainsKey("error"));

        // 4. The code, redeemed with the PKCE verifier by the confidential client.
        var tokens = await AuthorizationFlowClient.ReadTokensAsync(await _flow.ExchangeCodeAsync(response["code"], pkce.Verifier));
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.NotNull(tokens.RefreshToken);

        // 5. The MCP server validates it through the metadata and the JWKS alone.
        var call = await resource.CallAsync(tokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, call.StatusCode);
        using (var body = JsonDocument.Parse(await call.Content.ReadAsStringAsync()))
        {
            Assert.Equal(AuthorizationServerFactory.ClientId, body.RootElement.GetProperty("clientId").GetString());
            Assert.Contains(AuthorizationServerFactory.Scope, body.RootElement.GetProperty("scope").GetString()!.Split(' '));
        }

        // 6. Refresh, then refresh again with the rotated token.
        var first = await AuthorizationFlowClient.ReadTokensAsync(await _flow.RefreshAsync(tokens.RefreshToken!));
        Assert.NotEqual(tokens.RefreshToken, first.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await resource.CallAsync(first.AccessToken)).StatusCode);

        var second = await AuthorizationFlowClient.ReadTokensAsync(await _flow.RefreshAsync(first.RefreshToken!));
        Assert.Equal(HttpStatusCode.OK, (await resource.CallAsync(second.AccessToken)).StatusCode);
    }

    // ─── The brief's negative cases (AC8) ─────────────────────────────────────────

    [Fact]
    public async Task A_wrong_code_verifier_is_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);

        var response = await _flow.ExchangeCodeAsync(code, Pkce.Create().Verifier);

        await AssertTokenErrorAsync(response, "invalid_grant");
    }

    [Fact]
    public async Task A_reused_code_is_refused_and_ends_what_it_issued()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);
        var tokens = await AuthorizationFlowClient.ReadTokensAsync(await _flow.ExchangeCodeAsync(code, pkce.Verifier));

        var replay = await _flow.ExchangeCodeAsync(code, pkce.Verifier);

        await AssertTokenErrorAsync(replay, "invalid_grant");

        // A replayed code revokes the tokens issued from it (RFC 6749 §4.1.2).
        await AssertTokenErrorAsync(await _flow.RefreshAsync(tokens.RefreshToken!), "invalid_grant");
    }

    [Fact]
    public async Task An_unregistered_redirect_uri_is_never_redirected_to()
    {
        var url = AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state", redirectUri: "https://attacker.example/callback");

        var response = await _flow.Browser.GetAsync(url);

        // Shown on authservice's own error page, never sent to the unverified URI (MCP-SEC "Open Redirection").
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A_code_redeemed_with_a_different_redirect_uri_is_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);

        var response = await _flow.ExchangeCodeAsync(code, pkce.Verifier, redirectUri: "https://claude.example.test/elsewhere");

        await AssertTokenErrorAsync(response, "invalid_grant");
    }

    [Fact]
    public async Task A_token_request_for_a_resource_the_client_may_use_but_was_not_granted_is_refused()
    {
        using var factory = new AuthorizationServerFactory(settings =>
            settings["AuthorizationServer:Clients:0:AllowedResources:1"] = "https://mcp.example.test/other");
        await factory.InitializeAsync();
        using var flow = new AuthorizationFlowClient(factory);
        var (email, _) = await flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var redirect = await flow.AuthorizeHostedAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, "state"), email);

        // RFC 8707: the code was issued for one resource; it cannot buy a token for another.
        var response = await flow.ExchangeCodeAsync(AuthorizationFlowClient.Query(redirect)["code"], pkce.Verifier, resource: "https://mcp.example.test/other");

        await AssertTokenErrorAsync(response, "invalid_target");
    }

    [Fact]
    public async Task A_token_request_for_a_resource_the_client_may_not_use_is_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);

        var response = await _flow.ExchangeCodeAsync(code, pkce.Verifier, resource: "https://other.example.test/mcp");

        await AssertTokenErrorAsync(response, "invalid_request");
    }

    [Fact]
    public async Task An_unknown_client_is_refused_without_a_redirect()
    {
        var url = AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state", clientId: "not-a-client");

        var response = await _flow.Browser.GetAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task The_plain_challenge_method_is_refused()
    {
        var pkce = Pkce.Create();
        var url = AuthorizationFlowClient.AuthorizeUrl(pkce, "state", codeChallengeMethod: "plain", codeChallenge: pkce.Verifier);

        var response = await _flow.Browser.GetAsync(url);

        await AssertAuthorizationRefusedAsync(response, "invalid_request");
    }

    [Fact]
    public async Task A_request_without_pkce_is_refused()
    {
        var url = AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state", codeChallengeMethod: null, codeChallenge: "")
            .Replace("code_challenge=&", string.Empty, StringComparison.Ordinal);

        var response = await _flow.Browser.GetAsync(url);

        await AssertAuthorizationRefusedAsync(response, "invalid_request");
    }

    // ─── Resource indicators (N10) ─────────────────────────────────────────────────

    [Fact]
    public async Task A_request_without_a_resource_is_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        await SignInOnlyAsync(email);

        var response = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state", resource: null));

        await AssertAuthorizationRefusedAsync(response, "invalid_target");
    }

    [Fact]
    public async Task A_resource_the_client_is_not_allowed_is_refused()
    {
        var response = await _flow.Browser.GetAsync(
            AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state", resource: "https://other.example.test/mcp"));

        await AssertAuthorizationRefusedAsync(response);
    }

    [Fact]
    public async Task Two_resources_are_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        await SignInOnlyAsync(email);
        var url = AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "state") + "&resource=" + Uri.EscapeDataString(AuthorizationServerFactory.Resource + "/two");

        var response = await _flow.Browser.GetAsync(url);

        await AssertAuthorizationRefusedAsync(response);
    }

    [Theory]
    [InlineData("https://mcp.example.test")]
    [InlineData("https://mcp.example.test/")]
    public async Task An_origin_root_resource_works_with_or_without_its_trailing_slash(string requested)
    {
        using var factory = new AuthorizationServerFactory(settings =>
            settings["AuthorizationServer:Clients:0:AllowedResources:0"] = "https://mcp.example.test");
        await factory.InitializeAsync();
        using var flow = new AuthorizationFlowClient(factory);
        var (email, _) = await flow.Backchannel.RegisterAsync();

        var pkce = Pkce.Create();
        var redirect = await flow.AuthorizeHostedAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, "state", resource: requested), email);
        var tokens = await AuthorizationFlowClient.ReadTokensAsync(
            await flow.ExchangeCodeAsync(AuthorizationFlowClient.Query(redirect)["code"], pkce.Verifier, resource: requested));

        using var payload = TestAccounts.DecodeSegment(tokens.AccessToken, 1);
        Assert.Equal(requested, payload.RootElement.GetProperty("aud").GetString());
    }

    // ─── Refresh (AC3, A10, N3) ────────────────────────────────────────────────────

    [Fact]
    public async Task A_replayed_refresh_token_revokes_the_chain_and_is_audited()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);
        var rotated = await AuthorizationFlowClient.ReadTokensAsync(await _flow.RefreshAsync(tokens.RefreshToken!));

        var replay = await _flow.RefreshAsync(tokens.RefreshToken!);

        await AssertTokenErrorAsync(replay, "invalid_grant");
        await AssertTokenErrorAsync(await _flow.RefreshAsync(rotated.RefreshToken!), "invalid_grant");

        await _factory.WithScopeAsync(async services =>
        {
            var audit = await services.GetRequiredService<ApplicationDbContext>().AuditEvents.AsNoTracking()
                .SingleAsync(a => a.Action == AuditAction.OAuthRefreshTokenReuseDetected);
            Assert.False(audit.Succeeded);
            Assert.Contains(AuthorizationServerFactory.ClientId, audit.Metadata, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task A_locked_out_user_cannot_refresh()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);
        await WithUserAsync(email, (users, user) => users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(5)));

        await AssertTokenErrorAsync(await _flow.RefreshAsync(tokens.RefreshToken!), "invalid_grant");
    }

    [Fact]
    public async Task A_deleted_user_cannot_refresh()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var tokens = await _flow.ConnectAsync(email);
        await WithUserAsync(email, (users, user) =>
        {
            user.IsDeleted = true;
            return users.UpdateAsync(user);
        });

        await AssertTokenErrorAsync(await _flow.RefreshAsync(tokens.RefreshToken!), "invalid_grant");
    }

    [Fact]
    public async Task A_confidential_client_without_its_secret_is_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);

        var response = await _flow.TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = AuthorizationServerFactory.RedirectUri,
            ["code_verifier"] = pkce.Verifier
        }, secret: string.Empty);

        Assert.Equal("invalid_client", await AuthorizationFlowClient.ReadErrorAsync(response));
    }

    [Fact]
    public async Task A_wrong_client_secret_is_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);

        var response = await _flow.ExchangeCodeAsync(code, pkce.Verifier, secret: new string('0', 64));

        Assert.Equal("invalid_client", await AuthorizationFlowClient.ReadErrorAsync(response));
    }

    [Fact]
    public async Task The_client_may_authenticate_with_client_secret_post()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);

        var response = await _flow.ExchangeCodeAsync(code, pkce.Verifier, basic: false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ─── Consent (AC2, N2) ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Consent_shows_the_client_where_it_returns_and_what_each_scope_means()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var response = await SignInOnlyAsync(email);
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(response, "/connect/consent"));

        var page = await (await _flow.Browser.GetAsync(response.Headers.Location)).Content.ReadAsStringAsync();

        Assert.Contains($"data-testid=\"consent-client\">{AuthorizationServerFactory.ClientDisplayName}<", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"consent-redirect-host\">claude.example.test<", page, StringComparison.Ordinal);
        Assert.Contains($"data-scope=\"notes:read\">{AuthorizationServerFactory.ScopeDescription}<", page, StringComparison.Ordinal);
        Assert.Contains($"data-testid=\"consent-user\">{email}<", page, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Consent_is_remembered_for_the_same_client_and_scopes()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        await _flow.ConnectAsync(email);

        // Still signed in to the authorization server: straight back to the client.
        var response = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "again"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(AuthorizationServerFactory.RedirectUri, response.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.True(AuthorizationFlowClient.Query(response.Headers.Location).ContainsKey("code"));
    }

    [Fact]
    public async Task Consent_is_asked_again_for_a_new_scope()
    {
        using var factory = new AuthorizationServerFactory(settings =>
            settings["AuthorizationServer:Clients:0:AllowedScopes:2"] = "notes:write");
        await factory.InitializeAsync();
        using var flow = new AuthorizationFlowClient(factory);
        var (email, _) = await flow.Backchannel.RegisterAsync();
        await flow.ConnectAsync(email);

        var response = await flow.Browser.GetAsync(
            AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "wider", scope: "notes:read notes:write offline_access"));

        Assert.True(AuthorizationFlowClient.IsLocalRedirect(response, "/connect/consent"), await AuthorizationFlowClient.DescribeAsync(response));
    }

    [Fact]
    public async Task Declining_consent_returns_access_denied_to_the_client_and_is_audited()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();

        var redirect = await _flow.AuthorizeHostedAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "declined"), email, consent: "deny");

        var response = AuthorizationFlowClient.Query(redirect);
        Assert.Equal("access_denied", response["error"]);
        Assert.Equal("declined", response["state"]);
        Assert.Equal(AuthorizationServerFactory.Issuer, response["iss"]);
        Assert.False(response.ContainsKey("code"));

        await _factory.WithScopeAsync(async services =>
            Assert.True(await services.GetRequiredService<ApplicationDbContext>().AuditEvents
                .AnyAsync(a => a.Action == AuditAction.OAuthConsentDenied)));
    }

    [Fact]
    public async Task A_consent_post_without_the_antiforgery_token_is_refused()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var response = await SignInOnlyAsync(email);
        var page = await (await _flow.Browser.GetAsync(response.Headers.Location)).Content.ReadAsStringAsync();
        var form = HtmlForm.Parse(page, "consent-form");
        form.Remove("__RequestVerificationToken");
        form["consent"] = "accept";

        var posted = await _flow.Browser.PostAsync("/connect/authorize", new FormUrlEncodedContent(form));

        Assert.Equal(HttpStatusCode.BadRequest, posted.StatusCode);
    }

    [Fact]
    public async Task Prompt_none_without_a_session_returns_login_required()
    {
        var url = AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "silent", extra: new Dictionary<string, string> { ["prompt"] = "none" });

        var response = await _flow.Browser.GetAsync(url);

        await AssertAuthorizationRefusedAsync(response, "login_required");
    }

    // ─── Sign-in (AC2, IDENTITY-AND-ACCOUNTS.md §5, §6, §9) ─────────────────────────

    [Fact]
    public async Task A_wrong_password_and_an_unknown_account_get_the_same_answer()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var signIn = await SignInPageAsync();

        var wrongPassword = await ReadPageErrorAsync(await _flow.SignInAsync(signIn, email, "Wr0ng-password!"));
        var unknownAccount = await ReadPageErrorAsync(await _flow.SignInAsync(signIn, TestAccounts.NewEmail("nobody"), TestAccounts.Password));

        Assert.Equal("Invalid email or password.", wrongPassword);
        Assert.Equal(wrongPassword, unknownAccount);
    }

    [Fact]
    public async Task Lockout_is_disclosed_only_with_the_right_password()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var signIn = await SignInPageAsync();

        for (var i = 0; i < 5; i++)
            await _flow.SignInAsync(signIn, email, "Wr0ng-password!");

        Assert.Equal("Invalid email or password.", await ReadPageErrorAsync(await _flow.SignInAsync(signIn, email, "Wr0ng-password!")));
        Assert.Contains("temporarily locked", await ReadPageErrorAsync(await _flow.SignInAsync(signIn, email, TestAccounts.Password)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_user_whose_accepted_terms_are_out_of_date_is_sent_to_the_product()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        await _factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            foreach (var consent in await context.UserConsents.Where(c => c.User.Email == email).ToListAsync())
                consent.Version = "2020-01-01";
            await context.SaveChangesAsync();
        });

        var error = await ReadPageErrorAsync(await _flow.SignInAsync(await SignInPageAsync(), email, TestAccounts.Password));

        Assert.Contains("terms have changed", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_two_factor_account_signs_in_through_the_second_factor_page()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        string recoveryCode = string.Empty;
        await WithUserAsync(email, async (users, user) =>
        {
            await users.ResetAuthenticatorKeyAsync(user);
            await users.SetTwoFactorEnabledAsync(user, true);
            recoveryCode = (await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 1))!.Single();
        });

        var pkce = Pkce.Create();
        var authorize = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, "2fa"));
        var afterPassword = await _flow.SignInAsync(authorize.Headers.Location!, email, TestAccounts.Password);
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(afterPassword, "/connect/2fa"), await AuthorizationFlowClient.DescribeAsync(afterPassword));

        // A wrong code is refused and counts toward lockout.
        var twoFactorPage = afterPassword.Headers.Location!;
        var form = HtmlForm.Parse(await _flow.Browser.GetStringAsync(twoFactorPage), "twofactor-form");
        form["Code"] = "000000";
        Assert.Equal("That code is not valid.", await ReadPageErrorAsync(await _flow.Browser.PostAsync(twoFactorPage, new FormUrlEncodedContent(form))));
        await WithUserAsync(email, (_, user) =>
        {
            Assert.Equal(1, user.AccessFailedCount);
            return Task.CompletedTask;
        });

        form = HtmlForm.Parse(await _flow.Browser.GetStringAsync(twoFactorPage), "twofactor-form");
        form["Code"] = string.Empty;
        form["RecoveryCode"] = recoveryCode;
        var afterSecondFactor = await _flow.Browser.PostAsync(twoFactorPage, new FormUrlEncodedContent(form));
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(afterSecondFactor, "/connect/authorize"), await AuthorizationFlowClient.DescribeAsync(afterSecondFactor));

        var consent = await _flow.Browser.GetAsync(afterSecondFactor.Headers.Location);
        var redirect = await _flow.ConsentAsync(consent.Headers.Location!, "accept");
        Assert.True(AuthorizationFlowClient.Query(redirect.Headers.Location!).ContainsKey("code"));
    }

    [Fact]
    public async Task The_sign_in_page_returns_only_to_the_authorization_endpoint()
    {
        var response = await _flow.Browser.GetAsync("/connect/signin?returnUrl=" + Uri.EscapeDataString("https://attacker.example/"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task The_pages_send_the_browser_header_set()
    {
        var response = await _flow.Browser.GetAsync(await SignInPageAsync());
        var headers = response.Headers;

        var csp = headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", csp, StringComparison.Ordinal);
        Assert.DoesNotContain("script-src", csp, StringComparison.Ordinal);
        Assert.Equal("DENY", headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("nosniff", headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", headers.GetValues("Referrer-Policy").Single());
        Assert.True(headers.Contains("Permissions-Policy"));
    }

    [Fact]
    public async Task The_interaction_api_does_not_exist_in_hosted_mode()
    {
        var (_, tokens) = await _flow.Backchannel.RegisterAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/oauth/interactions/anything").WithBearer(tokens.AccessToken);

        Assert.Equal(HttpStatusCode.NotFound, (await _flow.Backchannel.SendAsync(request)).StatusCode);
    }

    // ─── What never reaches a log (N5) ─────────────────────────────────────────────

    [Fact]
    public async Task No_code_token_secret_or_verifier_is_logged()
    {
        var (email, _) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var code = await CodeAsync(email, pkce);
        var tokens = await AuthorizationFlowClient.ReadTokensAsync(await _flow.ExchangeCodeAsync(code, pkce.Verifier));
        var refreshed = await AuthorizationFlowClient.ReadTokensAsync(await _flow.RefreshAsync(tokens.RefreshToken!));
        await _flow.RefreshAsync(tokens.RefreshToken!); // a replay, logged as a warning

        var log = string.Join("\n", _factory.Logs.Entries);
        Assert.NotEmpty(_factory.Logs.Entries);

        foreach (var secret in new[]
                 {
                     code, pkce.Verifier, tokens.AccessToken, tokens.RefreshToken!, refreshed.AccessToken,
                     refreshed.RefreshToken!, _factory.ClientSecret, _factory.EncryptionKey
                 })
        {
            Assert.DoesNotContain(secret, log, StringComparison.Ordinal);
        }
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────────

    private async Task<string> CodeAsync(string email, Pkce pkce)
    {
        var redirect = await _flow.AuthorizeHostedAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, "state"), email);
        return AuthorizationFlowClient.Query(redirect)["code"];
    }

    /// <summary>Signs in through a first authorization request; returns where that left the browser.</summary>
    private async Task<HttpResponseMessage> SignInOnlyAsync(string email)
    {
        var authorize = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "first"));
        var signedIn = await _flow.SignInAsync(authorize.Headers.Location!, email, TestAccounts.Password);
        return await _flow.Browser.GetAsync(signedIn.Headers.Location);
    }

    private async Task<Uri> SignInPageAsync()
    {
        var authorize = await _flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(Pkce.Create(), "page"));
        Assert.True(AuthorizationFlowClient.IsLocalRedirect(authorize, "/connect/signin"));
        return authorize.Headers.Location!;
    }

    private static async Task<string> ReadPageErrorAsync(HttpResponseMessage response)
    {
        var html = await response.Content.ReadAsStringAsync();
        var match = System.Text.RegularExpressions.Regex.Match(html, "data-testid=\"(?:signin|twofactor)-error\">([^<]*)<");
        Assert.True(match.Success, await AuthorizationFlowClient.DescribeAsync(response));
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    private Task WithUserAsync(string email, Func<UserManager<ApplicationUser>, ApplicationUser, Task> action) =>
        _factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            await action(users, (await users.FindByEmailAsync(email))!);
        });

    private static async Task AssertTokenErrorAsync(HttpResponseMessage response, string error)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(error, await AuthorizationFlowClient.ReadErrorAsync(response));
    }

    /// <summary>
    /// Refused either on authservice's own page (errors found before the redirect URI was
    /// validated) or back at the client with an error — never with a code.
    /// </summary>
    private static async Task AssertAuthorizationRefusedAsync(HttpResponseMessage response, string? error = null)
    {
        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            Assert.Null(response.Headers.Location);
            if (error is not null)
                Assert.Contains(error, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            return;
        }

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.StartsWith(AuthorizationServerFactory.RedirectUri, location.ToString(), StringComparison.Ordinal);

        var query = AuthorizationFlowClient.Query(location);
        Assert.False(query.ContainsKey("code"));
        if (error is not null)
            Assert.Equal(error, query["error"]);
    }
}

/// <summary>
/// Signing in with an external provider from the Hosted sign-in page (AC2 notes): the existing
/// flow, unchanged, lands on <c>/oauth/callback</c> with its exchange code, and the request
/// resumes — but only in the browser that started it.
/// </summary>
public class ExternalProviderReturnTests : IAsyncLifetime
{
    private AuthorizationServerFactory _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new AuthorizationServerFactory(settings =>
        {
            // Registers the Google handler; no call to Google is made before its callback.
            settings["OAuth:Google:ClientId"] = "test-google-client";
            settings["OAuth:Google:ClientSecret"] = "test-google-secret";
            // The runbook step: the issuer's origin on ExternalAuthController's allow list.
            settings["OAuth:PostLoginRedirectAllowedBaseUrls:0"] = AuthorizationServerFactory.Issuer;
        });
        await _factory.InitializeAsync();
    }

    public Task DisposeAsync()
    {
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Signing_in_with_a_provider_resumes_the_authorization_request()
    {
        using var flow = new AuthorizationFlowClient(_factory);
        var (email, _) = await flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();

        var (providerLogin, nonce) = await StartProviderSignInAsync(flow, pkce);

        // The existing controller accepts the callback path on the issuer's origin and hands
        // off to the provider.
        var challenge = await flow.Browser.GetAsync(providerLogin);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.Equal("accounts.google.com", challenge.Headers.Location!.Host);

        // What its callback does once the provider signs the user in: an exchange code.
        var code = await IssueExchangeCodeAsync(email);
        var landing = await flow.Browser.GetAsync($"/oauth/callback?resume={nonce}&code={code}");

        Assert.True(AuthorizationFlowClient.IsLocalRedirect(landing, "/connect/authorize"), await AuthorizationFlowClient.DescribeAsync(landing));
        var consent = await flow.Browser.GetAsync(landing.Headers.Location);
        var redirect = await flow.ConsentAsync(consent.Headers.Location!, "accept");
        Assert.True(AuthorizationFlowClient.Query(redirect.Headers.Location!).ContainsKey("code"));
    }

    [Fact]
    public async Task A_callback_link_from_someone_elses_sign_in_is_refused()
    {
        // The attacker starts a sign-in in their own browser and gets their own nonce, and
        // an exchange code for their own account.
        using var attacker = new AuthorizationFlowClient(_factory);
        var (attackerEmail, _) = await attacker.Backchannel.RegisterAsync();
        var (_, attackerNonce) = await StartProviderSignInAsync(attacker, Pkce.Create());
        var attackerCode = await IssueExchangeCodeAsync(attackerEmail);

        // The victim has a sign-in of their own under way, and follows the attacker's link.
        using var victim = new AuthorizationFlowClient(_factory);
        await StartProviderSignInAsync(victim, Pkce.Create());
        var landing = await victim.Browser.GetAsync($"/oauth/callback?resume={attackerNonce}&code={attackerCode}");

        Assert.Equal(HttpStatusCode.OK, landing.StatusCode);
        Assert.Contains("external-return-error", await landing.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        // Refused before the code was looked at: it is still unredeemed.
        await _factory.WithScopeAsync(async services =>
            Assert.NotNull(await services.GetRequiredService<IOAuthExchangeCodeService>().RedeemAsync(attackerCode)));
    }

    [Fact]
    public async Task A_provider_sign_in_still_asks_for_the_second_factor()
    {
        using var flow = new AuthorizationFlowClient(_factory);
        var (email, _) = await flow.Backchannel.RegisterAsync();
        await _factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByEmailAsync(email);
            await users.ResetAuthenticatorKeyAsync(user!);
            await users.SetTwoFactorEnabledAsync(user!, true);
        });

        var (_, nonce) = await StartProviderSignInAsync(flow, Pkce.Create());
        var landing = await flow.Browser.GetAsync($"/oauth/callback?resume={nonce}&code={await IssueExchangeCodeAsync(email)}");

        Assert.True(AuthorizationFlowClient.IsLocalRedirect(landing, "/connect/2fa"), await AuthorizationFlowClient.DescribeAsync(landing));
    }

    /// <summary>Opens the sign-in page and takes its provider button; returns where it leads, and the nonce it carries.</summary>
    private static async Task<(Uri ProviderLogin, string Nonce)> StartProviderSignInAsync(AuthorizationFlowClient flow, Pkce pkce)
    {
        var authorize = await flow.Browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, "provider"));
        var page = await flow.Browser.GetStringAsync(authorize.Headers.Location);

        var href = System.Text.RegularExpressions.Regex.Match(page, "data-testid=\"provider-google\"\\s+href=\"([^\"]+)\"").Groups[1].Value;
        var start = await flow.Browser.GetAsync(WebUtility.HtmlDecode(href));
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);

        var providerLogin = start.Headers.Location!;
        Assert.Equal("/api/v1/external-auth/login", providerLogin.OriginalString.Split('?')[0]);

        var returnUrl = new Uri(Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(providerLogin.OriginalString.Split('?')[1])["returnUrl"]!);
        Assert.Equal($"{AuthorizationServerFactory.Issuer}/oauth/callback", returnUrl.GetLeftPart(UriPartial.Path));

        return (providerLogin, AuthorizationFlowClient.Query(returnUrl)["resume"]);
    }

    private async Task<string> IssueExchangeCodeAsync(string email)
    {
        string code = string.Empty;
        await _factory.WithScopeAsync(async services =>
        {
            var user = await services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email);
            code = await services.GetRequiredService<IOAuthExchangeCodeService>().IssueAsync(user!.Id, "Google");
        });
        return code;
    }
}
