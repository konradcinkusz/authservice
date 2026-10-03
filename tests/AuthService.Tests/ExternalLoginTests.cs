using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace AuthService.Tests;

/// <summary>Starting a sign-in with Google or GitHub: which providers exist and where the browser may be sent afterwards.</summary>
public class ExternalLoginEntryTests : IntegrationTestBase
{
    private const string Login = "/api/v1/external-auth/login";

    protected override IReadOnlyDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        ["OAuth:Google:ClientId"] = "test-google-client",
        ["OAuth:Google:ClientSecret"] = "test-google-secret",
        ["OAuth:PostLoginRedirectAllowedBaseUrls:0"] = "https://app.example.test"
    };

    private Task<HttpResponseMessage> StartAsync(string provider, string? returnUrl = null) =>
        Factory.ClientFor().GetAsync($"{Login}?provider={Uri.EscapeDataString(provider)}" +
            (returnUrl is null ? "" : $"&returnUrl={Uri.EscapeDataString(returnUrl)}"));

    [Fact]
    public async Task Only_the_providers_that_have_credentials_are_offered()
    {
        var response = await Factory.ClientFor().GetAsync("/api/v1/external-auth/providers");

        var providers = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("providers");
        Assert.Equal(["Google"], providers.EnumerateArray().Select(p => p.GetProperty("provider").GetString()));
    }

    [Theory]
    [InlineData("Google")]
    [InlineData("google")]
    [InlineData("GOOGLE")]
    public async Task A_configured_provider_hands_the_browser_to_the_provider_whatever_the_case_of_its_name(string provider)
    {
        var response = await StartAsync(provider);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("accounts.google.com", response.Headers.Location!.Host);
    }

    [Fact]
    public async Task A_provider_that_is_not_supported_is_refused_with_the_ones_that_are()
    {
        var response = await StartAsync("Facebook");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("Google, GitHub", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task No_provider_at_all_is_a_bad_request(string provider)
    {
        Assert.Equal(HttpStatusCode.BadRequest, (await StartAsync(provider)).StatusCode);
    }

    [Theory]
    [InlineData("GitHub")]
    [InlineData("github")]
    public async Task A_supported_provider_with_no_credentials_is_refused_not_a_server_error(string provider)
    {
        var response = await StartAsync(provider);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("not configured", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("http://localhost:3000/oauth/callback")]
    [InlineData("http://localhost:3000/oauth/callback/finish")]
    [InlineData("http://LOCALHOST:3000/OAuth/Callback")]
    [InlineData("https://app.example.test/oauth/callback")]
    public async Task A_return_address_on_an_allowed_origin_and_the_callback_path_is_accepted(string returnUrl)
    {
        var response = await StartAsync("Google", returnUrl);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    [Theory]
    [InlineData("https://evil.test/oauth/callback")]
    [InlineData("http://localhost:3001/oauth/callback")]
    [InlineData("https://localhost:3000/oauth/callback")]
    [InlineData("http://localhost:3000/somewhere-else")]
    [InlineData("http://localhost:3000/oauth/callbackx")]
    [InlineData("http://localhost:3000/oauth/callback/../admin")]
    [InlineData("http://localhost:3000.evil.test/oauth/callback")]
    [InlineData("http://localhost:3000@evil.test/oauth/callback")]
    [InlineData("/oauth/callback")]
    [InlineData("javascript:alert(1)")]
    public async Task A_return_address_anywhere_else_is_refused_so_the_code_cannot_be_sent_to_a_stranger(string returnUrl)
    {
        var response = await StartAsync("Google", returnUrl);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("allowed origin", await response.Content.ReadAsStringAsync());
    }
}

/// <summary>
/// Coming back from the provider: the callback finds or creates the account, and hands the
/// browser a one-time code instead of tokens. The provider's sign-in is the signed cookie it
/// leaves behind, which these tests write the way the provider's handler does.
/// </summary>
public class ExternalLoginCallbackTests : IntegrationTestBase
{
    private const string LoginPage = "http://localhost:3000/login";

    private static ProviderIdentity Google(string? email, string key = "google-key-1", string? verified = "true") =>
        new("Google", key, email, EmailVerified: verified);

    private Task<HttpResponseMessage> CallbackAsync(ProviderIdentity? identity) => Factory.CallbackAsync(identity);

    private Task<HttpResponseMessage> ExchangeAsync(string? code) =>
        Factory.ClientFor().PostAsJsonAsync("/api/v1/external-auth/exchange", new { code });

    private static void AssertRefusedWith(HttpResponseMessage response, string error)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith($"{LoginPage}?error={error}", response.Headers.Location!.ToString());
        Assert.Null(response.QueryValue("code"));
    }

    private async Task<IList<UserLoginInfo>> LoginsAsync(string email)
    {
        IList<UserLoginInfo> logins = [];
        await Factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            logins = await users.GetLoginsAsync((await users.FindByEmailAsync(email))!);
        });

        return logins;
    }

    private async Task<int> UserCountAsync()
    {
        var count = 0;
        await Factory.WithScopeAsync(async services =>
            count = await services.GetRequiredService<ApplicationDbContext>().Users.CountAsync());

        return count;
    }

    // ─── Nothing to go on ────────────────────────────────────────────────────

    [Fact]
    public async Task A_callback_with_no_provider_sign_in_behind_it_goes_back_to_the_login_page_with_an_error()
    {
        AssertRefusedWith(await CallbackAsync(null), "oauth_failed");
    }

    [Fact]
    public async Task A_provider_that_gave_no_address_is_turned_away()
    {
        AssertRefusedWith(await CallbackAsync(Google(email: null)), "no_email");
        Assert.Equal(0, await UserCountAsync());
    }

    // ─── A new person ────────────────────────────────────────────────────────

    [Fact]
    public async Task A_new_verified_address_becomes_a_confirmed_account_and_the_browser_gets_a_one_time_code()
    {
        var email = TestData.NewEmail("newcomer");

        var response = await CallbackAsync(Google(email));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("http://localhost:3000/oauth/callback?code=", response.Headers.Location!.ToString());
        Assert.Null(response.QueryValue("accessToken"));
        Assert.Null(response.QueryValue("refreshToken"));

        var user = await Factory.ReadUserAsync(email, u => u);
        Assert.True(user.EmailConfirmed);
        Assert.Null(user.PasswordHash);
        Assert.NotNull(user.LastLoginAt);
        var login = Assert.Single(await LoginsAsync(email));
        Assert.Equal(("Google", "google-key-1"), (login.LoginProvider, login.ProviderKey));
        Assert.Single(Factory.Emails.To(email, EmailKind.Welcome));
        var created = Assert.Single(await Factory.AuditAsync(AuditAction.OAuthAccountCreated));
        Assert.Equal(user.Id, created.TargetUserId);
        Assert.Contains("Google", created.Metadata);
    }

    [Fact]
    public async Task The_code_buys_tokens_once()
    {
        var email = TestData.NewEmail("newcomer");
        var code = (await CallbackAsync(Google(email))).QueryValue("code");

        var first = await ExchangeAsync(code);
        var second = await ExchangeAsync(code);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var tokens = (await first.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;
        var me = await Factory.ClientFor(tokens).GetFromJsonAsync<JsonElement>("/api/v1/auth/me");
        Assert.Equal(email, me.GetProperty("email").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
        var exchanged = Assert.Single(await Factory.AuditAsync(AuditAction.LoginSucceeded));
        Assert.Contains("oauth_exchange", exchanged.Metadata);
    }

    [Fact]
    public async Task Addresses_that_make_the_same_user_name_get_a_numeric_suffix_and_the_name_comes_from_the_address()
    {
        var domain = $"d{Guid.NewGuid():N}"[..8];
        var first = $"jane.doe@{domain}.test";
        var second = $"janedoe+news@{domain}.test";

        await CallbackAsync(Google(first, "key-a"));
        await CallbackAsync(Google(second, "key-b"));

        Assert.Equal($"janedoe_{domain}", await Factory.ReadUserAsync(first, u => u.UserName));
        Assert.Equal($"janedoenews_{domain}", await Factory.ReadUserAsync(second, u => u.UserName));

        await CallbackAsync(Google($"jane.doe@{domain}.example", "key-c"));
        Assert.Equal($"janedoe_{domain}1", await Factory.ReadUserAsync($"jane.doe@{domain}.example", u => u.UserName));
    }

    [Theory]
    [InlineData("https://lh3.googleusercontent.com/a/photo=s64-c", "https://lh3.googleusercontent.com/a/photo=s96-c")]
    [InlineData("https://lh3.googleusercontent.com/a/photo=s1024-c", "https://lh3.googleusercontent.com/a/photo=s96-c")]
    [InlineData("https://lh3.googleusercontent.com/a/photo", "https://lh3.googleusercontent.com/a/photo=s96-c")]
    [InlineData("https://example.test/avatar.png", "https://example.test/avatar.png")]
    public async Task A_google_picture_is_asked_for_at_96_pixels_and_any_other_is_left_alone(string given, string stored)
    {
        var email = TestData.NewEmail("pictured");

        await CallbackAsync(Google(email) with { Picture = given });

        Assert.Equal(stored, await Factory.ReadUserAsync(email, u => u.ProfileImageUrl));
    }

    [Fact]
    public async Task A_github_avatar_is_used_when_there_is_no_picture()
    {
        var email = TestData.NewEmail("octo");

        await CallbackAsync(Google(email) with { AvatarUrl = "https://avatars.example.test/u/1" });

        Assert.Equal("https://avatars.example.test/u/1", await Factory.ReadUserAsync(email, u => u.ProfileImageUrl));
    }

    // ─── Someone who already has an account ──────────────────────────────────

    [Fact]
    public async Task A_verified_address_that_already_has_an_account_is_linked_to_it_not_given_a_second_one()
    {
        var existing = await Factory.CreateAccountAsync();
        var before = await UserCountAsync();

        var response = await CallbackAsync(Google(existing.Email));

        Assert.StartsWith("http://localhost:3000/oauth/callback?code=", response.Headers.Location!.ToString());
        Assert.Equal(before, await UserCountAsync());
        Assert.Equal("Google", Assert.Single(await LoginsAsync(existing.Email)).LoginProvider);
        Assert.Single(Factory.Emails.To(existing.Email, EmailKind.OAuthLinked));
        var linked = Assert.Single(await Factory.AuditAsync(AuditAction.OAuthAccountLinked));
        Assert.Equal(existing.Id, linked.TargetUserId);

        var tokens = (await (await ExchangeAsync(response.QueryValue("code"))).Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;
        using var payload = tokens.Payload();
        Assert.Equal(existing.Id, payload.RootElement.GetProperty("sub").GetString());
        await Factory.ClientFor().LoginAsync(existing.Email);
    }

    [Theory]
    [InlineData("false")]
    [InlineData(null)]
    public async Task An_address_the_provider_did_not_verify_cannot_be_used_to_take_over_an_account(string? verified)
    {
        var victim = await Factory.CreateAccountAsync();

        var response = await CallbackAsync(Google(victim.Email, verified: verified));

        AssertRefusedWith(response, "email_not_verified&provider=Google");
        Assert.Empty(await LoginsAsync(victim.Email));
        Assert.Empty(Factory.Emails.To(victim.Email, EmailKind.OAuthLinked));
        var refusal = Assert.Single(await Factory.AuditAsync(AuditAction.OAuthLinkRejectedUnverified));
        Assert.False(refusal.Succeeded);
        Assert.Contains(victim.Email, refusal.Metadata);
    }

    [Fact]
    public async Task An_address_the_provider_did_not_verify_does_not_create_an_account_either()
    {
        var email = TestData.NewEmail("unproven");

        var response = await CallbackAsync(Google(email, verified: "false"));

        AssertRefusedWith(response, "email_not_verified");
        Assert.Equal(0, await UserCountAsync());
        Assert.Empty(Factory.Emails.To(email));
    }

    [Fact]
    public async Task A_failing_email_provider_does_not_stop_a_sign_in()
    {
        Factory.Emails.FailWith = new InvalidOperationException("provider down");
        var existing = await Factory.CreateAccountAsync();
        var newcomer = TestData.NewEmail("newcomer");

        var linked = await CallbackAsync(Google(existing.Email, "key-existing"));
        var created = await CallbackAsync(Google(newcomer, "key-newcomer"));

        Assert.NotNull(linked.QueryValue("code"));
        Assert.NotNull(created.QueryValue("code"));
        Assert.Equal("Google", Assert.Single(await LoginsAsync(existing.Email)).LoginProvider);
        Assert.True(await Factory.ReadUserAsync(newcomer, u => u.EmailConfirmed));
    }

    [Fact]
    public async Task An_address_the_provider_vouches_for_but_that_cannot_be_an_account_creates_nothing()
    {
        var response = await CallbackAsync(Google("not an address", verified: "true"));

        AssertRefusedWith(response, "creation_failed");
        Assert.Equal(0, await UserCountAsync());
    }

    [Fact]
    public async Task A_provider_identity_that_is_already_linked_signs_in_on_its_key_alone()
    {
        var existing = await Factory.CreateAccountAsync();
        await CallbackAsync(Google(existing.Email, "key-linked"));
        var before = await UserCountAsync();

        // The provider now reports another address, unverified: the key is still the proof.
        var response = await CallbackAsync(Google(TestData.NewEmail("changed"), "key-linked", verified: "false"));

        Assert.StartsWith("http://localhost:3000/oauth/callback?code=", response.Headers.Location!.ToString());
        Assert.Equal(before, await UserCountAsync());
        var tokens = (await (await ExchangeAsync(response.QueryValue("code"))).Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;
        using var payload = tokens.Payload();
        Assert.Equal(existing.Id, payload.RootElement.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task A_locked_out_account_is_turned_away()
    {
        var existing = await Factory.CreateAccountAsync();
        await CallbackAsync(Google(existing.Email, "key-locked"));
        await Factory.UpdateUserAsync(existing.Email, u => u.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(10));

        AssertRefusedWith(await CallbackAsync(Google(existing.Email, "key-locked")), "locked_out");
    }

    [Fact]
    public async Task A_deleted_account_is_turned_away_whether_it_is_found_by_its_link_or_by_its_address()
    {
        var linked = await Factory.CreateAccountAsync();
        await CallbackAsync(Google(linked.Email, "key-deleted"));
        await Factory.UpdateUserAsync(linked.Email, u => u.IsDeleted = true);
        var byAddress = await Factory.CreateAccountAsync();
        await Factory.UpdateUserAsync(byAddress.Email, u => u.IsDeleted = true);

        AssertRefusedWith(await CallbackAsync(Google(linked.Email, "key-deleted")), "account_deleted");
        AssertRefusedWith(await CallbackAsync(Google(byAddress.Email, "key-other")), "account_deleted");
    }

    [Fact]
    public async Task The_return_address_kept_in_the_sign_in_is_where_the_code_is_sent()
    {
        var response = await CallbackAsync(Google(TestData.NewEmail("returning")) with
        {
            ReturnUrl = "http://localhost:3000/oauth/callback?from=login"
        });

        Assert.StartsWith("http://localhost:3000/oauth/callback?from=login&code=", response.Headers.Location!.ToString());
    }

    // ─── Exchanging the code ─────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Exchanging_without_a_code_is_a_bad_request(string? code)
    {
        Assert.Equal(HttpStatusCode.BadRequest, (await ExchangeAsync(code)).StatusCode);
    }

    [Fact]
    public async Task A_code_that_was_never_issued_buys_nothing()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await ExchangeAsync("never-issued")).StatusCode);
    }

    [Fact]
    public async Task A_code_is_stored_as_a_hash_and_expires_after_a_minute()
    {
        var email = TestData.NewEmail("slow");
        var code = (await CallbackAsync(Google(email))).QueryValue("code")!;
        OAuthExchangeCode stored = null!;
        await Factory.WithScopeAsync(async services =>
            stored = await services.GetRequiredService<ApplicationDbContext>().OAuthExchangeCodes.AsNoTracking().SingleAsync());

        Assert.NotEqual(code, stored.CodeHash);
        Assert.Equal(TokenHasher.Hash(code), stored.CodeHash);
        Assert.Equal("Google", stored.Provider);
        Assert.InRange(stored.ExpiresAt - stored.CreatedAt, TimeSpan.FromSeconds(59), TimeSpan.FromSeconds(61));

        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            (await context.OAuthExchangeCodes.SingleAsync()).ExpiresAt = DateTime.UtcNow.AddSeconds(-1);
            await context.SaveChangesAsync();
        });

        Assert.Equal(HttpStatusCode.Unauthorized, (await ExchangeAsync(code)).StatusCode);
    }

    [Fact]
    public async Task Issuing_a_code_sweeps_away_the_ones_that_expired_an_hour_ago()
    {
        await CallbackAsync(Google(TestData.NewEmail("first"), "key-first"));
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            (await context.OAuthExchangeCodes.SingleAsync()).ExpiresAt = DateTime.UtcNow.AddHours(-2);
            await context.SaveChangesAsync();
        });

        await CallbackAsync(Google(TestData.NewEmail("second"), "key-second"));

        await Factory.WithScopeAsync(async services =>
            Assert.Single(await services.GetRequiredService<ApplicationDbContext>().OAuthExchangeCodes.ToListAsync()));
    }

    [Theory]
    [InlineData("deleted")]
    [InlineData("locked")]
    public async Task A_code_buys_nothing_once_its_account_has_become_unavailable(string state)
    {
        var email = TestData.NewEmail("unavailable");
        var code = (await CallbackAsync(Google(email))).QueryValue("code");
        await Factory.UpdateUserAsync(email, u =>
        {
            if (state == "deleted")
                u.IsDeleted = true;
            else
                u.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(10);
        });

        var response = await ExchangeAsync(code);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("accessToken", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task An_account_with_two_factor_is_given_a_challenge_instead_of_tokens()
    {
        var existing = await Factory.CreateAccountAsync();
        await Factory.UpdateUserAsync(existing.Email, u => u.TwoFactorEnabled = true);
        var code = (await CallbackAsync(Google(existing.Email))).QueryValue("code");

        var response = await ExchangeAsync(code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("requiresTwoFactor").GetBoolean());
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("challengeToken").GetString()));
        Assert.Equal(300, body.GetProperty("expiresIn").GetInt32());
        Assert.False(body.TryGetProperty("accessToken", out _));
    }
}

/// <summary>GitHub does not say whether an address is verified: the service asks, with the user's own token.</summary>
public class ExternalLoginGitHubTests : IntegrationTestBase
{
    private string _emailsAnswer = "[]";
    private StubHttpHandler _github = null!;

    protected override void ConfigureServices(IServiceCollection services)
    {
        _github = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(_emailsAnswer, Encoding.UTF8, "application/json")
        });
        services.RemoveAll<IHttpClientFactory>();
        services.AddSingleton<IHttpClientFactory>(new StubHttpClientFactory(_github));
    }

    private static ProviderIdentity GitHub(string email) =>
        new("GitHub", "github-key-1", email, AccessToken: "gh-token", AvatarUrl: "https://avatars.example.test/u/1");

    [Fact]
    public async Task An_address_github_lists_as_verified_makes_an_account_and_the_avatar_is_kept()
    {
        var email = TestData.NewEmail("octo");
        _emailsAnswer = $$"""[{"email":"{{email}}","verified":true,"primary":true}]""";

        var response = await Factory.CallbackAsync(GitHub(email));

        Assert.StartsWith("http://localhost:3000/oauth/callback?code=", response.Headers.Location!.ToString());
        Assert.Equal("https://avatars.example.test/u/1", await Factory.ReadUserAsync(email, u => u.ProfileImageUrl));
        var asked = Assert.Single(_github.Requests);
        Assert.Equal("gh-token", asked.Headers.Authorization!.Parameter);
    }

    [Fact]
    public async Task An_address_github_lists_as_unverified_is_refused_and_links_nothing()
    {
        var victim = await Factory.CreateAccountAsync();
        _emailsAnswer = $$"""[{"email":"{{victim.Email}}","verified":false,"primary":true}]""";

        var response = await Factory.CallbackAsync(GitHub(victim.Email));

        Assert.StartsWith("http://localhost:3000/login?error=email_not_verified&provider=GitHub", response.Headers.Location!.ToString());
        var refusal = Assert.Single(await Factory.AuditAsync(AuditAction.OAuthLinkRejectedUnverified));
        Assert.Contains("email_not_verified", refusal.Metadata);
        Assert.Empty(Factory.Emails.To(victim.Email, EmailKind.OAuthLinked));
    }
}

/// <summary>The escape hatch for deployments mid-migration: an address the provider did not verify is accepted.</summary>
public class ExternalLoginUnverifiedAddressAllowedTests : IntegrationTestBase
{
    protected override void ConfigureServices(IServiceCollection services) =>
        services.Configure<AuthOptions>(o => o.RequireVerifiedProviderEmail = false);

    [Fact]
    public async Task With_the_check_switched_off_an_unverified_address_is_linked_to_the_account_that_has_it()
    {
        var existing = await Factory.CreateAccountAsync();

        var response = await Factory.CallbackAsync(new ProviderIdentity("Google", "key", existing.Email, EmailVerified: "false"));

        Assert.StartsWith("http://localhost:3000/oauth/callback?code=", response.Headers.Location!.ToString());
        Assert.Empty(await Factory.AuditAsync(AuditAction.OAuthLinkRejectedUnverified));
    }
}

/// <summary>The legacy redirect that carries tokens in the URL: off by default, and when on it says so by what it does.</summary>
public class ExternalLoginTokensInRedirectTests : IntegrationTestBase
{
    protected override void ConfigureServices(IServiceCollection services) =>
        services.Configure<AuthOptions>(o => o.AllowTokensInOAuthRedirect = true);

    [Fact]
    public async Task With_the_legacy_switch_on_the_tokens_travel_in_the_url_and_no_code_is_issued()
    {
        var response = await Factory.CallbackAsync(
            new ProviderIdentity("Google", "key", TestData.NewEmail("legacy"), EmailVerified: "true"));

        Assert.False(string.IsNullOrWhiteSpace(response.QueryValue("accessToken")));
        Assert.False(string.IsNullOrWhiteSpace(response.QueryValue("refreshToken")));
        Assert.Equal("3600", response.QueryValue("expiresIn"));
        Assert.Null(response.QueryValue("code"));
        await Factory.WithScopeAsync(async services =>
            Assert.Empty(await services.GetRequiredService<ApplicationDbContext>().OAuthExchangeCodes.ToListAsync()));
    }
}
