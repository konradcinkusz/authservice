using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Forgot and reset password: the link a user is sent, what following it changes, and the
/// rules that stop the endpoints being used to find out who has an account.
/// </summary>
public class PasswordResetTests : IntegrationTestBase
{
    private const string NewPassword = "Br4nd-new-Passw0rd!";
    private const string GenericMessage = "If an account with that email exists, a password reset link has been sent.";

    private Task<HttpResponseMessage> ForgotAsync(string email) =>
        Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });

    private Task<HttpResponseMessage> ResetAsync(string email, string token, string password = NewPassword) =>
        Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/reset-password", new { email, token, newPassword = password });

    private async Task<string> RequestTokenAsync(string email)
    {
        (await ForgotAsync(email)).EnsureSuccessStatusCode();
        return Factory.Emails.To(email, EmailKind.PasswordReset).Last().Token!;
    }

    private async Task<bool> CanSignInAsync(string email, string password) =>
        (await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/login", new { email, password })).IsSuccessStatusCode;

    private async Task<int> AuditCountAsync(string action, string userId)
    {
        var count = 0;
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            count = await context.AuditEvents.CountAsync(a => a.Action == action && a.TargetUserId == userId);
        });
        return count;
    }

    // ─── Asking for a link ───────────────────────────────────────────────────

    [Fact]
    public async Task Asking_for_a_reset_emails_the_account_a_link_that_carries_the_token()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await ForgotAsync(account.Email);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var email = Assert.Single(Factory.Emails.To(account.Email, EmailKind.PasswordReset));
        Assert.False(string.IsNullOrWhiteSpace(email.Token));
        Assert.StartsWith("http://localhost:3000/reset-password?", email.Url);
        Assert.Contains($"token={Uri.EscapeDataString(email.Token!)}", email.Url);
        Assert.Contains($"email={Uri.EscapeDataString(account.Email)}", email.Url);
        Assert.Equal(1, await AuditCountAsync(AuditAction.PasswordResetRequested, account.Id));
    }

    [Fact]
    public async Task An_unknown_address_gets_the_same_answer_as_a_known_one_and_no_email()
    {
        var account = await Factory.CreateAccountAsync();
        var stranger = TestData.NewEmail("stranger");

        var known = await (await ForgotAsync(account.Email)).Content.ReadAsStringAsync();
        var unknown = await (await ForgotAsync(stranger)).Content.ReadAsStringAsync();

        Assert.Equal(known, unknown);
        Assert.Contains(GenericMessage, unknown);
        Assert.DoesNotContain(Factory.Emails.Sent, e => e.To == stranger);
    }

    [Fact]
    public async Task A_malformed_address_is_refused_before_anything_is_looked_up()
    {
        var response = await ForgotAsync("not-an-email");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(Factory.Emails.Sent, e => e.Kind == EmailKind.PasswordReset);
    }

    [Fact]
    public async Task A_known_account_is_told_it_has_no_provider_to_use_instead()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await ForgotAsync(account.Email);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(body.GetProperty("isOAuthOnly").GetBoolean());
        Assert.Contains("password reset link", body.GetProperty("message").GetString());
    }

    [Fact]
    public async Task An_account_with_no_password_is_pointed_at_its_provider_and_sent_no_link()
    {
        var email = TestData.NewEmail("social");
        var signedIn = await Factory.CallbackAsync(new ProviderIdentity("Google", "google-key", email, EmailVerified: "true"));
        Assert.NotNull(signedIn.QueryValue("code"));

        var response = await ForgotAsync(email);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("isOAuthOnly").GetBoolean());
        Assert.Contains("Google", body.GetProperty("message").GetString());
        Assert.Empty(Factory.Emails.To(email, EmailKind.PasswordReset));
    }

    [Fact]
    public async Task An_account_with_no_password_and_no_provider_is_told_to_use_its_social_account()
    {
        var email = TestData.NewEmail("orphan");
        await Factory.WithScopeAsync(async services =>
            (await services.GetRequiredService<UserManager<ApplicationUser>>()
                .CreateAsync(new ApplicationUser { UserName = "orphan", Email = email })).ThrowIfFailed());

        var response = await ForgotAsync(email);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("isOAuthOnly").GetBoolean());
        Assert.Contains("your social account", body.GetProperty("message").GetString());
    }

    [Fact]
    public async Task A_failing_email_provider_does_not_fail_the_request_and_nothing_is_recorded_as_requested()
    {
        var account = await Factory.CreateAccountAsync();
        Factory.Emails.FailWith = new InvalidOperationException("provider down");

        var response = await ForgotAsync(account.Email);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(GenericMessage, await response.Content.ReadAsStringAsync());
        Assert.Equal(0, await AuditCountAsync(AuditAction.PasswordResetRequested, account.Id));

        Factory.Emails.FailWith = null;
        await ForgotAsync(account.Email);
        Assert.Single(Factory.Emails.To(account.Email, EmailKind.PasswordReset));
        Assert.Equal(1, await AuditCountAsync(AuditAction.PasswordResetRequested, account.Id));
    }

    // ─── Following a link ────────────────────────────────────────────────────

    [Fact]
    public async Task A_valid_link_sets_the_new_password_and_ends_every_session()
    {
        var account = await Factory.CreateAccountAsync();
        var token = await RequestTokenAsync(account.Email);

        var response = await ResetAsync(account.Email, token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await CanSignInAsync(account.Email, NewPassword));
        Assert.False(await CanSignInAsync(account.Email, TestData.ValidPassword));
        var refresh = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/refresh",
            new { refreshToken = account.Tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
        Assert.Equal(1, await AuditCountAsync(AuditAction.PasswordResetCompleted, account.Id));
    }

    [Fact]
    public async Task A_reset_link_works_once()
    {
        var account = await Factory.CreateAccountAsync();
        var token = await RequestTokenAsync(account.Email);
        await ResetAsync(account.Email, token);

        var again = await ResetAsync(account.Email, token, "An0ther-Passw0rd!");

        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        Assert.True(await CanSignInAsync(account.Email, NewPassword));
    }

    [Fact]
    public async Task A_wrong_token_is_refused_and_changes_nothing()
    {
        var account = await Factory.CreateAccountAsync();
        await RequestTokenAsync(account.Email);

        var response = await ResetAsync(account.Email, "not-the-token");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True(await CanSignInAsync(account.Email, TestData.ValidPassword));
        Assert.Equal(0, await AuditCountAsync(AuditAction.PasswordResetCompleted, account.Id));
    }

    [Fact]
    public async Task One_accounts_token_does_not_reset_another_account()
    {
        var victim = await Factory.CreateAccountAsync();
        var attacker = await Factory.CreateAccountAsync();
        var attackersToken = await RequestTokenAsync(attacker.Email);

        var response = await ResetAsync(victim.Email, attackersToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True(await CanSignInAsync(victim.Email, TestData.ValidPassword));
        Assert.False(await CanSignInAsync(victim.Email, NewPassword));
    }

    [Fact]
    public async Task An_unknown_address_is_refused_like_a_bad_token()
    {
        var account = await Factory.CreateAccountAsync();
        var token = await RequestTokenAsync(account.Email);
        var bad = await (await ResetAsync(account.Email, "not-the-token")).Content.ReadAsStringAsync();

        var response = await ResetAsync(TestData.NewEmail("stranger"), token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("Invalid or expired reset token.", await response.Content.ReadAsStringAsync());
        Assert.Contains("Invalid", bad);
    }

    [Fact]
    public async Task A_password_that_breaks_the_policy_is_refused_and_the_old_one_still_works()
    {
        var account = await Factory.CreateAccountAsync();
        var token = await RequestTokenAsync(account.Email);

        var response = await ResetAsync(account.Email, token, "alllowercase1!");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True(await CanSignInAsync(account.Email, TestData.ValidPassword));
    }

    [Theory]
    [InlineData("", "token", "Valid-Passw0rd!")]
    [InlineData("user@example.test", "", "Valid-Passw0rd!")]
    [InlineData("user@example.test", "token", "short")]
    [InlineData("not-an-email", "token", "Valid-Passw0rd!")]
    public async Task A_malformed_request_is_a_bad_request_with_the_reasons(string email, string token, string password)
    {
        var response = await ResetAsync(email, token, password);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task A_link_stops_working_once_the_password_has_been_changed_another_way()
    {
        var account = await Factory.CreateAccountAsync();
        var token = await RequestTokenAsync(account.Email);
        var changed = await Factory.ClientFor(account.Tokens).PostAsJsonAsync("/api/v1/auth/change-password",
            new { currentPassword = TestData.ValidPassword, newPassword = "Chang3d-Passw0rd!" });
        changed.EnsureSuccessStatusCode();

        var response = await ResetAsync(account.Email, token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True(await CanSignInAsync(account.Email, "Chang3d-Passw0rd!"));
    }
}

/// <summary>The same link when the deployment has said where its frontend lives.</summary>
public class PasswordResetFrontendUrlTests : IntegrationTestBase
{
    protected override IReadOnlyDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        ["FrontendBaseUrl"] = "https://app.example.test/"
    };

    [Fact]
    public async Task The_link_points_at_the_configured_frontend_without_a_doubled_slash()
    {
        var account = await Factory.CreateAccountAsync();

        await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = account.Email });

        var email = Assert.Single(Factory.Emails.To(account.Email, EmailKind.PasswordReset));
        Assert.StartsWith("https://app.example.test/reset-password?token=", email.Url);
    }
}
