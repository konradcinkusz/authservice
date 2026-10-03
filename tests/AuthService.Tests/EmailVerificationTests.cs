using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
/// A deployment that can send email makes a new address prove itself: registration answers 202
/// with no tokens, and the emailed link is what confirms the address.
/// </summary>
public class EmailVerificationTests : IntegrationTestBase
{
    // Both switches production derives from one setting, turned on together.
    protected override void ConfigureServices(IServiceCollection services)
    {
        services.Configure<IdentityOptions>(o => o.SignIn.RequireConfirmedEmail = true);
        services.Configure<AuthOptions>(o => o.RequireConfirmedEmail = true);
    }

    private async Task<string> RegisterPendingAsync(string? email = null)
    {
        email ??= TestData.NewEmail();
        var response = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = TestData.ValidPassword,
            acceptedTermsVersion = TestData.TermsVersion,
            acceptedPrivacyVersion = TestData.PrivacyVersion
        });
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        return email;
    }

    private string TokenFor(string email) => Factory.Emails.To(email, EmailKind.Verification).Last().Token!;

    private Task<HttpResponseMessage> VerifyAsync(string email, string token) =>
        Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/verify-email", new { email, token });

    private Task<HttpResponseMessage> ResendAsync(string email) =>
        Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/resend-verification", new { email });

    private async Task<bool> ConfirmedAsync(string email) => await Factory.ReadUserAsync(email, u => u.EmailConfirmed);

    private async Task<int> AuditCountAsync(string action, string email)
    {
        var id = await Factory.UserIdAsync(email);
        var count = 0;
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            count = await context.AuditEvents.CountAsync(a => a.Action == action && a.TargetUserId == id);
        });
        return count;
    }

    [Fact]
    public async Task Registering_answers_202_with_no_tokens_and_emails_a_verification_link()
    {
        var email = TestData.NewEmail();

        var response = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = TestData.ValidPassword,
            acceptedTermsVersion = TestData.TermsVersion,
            acceptedPrivacyVersion = TestData.PrivacyVersion
        });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(email, body.GetProperty("email").GetString());
        Assert.False(body.TryGetProperty("accessToken", out _));
        Assert.False(body.TryGetProperty("refreshToken", out _));

        var link = Assert.Single(Factory.Emails.To(email, EmailKind.Verification));
        Assert.StartsWith("http://localhost:3000/verify-email?token=", link.Url);
        Assert.Contains($"email={Uri.EscapeDataString(email)}", link.Url);
        Assert.Single(Factory.Emails.To(email, EmailKind.Welcome));
        Assert.False(await ConfirmedAsync(email));
        Assert.Equal(1, await AuditCountAsync(AuditAction.EmailVerificationSent, email));
    }

    [Fact]
    public async Task The_link_confirms_the_address_and_the_user_can_then_sign_in()
    {
        var email = await RegisterPendingAsync();

        var response = await VerifyAsync(email, TokenFor(email));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await ConfirmedAsync(email));
        await Factory.ClientFor().LoginAsync(email);
        Assert.Equal(1, await AuditCountAsync(AuditAction.EmailVerified, email));
    }

    [Fact]
    public async Task A_wrong_token_is_refused_and_the_address_stays_unconfirmed()
    {
        var email = await RegisterPendingAsync();

        var response = await VerifyAsync(email, "not-the-token");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await ConfirmedAsync(email));
        Assert.Equal(0, await AuditCountAsync(AuditAction.EmailVerified, email));
    }

    [Fact]
    public async Task A_token_confirms_only_the_account_it_was_issued_for()
    {
        var mine = await RegisterPendingAsync();
        var theirs = await RegisterPendingAsync();

        var response = await VerifyAsync(theirs, TokenFor(mine));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await ConfirmedAsync(theirs));
    }

    [Fact]
    public async Task An_unknown_address_is_refused_in_exactly_the_words_of_a_bad_token()
    {
        var email = await RegisterPendingAsync();
        var badToken = await (await VerifyAsync(email, "not-the-token")).Content.ReadAsStringAsync();

        var unknown = await VerifyAsync(TestData.NewEmail("stranger"), TokenFor(email));

        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Equal(badToken, await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_deleted_account_cannot_be_verified()
    {
        var email = await RegisterPendingAsync();
        var token = TokenFor(email);
        await Factory.UpdateUserAsync(email, u => u.IsDeleted = true);

        var response = await VerifyAsync(email, token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await ConfirmedAsync(email));
    }

    [Fact]
    public async Task An_address_that_is_already_confirmed_is_told_so_whatever_token_it_sends()
    {
        var email = await RegisterPendingAsync();
        await VerifyAsync(email, TokenFor(email));

        var again = await VerifyAsync(email, "anything");

        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Contains("already verified", await again.Content.ReadAsStringAsync());
        Assert.Equal(1, await AuditCountAsync(AuditAction.EmailVerified, email));
    }

    [Theory]
    [InlineData("", "token")]
    [InlineData("user@example.test", "")]
    [InlineData("not-an-email", "token")]
    public async Task A_malformed_verification_request_is_refused(string email, string token)
    {
        var response = await VerifyAsync(email, token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Resending_sends_a_fresh_link_that_works()
    {
        var email = await RegisterPendingAsync();

        var response = await ResendAsync(email);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, Factory.Emails.To(email, EmailKind.Verification).Count());
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(email, TokenFor(email))).StatusCode);
    }

    [Fact]
    public async Task Resending_answers_alike_for_everyone_and_mails_only_an_account_that_needs_it()
    {
        var pending = await RegisterPendingAsync();
        var confirmed = await RegisterPendingAsync();
        await VerifyAsync(confirmed, TokenFor(confirmed));
        var deleted = await RegisterPendingAsync();
        await Factory.UpdateUserAsync(deleted, u => u.IsDeleted = true);
        var unknown = TestData.NewEmail("stranger");

        var answers = new List<string>();
        foreach (var address in new[] { pending, confirmed, deleted, unknown })
            answers.Add(await (await ResendAsync(address)).Content.ReadAsStringAsync());

        Assert.Single(answers.Distinct());
        Assert.Equal(2, Factory.Emails.To(pending, EmailKind.Verification).Count());
        Assert.Single(Factory.Emails.To(confirmed, EmailKind.Verification));
        Assert.Single(Factory.Emails.To(deleted, EmailKind.Verification));
        Assert.Empty(Factory.Emails.To(unknown));
    }

    [Fact]
    public async Task A_failing_email_provider_does_not_fail_registration_or_a_resend()
    {
        Factory.Emails.FailWith = new InvalidOperationException("provider down");
        var email = TestData.NewEmail();

        var registered = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = TestData.ValidPassword,
            acceptedTermsVersion = TestData.TermsVersion,
            acceptedPrivacyVersion = TestData.PrivacyVersion
        });
        var resent = await ResendAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, registered.StatusCode);
        Assert.Equal(HttpStatusCode.OK, resent.StatusCode);
        Assert.False(await ConfirmedAsync(email));
        Assert.Equal(0, await AuditCountAsync(AuditAction.EmailVerificationSent, email));

        Factory.Emails.FailWith = null;
        await ResendAsync(email);
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(email, TokenFor(email))).StatusCode);
    }
}

/// <summary>
/// The controller's own check, for when Identity's is off: a password that checks out on an
/// unconfirmed account is told to verify rather than given tokens.
/// </summary>
public class EmailConfirmationGateTests : IntegrationTestBase
{
    protected override void ConfigureServices(IServiceCollection services) =>
        services.Configure<AuthOptions>(o => o.RequireConfirmedEmail = true);

    [Fact]
    public async Task A_correct_password_on_an_unconfirmed_account_is_told_to_verify()
    {
        var email = TestData.NewEmail();
        var registered = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = TestData.ValidPassword,
            acceptedTermsVersion = TestData.TermsVersion,
            acceptedPrivacyVersion = TestData.PrivacyVersion
        });
        Assert.Equal(HttpStatusCode.Accepted, registered.StatusCode);

        var login = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestData.ValidPassword });

        Assert.Equal(HttpStatusCode.Forbidden, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("emailVerificationRequired").GetBoolean());
        Assert.False(body.TryGetProperty("accessToken", out _));
    }
}
