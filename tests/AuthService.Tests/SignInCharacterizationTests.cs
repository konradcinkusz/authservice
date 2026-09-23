using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Every branch of the password sign-in decision in <c>POST /api/v1/auth/login</c>, pinned
/// before that decision was extracted into <c>SignInFlow</c> so the authorization server's
/// sign-in page could share it (AUTH-MCP-01, AC2). The response bodies and audit rows are the
/// behaviour being preserved, including the enumeration-safety and lockout-disclosure rules
/// (IDENTITY-AND-ACCOUNTS.md §5, §6).
/// </summary>
public class SignInCharacterizationTests : IntegrationTestBase
{
    private const string GenericFailure = "Invalid email or password";

    [Fact]
    public async Task An_unknown_email_gets_the_generic_failure_and_an_audit_row()
    {
        var email = TestData.NewEmail("nobody");

        var response = await LoginAsync(email, TestData.ValidPassword);

        await AssertGenericFailureAsync(response);
        var audit = await SingleAuditAsync(AuditAction.LoginFailed, a => a.TargetUserId == null && a.Metadata!.Contains(email));
        Assert.False(audit.Succeeded);
        Assert.Equal("unknown_or_deleted_account", Reason(audit));
    }

    [Fact]
    public async Task A_soft_deleted_account_gets_the_generic_failure_even_with_the_right_password()
    {
        var (email, _) = await Client.RegisterAsync();
        await UpdateUserAsync(email, user => user.IsDeleted = true);

        var response = await LoginAsync(email, TestData.ValidPassword);

        await AssertGenericFailureAsync(response);
        var audit = await SingleAuditAsync(AuditAction.LoginFailed, a => a.TargetUserId == null && a.Metadata!.Contains(email));
        Assert.Equal("unknown_or_deleted_account", Reason(audit));
    }

    [Fact]
    public async Task A_wrong_password_gets_the_generic_failure_and_counts_toward_lockout()
    {
        var (email, _) = await Client.RegisterAsync();
        var userId = await GetUserIdAsync(email);

        var response = await LoginAsync(email, "Wr0ng-password!");

        await AssertGenericFailureAsync(response);
        Assert.Equal(1, await GetUserAsync(email, u => u.AccessFailedCount));
        var audit = await SingleAuditAsync(AuditAction.LoginFailed, a => a.TargetUserId == userId);
        Assert.Equal("invalid_password", Reason(audit));
    }

    [Fact]
    public async Task Lockout_is_disclosed_only_to_a_caller_who_knows_the_password()
    {
        var (email, _) = await Client.RegisterAsync();
        var userId = await GetUserIdAsync(email);

        // Five failures is the configured threshold.
        for (var i = 0; i < 5; i++)
            await AssertGenericFailureAsync(await LoginAsync(email, "Wr0ng-password!"));

        // Wrong password on a locked account: still the generic answer, recorded as locked_out.
        await AssertGenericFailureAsync(await LoginAsync(email, "Wr0ng-password!"));
        Assert.Contains(await AuditRowsAsync(AuditAction.LoginFailed, a => a.TargetUserId == userId),
            a => Reason(a) == "locked_out");

        // Right password on a locked account: the lockout is disclosed.
        var response = await LoginAsync(email, TestData.ValidPassword);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(["error", "lockedOut", "lockoutEnd"], body.RootElement.EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal("Account is temporarily locked after too many failed sign-in attempts.",
            body.RootElement.GetProperty("error").GetString());
        Assert.True(body.RootElement.GetProperty("lockedOut").GetBoolean());
        Assert.True(body.RootElement.GetProperty("lockoutEnd").GetDateTimeOffset() > DateTimeOffset.UtcNow);

        var audit = await SingleAuditAsync(AuditAction.LoginLockedOut, a => a.TargetUserId == userId);
        Assert.False(audit.Succeeded);
    }

    [Fact]
    public async Task A_two_factor_account_gets_a_challenge_and_no_session()
    {
        var (email, _) = await Client.RegisterAsync();
        var userId = await GetUserIdAsync(email);
        await Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            await userManager.ResetAuthenticatorKeyAsync(user!);
            await userManager.SetTwoFactorEnabledAsync(user!, true);
        });
        // Registration itself issued one session.
        var sessionsBefore = (await RefreshTokensAsync(userId)).Count;

        var response = await LoginAsync(email, TestData.ValidPassword);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(["challengeToken", "expiresIn", "requiresTwoFactor"], body.RootElement.EnumerateObject().Select(p => p.Name).Order());
        Assert.True(body.RootElement.GetProperty("requiresTwoFactor").GetBoolean());
        Assert.Equal(300, body.RootElement.GetProperty("expiresIn").GetInt32());

        // The first factor alone is not a sign-in.
        Assert.Null(await GetUserAsync(email, u => u.LastLoginAt));
        Assert.Empty(await AuditRowsAsync(AuditAction.LoginSucceeded, a => a.TargetUserId == userId));
        Assert.Equal(sessionsBefore, (await RefreshTokensAsync(userId)).Count);
    }

    [Fact]
    public async Task A_successful_sign_in_issues_tokens_records_the_login_and_audits_it()
    {
        var (email, _) = await Client.RegisterAsync();
        var userId = await GetUserIdAsync(email);

        var response = await LoginAsync(email, TestData.ValidPassword);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokens = await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
        Assert.NotNull(await GetUserAsync(email, u => u.LastLoginAt));

        var audit = await SingleAuditAsync(AuditAction.LoginSucceeded, a => a.TargetUserId == userId);
        Assert.Equal(userId, audit.ActorUserId);
        Assert.Equal(email, audit.ActorEmail);
        Assert.True(audit.Succeeded);
    }

    [Fact]
    public async Task An_unconfirmed_address_signs_in_when_confirmation_is_not_required()
    {
        // The test host runs with Auth:RequireConfirmedEmail=false, the zero-config default
        // for a deployment that cannot send email.
        var (email, _) = await Client.RegisterAsync();
        await UpdateUserAsync(email, user => user.EmailConfirmed = false);

        var response = await LoginAsync(email, TestData.ValidPassword);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private Task<HttpResponseMessage> LoginAsync(string email, string password) =>
        Client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });

    internal static async Task AssertGenericFailureAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(["error"], body.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(GenericFailure, body.RootElement.GetProperty("error").GetString());
    }

    internal static string? Reason(AuditEvent audit)
    {
        using var metadata = JsonDocument.Parse(audit.Metadata!);
        return metadata.RootElement.TryGetProperty("reason", out var reason) ? reason.GetString() : null;
    }

    private Task UpdateUserAsync(string email, Action<ApplicationUser> change) =>
        Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            change(user!);
            await userManager.UpdateAsync(user!);
        });

    private async Task<string> GetUserIdAsync(string email) => (await GetUserAsync(email, u => u.Id))!;

    private async Task<T?> GetUserAsync<T>(string email, Func<ApplicationUser, T> select)
    {
        T? value = default;
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var user = await context.Users.AsNoTracking().IgnoreQueryFilters()
                .SingleAsync(u => u.NormalizedEmail == email.ToUpperInvariant());
            value = select(user);
        });
        return value;
    }

    private async Task<List<AuditEvent>> AuditRowsAsync(string action, Func<AuditEvent, bool> predicate)
    {
        var rows = new List<AuditEvent>();
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            rows = (await context.AuditEvents.AsNoTracking().Where(a => a.Action == action).ToListAsync())
                .Where(predicate).ToList();
        });
        return rows;
    }

    private async Task<AuditEvent> SingleAuditAsync(string action, Func<AuditEvent, bool> predicate) =>
        Assert.Single(await AuditRowsAsync(action, predicate));

    private async Task<List<RefreshToken>> RefreshTokensAsync(string userId)
    {
        var rows = new List<RefreshToken>();
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            rows = await context.RefreshTokens.AsNoTracking().Where(t => t.UserId == userId).ToListAsync();
        });
        return rows;
    }
}

/// <summary>
/// The same decision in a deployment that enforces email confirmation. Identity's own
/// pre-sign-in check refuses the unconfirmed account before the password is looked at, so
/// the caller sees the generic failure rather than a distinct "unverified" answer, and the
/// attempt does not count toward lockout.
/// </summary>
public class SignInWithConfirmationRequiredCharacterizationTests : IAsyncLifetime
{
    private ConfirmationRequiredFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new ConfirmationRequiredFactory();
        await _factory.InitializeAsync();
        _client = _factory.CreateClient();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task An_unconfirmed_address_gets_the_generic_failure_without_a_lockout_strike()
    {
        var (email, _) = await RegisterConfirmedAsync();
        await _factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            user!.EmailConfirmed = false;
            await userManager.UpdateAsync(user);
        });

        var response = await _client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestData.ValidPassword });

        await SignInCharacterizationTests.AssertGenericFailureAsync(response);
        await _factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var user = await context.Users.AsNoTracking().SingleAsync(u => u.NormalizedEmail == email.ToUpperInvariant());
            Assert.Equal(0, user.AccessFailedCount);

            var audit = Assert.Single(await context.AuditEvents.AsNoTracking()
                .Where(a => a.Action == AuditAction.LoginFailed && a.TargetUserId == user.Id).ToListAsync());
            Assert.Equal("invalid_password", SignInCharacterizationTests.Reason(audit));
        });
    }

    [Fact]
    public async Task A_confirmed_address_signs_in()
    {
        var (email, _) = await RegisterConfirmedAsync();

        var response = await _client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestData.ValidPassword });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>Registration answers 202 here, so the account is confirmed directly.</summary>
    private async Task<(string Email, HttpResponseMessage Response)> RegisterConfirmedAsync()
    {
        var email = TestData.NewEmail();
        var response = await _client.PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = TestData.ValidPassword,
            acceptedTermsVersion = TestData.TermsVersion,
            acceptedPrivacyVersion = TestData.PrivacyVersion
        });
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        await _factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            user!.EmailConfirmed = true;
            await userManager.UpdateAsync(user);
        });

        return (email, response);
    }

    /// <summary>
    /// Both switches production derives from one setting, turned on together: Identity's
    /// sign-in option and the controller's own. Overridden in services rather than through
    /// the process-wide environment the base factory uses, which other test classes share.
    /// </summary>
    private sealed class ConfirmationRequiredFactory : AuthServiceFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
            {
                services.Configure<IdentityOptions>(o => o.SignIn.RequireConfirmedEmail = true);
                services.Configure<AuthOptions>(o => o.RequireConfirmedEmail = true);
            });
        }
    }
}
