using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Data;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>What a signed-in user can read and change about their own account.</summary>
public class AccountSelfServiceTests : IntegrationTestBase
{
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

    /// <summary>An account created the way a social sign-in does: no password, one provider login.</summary>
    private async Task<TestAccount> NewSocialAccountAsync()
    {
        var email = TestData.NewEmail("social");
        await Factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = new ApplicationUser { UserName = $"social-{Guid.NewGuid():N}"[..20], Email = email, EmailConfirmed = true };
            (await users.CreateAsync(user)).ThrowIfFailed();
            (await users.AddLoginAsync(user, new UserLoginInfo("GitHub", "gh-12345", "GitHub"))).ThrowIfFailed();
        });

        // Tokens come from the service's own token service: there is no password to log in with.
        TestTokens? tokens = null;
        await Factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var issued = await services.GetRequiredService<ITokenService>().GenerateTokensAsync((await users.FindByEmailAsync(email))!);
            tokens = new TestTokens(issued.AccessToken, issued.RefreshToken, issued.ExpiresIn);
        });

        return new TestAccount(email, await Factory.UserIdAsync(email), tokens!);
    }

    // ─── Profile ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_user_can_rename_themselves_and_set_a_profile_image()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PutAsJsonAsync("/api/v1/auth/profile",
            new { userName = "new_name-1", profileImageUrl = "https://img.example.test/me.png" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("new_name-1", await Factory.ReadUserAsync(account.Email, u => u.UserName));
        Assert.Equal("https://img.example.test/me.png", await Factory.ReadUserAsync(account.Email, u => u.ProfileImageUrl));
    }

    [Fact]
    public async Task Fields_that_are_left_out_are_left_alone()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);
        var before = await Factory.ReadUserAsync(account.Email, u => u.UserName);
        await client.PutAsJsonAsync("/api/v1/auth/profile", new { profileImageUrl = "https://img.example.test/me.png" });

        var response = await client.PutAsJsonAsync("/api/v1/auth/profile", new { userName = "" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before, await Factory.ReadUserAsync(account.Email, u => u.UserName));
        Assert.Equal("https://img.example.test/me.png", await Factory.ReadUserAsync(account.Email, u => u.ProfileImageUrl));
    }

    [Fact]
    public async Task A_name_someone_else_has_is_refused()
    {
        var taken = await Factory.CreateAccountAsync();
        var account = await Factory.CreateAccountAsync();
        var takenName = (await Factory.ReadUserAsync(taken.Email, u => u.UserName))!;

        var response = await Factory.ClientFor(account.Tokens).PutAsJsonAsync("/api/v1/auth/profile", new { userName = takenName });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True((await response.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("errors", out _));
        Assert.NotEqual(takenName, await Factory.ReadUserAsync(account.Email, u => u.UserName));
    }

    [Theory]
    [InlineData("has spaces")]
    [InlineData("semi;colon")]
    [InlineData("<script>")]
    public async Task A_name_with_characters_outside_the_allowed_set_is_refused(string userName)
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PutAsJsonAsync("/api/v1/auth/profile", new { userName });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("not a url")]
    [InlineData("data:text/html;base64,PHNjcmlwdD4=")]
    public async Task A_profile_image_that_is_not_a_web_address_is_refused(string profileImageUrl)
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PutAsJsonAsync("/api/v1/auth/profile", new { profileImageUrl });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(await Factory.ReadUserAsync(account.Email, u => u.ProfileImageUrl));
    }

    [Fact]
    public async Task A_profile_image_address_over_the_limit_is_refused()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PutAsJsonAsync("/api/v1/auth/profile",
            new { profileImageUrl = $"https://img.example.test/{new string('a', 500)}" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Updating_a_profile_needs_a_signed_in_user()
    {
        var response = await Factory.ClientFor().PutAsJsonAsync("/api/v1/auth/profile", new { userName = "someone" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ─── Me ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Me_lists_the_organizations_the_user_belongs_to_with_their_role_in_each()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);
        (await client.PostAsJsonAsync("/api/v1/organizations", new { name = "Acme" })).EnsureSuccessStatusCode();
        (await client.PostAsJsonAsync("/api/v1/organizations", new { name = "Globex" })).EnsureSuccessStatusCode();

        var me = (await (await client.GetAsync("/api/v1/auth/me")).Content.ReadFromJsonAsync<UserInfoResponse>(TestData.Json))!;

        Assert.Equal(account.Id, me.Id);
        Assert.Equal(account.Email, me.Email);
        Assert.Equal(new[] { "Acme", "Globex" }, me.Organizations.Select(o => o.Name).Order());
        Assert.All(me.Organizations, o => Assert.Equal("Owner", o.Role));
    }

    [Fact]
    public async Task Me_says_when_the_user_has_to_accept_new_terms()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);
        var accepted = (await (await client.GetAsync("/api/v1/auth/me")).Content.ReadFromJsonAsync<UserInfoResponse>(TestData.Json))!;
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            foreach (var row in context.UserConsents.Where(c => c.UserId == account.Id))
                row.Version = "2020-01-01";
            await context.SaveChangesAsync();
        });

        var stale = (await (await client.GetAsync("/api/v1/auth/me")).Content.ReadFromJsonAsync<UserInfoResponse>(TestData.Json))!;

        Assert.False(accepted.RequiresConsent);
        Assert.True(stale.RequiresConsent);
    }

    // ─── Deleting the account ────────────────────────────────────────────────

    [Fact]
    public async Task Deleting_an_account_needs_the_current_password()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);

        var missing = await client.SendAsync(Delete(new { confirmation = "DELETE" }));
        var wrong = await client.SendAsync(Delete(new { confirmation = "DELETE", password = "Wr0ng-password!" }));

        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.False(await Factory.ReadUserAsync(account.Email, u => u.IsDeleted));
    }

    [Theory]
    [InlineData("delete")]
    [InlineData("")]
    [InlineData("DELETE ME")]
    public async Task Deleting_an_account_needs_the_confirmation_word_exactly(string confirmation)
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens)
            .SendAsync(Delete(new { confirmation, password = TestData.ValidPassword }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await Factory.ReadUserAsync(account.Email, u => u.IsDeleted));
    }

    [Fact]
    public async Task A_deleted_account_is_soft_deleted_signed_out_and_audited()
    {
        var account = await Factory.CreateAccountAsync();
        var before = DateTime.UtcNow;

        var response = await Factory.ClientFor(account.Tokens)
            .SendAsync(Delete(new { confirmation = "DELETE", password = TestData.ValidPassword }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await Factory.ReadUserAsync(account.Email, u => u.IsDeleted));
        var scheduled = await Factory.ReadUserAsync(account.Email, u => u.ScheduledPermanentDeletionAt);
        Assert.InRange(scheduled!.Value, before.AddDays(ApplicationUser.DefaultRetentionDays).AddMinutes(-1),
            DateTime.UtcNow.AddDays(ApplicationUser.DefaultRetentionDays).AddMinutes(1));
        var anonymous = Factory.ClientFor();
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = account.Tokens.RefreshToken })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.PostAsJsonAsync("/api/v1/auth/login", new { email = account.Email, password = TestData.ValidPassword })).StatusCode);
        Assert.Equal(1, await AuditCountAsync(AuditAction.AccountSoftDeleted, account.Id));
    }

    [Fact]
    public async Task An_account_with_no_password_can_be_deleted_by_confirming_alone()
    {
        var account = await NewSocialAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).SendAsync(Delete(new { confirmation = "DELETE" }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await Factory.ReadUserAsync(account.Email, u => u.IsDeleted));
    }

    [Fact]
    public async Task Deleting_an_account_needs_a_signed_in_user()
    {
        var response = await Factory.ClientFor().SendAsync(Delete(new { confirmation = "DELETE" }));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static HttpRequestMessage Delete(object body) =>
        new(HttpMethod.Delete, "/api/v1/auth/account") { Content = JsonContent.Create(body) };

    // ─── Export ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_export_names_social_logins_without_their_provider_keys_and_lists_organizations()
    {
        var account = await NewSocialAccountAsync();
        var client = Factory.ClientFor(account.Tokens);
        (await client.PostAsJsonAsync("/api/v1/organizations", new { name = "Acme" })).EnsureSuccessStatusCode();

        var response = await client.GetAsync("/api/v1/auth/export");
        var raw = await response.Content.ReadAsStringAsync();
        var export = JsonSerializer.Deserialize<UserDataExport>(raw, TestData.Json)!;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("GitHub", Assert.Single(export.ExternalLogins).Provider);
        Assert.DoesNotContain("gh-12345", raw);
        Assert.False(export.Profile.HasPassword);
        var org = Assert.Single(export.Organizations);
        Assert.Equal("Acme", org.Name);
        Assert.Equal("Owner", org.Role);
        Assert.Equal(1, await AuditCountAsync(AuditAction.DataExported, account.Id));
    }

    [Fact]
    public async Task The_export_is_offered_as_a_download()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).GetAsync("/api/v1/auth/export");

        Assert.Contains("authservice-export.json", response.Content.Headers.ContentDisposition?.ToString()
            ?? string.Join(' ', response.Headers.GetValues("Content-Disposition")));
    }
}

/// <summary>
/// Changing a password with the session options at their non-default settings. The default,
/// where other sessions end and the caller is handed fresh tokens, is in
/// <see cref="PasswordChangeTests"/>.
/// </summary>
public class PasswordChangeFailureTests : IntegrationTestBase
{
    [Fact]
    public async Task A_wrong_current_password_changes_nothing()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PostAsJsonAsync("/api/v1/auth/change-password",
            new { currentPassword = "Wr0ng-password!", newPassword = "Chang3d-Passw0rd!" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await Factory.ClientFor().LoginAsync(account.Email);
        var refresh = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = account.Tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    [Fact]
    public async Task A_new_password_that_breaks_the_policy_is_refused()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PostAsJsonAsync("/api/v1/auth/change-password",
            new { currentPassword = TestData.ValidPassword, newPassword = "alllowercase1!" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await Factory.ClientFor().LoginAsync(account.Email);
    }
}

/// <summary>Auth:RevokeSessionsOnPasswordChange off: the password changes and nothing is signed out.</summary>
public class PasswordChangeWithoutRevocationTests : IntegrationTestBase
{
    protected override void ConfigureServices(IServiceCollection services) =>
        services.Configure<AuthOptions>(o => o.RevokeSessionsOnPasswordChange = false);

    [Fact]
    public async Task Other_sessions_survive_and_no_new_tokens_are_issued()
    {
        var account = await Factory.CreateAccountAsync();
        var other = await Factory.ClientFor().LoginAsync(account.Email);

        var response = await Factory.ClientFor(account.Tokens).PostAsJsonAsync("/api/v1/auth/change-password",
            new { currentPassword = TestData.ValidPassword, newPassword = "Chang3d-Passw0rd!" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(body.GetProperty("sessionsRevoked").GetBoolean());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("tokens").ValueKind);
        var refresh = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = other.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }
}

/// <summary>Auth:ReissueTokensOnPasswordChange off: every session ends, the caller's included.</summary>
public class PasswordChangeWithoutReissueTests : IntegrationTestBase
{
    protected override void ConfigureServices(IServiceCollection services) =>
        services.Configure<AuthOptions>(o => o.ReissueTokensOnPasswordChange = false);

    [Fact]
    public async Task Every_session_ends_and_the_caller_is_told_to_sign_in_again()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PostAsJsonAsync("/api/v1/auth/change-password",
            new { currentPassword = TestData.ValidPassword, newPassword = "Chang3d-Passw0rd!" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("sessionsRevoked").GetBoolean());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("tokens").ValueKind);
        Assert.Contains("sign in again", body.GetProperty("message").GetString());
        var refresh = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = account.Tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }
}
