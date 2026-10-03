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
/// Two-factor from enrolment to sign-in, with real authenticator codes: the paths the earlier
/// tests could not reach because Identity validates a code but cannot produce one.
/// </summary>
public class TwoFactorFlowTests : IntegrationTestBase
{
    private sealed record Enrolled(TestAccount Account, string SharedKey, List<string> RecoveryCodes);

    /// <summary>Walks enrolment the way a user does: start, read the key, confirm with a code.</summary>
    private async Task<Enrolled> EnrolAsync()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);

        var setup = await (await client.PostAsync("/api/v1/auth/2fa/enable", null)).Content.ReadFromJsonAsync<JsonElement>();
        var key = setup.GetProperty("sharedKey").GetString()!;

        var confirmed = await client.PostAsJsonAsync("/api/v1/auth/2fa/verify", new { code = Totp.Code(key) });
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);

        var codes = (await confirmed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("recoveryCodes")
            .EnumerateArray().Select(c => c.GetString()!).ToList();

        return new Enrolled(account, key, codes);
    }

    private async Task<string> ChallengeAsync(Enrolled enrolled)
    {
        var response = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/login",
            new { email = enrolled.Account.Email, password = TestData.ValidPassword });

        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("challengeToken").GetString()!;
    }

    private Task<HttpResponseMessage> CompleteAsync(string challenge, string? code = null, string? recoveryCode = null) =>
        Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/2fa/login", new { challengeToken = challenge, code, recoveryCode });

    private async Task<List<AuditEvent>> AuditAsync(string action, string userId)
    {
        List<AuditEvent> rows = [];
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            rows = await context.AuditEvents.AsNoTracking()
                .Where(a => a.Action == action && (a.TargetUserId == userId || a.ActorUserId == userId)).ToListAsync();
        });
        return rows;
    }

    // ─── Enrolment ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Confirming_enrolment_with_a_real_code_turns_two_factor_on_and_hands_out_recovery_codes()
    {
        var enrolled = await EnrolAsync();

        Assert.Equal(10, enrolled.RecoveryCodes.Count);
        Assert.Equal(enrolled.RecoveryCodes.Count, enrolled.RecoveryCodes.Distinct().Count());
        Assert.True(await Factory.ReadUserAsync(enrolled.Account.Email, u => u.TwoFactorEnabled));
        Assert.Single(await AuditAsync(AuditAction.TwoFactorEnabled, enrolled.Account.Id));
    }

    [Fact]
    public async Task Enrolment_cannot_be_started_or_confirmed_again_while_it_is_on()
    {
        var enrolled = await EnrolAsync();
        var client = Factory.ClientFor(enrolled.Account.Tokens);

        var start = await client.PostAsync("/api/v1/auth/2fa/enable", null);
        var confirm = await client.PostAsJsonAsync("/api/v1/auth/2fa/verify", new { code = Totp.Code(enrolled.SharedKey) });

        Assert.Equal(HttpStatusCode.BadRequest, start.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, confirm.StatusCode);
    }

    [Fact]
    public async Task Restarting_enrolment_issues_a_new_key_so_an_abandoned_setup_leaves_nothing_usable()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);
        string KeyOf(JsonElement setup) => setup.GetProperty("sharedKey").GetString()!;

        var first = KeyOf(await (await client.PostAsync("/api/v1/auth/2fa/enable", null)).Content.ReadFromJsonAsync<JsonElement>());
        var second = KeyOf(await (await client.PostAsync("/api/v1/auth/2fa/enable", null)).Content.ReadFromJsonAsync<JsonElement>());
        var withOldKey = await client.PostAsJsonAsync("/api/v1/auth/2fa/verify", new { code = Totp.Code(first) });

        Assert.NotEqual(first, second);
        Assert.Equal(HttpStatusCode.BadRequest, withOldKey.StatusCode);
        Assert.False(await Factory.ReadUserAsync(account.Email, u => u.TwoFactorEnabled));
    }

    [Theory]
    [InlineData("POST", "/api/v1/auth/2fa/enable")]
    [InlineData("POST", "/api/v1/auth/2fa/verify")]
    [InlineData("POST", "/api/v1/auth/2fa/recovery-codes")]
    [InlineData("POST", "/api/v1/auth/2fa/disable")]
    public async Task Managing_two_factor_requires_a_signed_in_user(string method, string url)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), url)
        {
            Content = JsonContent.Create(new { code = "123456", password = "x" })
        };

        var response = await Factory.ClientFor().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ─── Signing in ──────────────────────────────────────────────────────────

    [Fact]
    public async Task A_current_code_completes_the_challenge_and_signs_in()
    {
        var enrolled = await EnrolAsync();
        var challenge = await ChallengeAsync(enrolled);

        var response = await CompleteAsync(challenge, Totp.Code(enrolled.SharedKey));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokens = (await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;
        var me = await Factory.ClientFor(tokens).GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.NotNull(await Factory.ReadUserAsync(enrolled.Account.Email, u => u.LastLoginAt));
        var row = Assert.Single(await AuditAsync(AuditAction.LoginSucceeded, enrolled.Account.Id));
        Assert.Contains("totp", row.Metadata);
    }

    [Fact]
    public async Task A_code_pasted_with_spaces_or_dashes_is_accepted()
    {
        var enrolled = await EnrolAsync();
        var code = Totp.Code(enrolled.SharedKey);

        var spaced = await CompleteAsync(await ChallengeAsync(enrolled), $"{code[..3]} {code[3..]}");
        var dashed = await CompleteAsync(await ChallengeAsync(enrolled), $"{code[..3]}-{code[3..]}");

        Assert.Equal(HttpStatusCode.OK, spaced.StatusCode);
        Assert.Equal(HttpStatusCode.OK, dashed.StatusCode);
    }

    [Fact]
    public async Task A_recovery_code_signs_in_once_and_is_audited_with_how_many_remain()
    {
        var enrolled = await EnrolAsync();
        var recovery = enrolled.RecoveryCodes[0];

        var first = await CompleteAsync(await ChallengeAsync(enrolled), recoveryCode: recovery);
        var again = await CompleteAsync(await ChallengeAsync(enrolled), recoveryCode: recovery);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, again.StatusCode);
        var used = Assert.Single(await AuditAsync(AuditAction.TwoFactorRecoveryCodeUsed, enrolled.Account.Id));
        Assert.Contains("9", used.Metadata);
    }

    [Fact]
    public async Task Neither_a_code_nor_a_recovery_code_is_a_bad_request()
    {
        var enrolled = await EnrolAsync();

        var response = await CompleteAsync(await ChallengeAsync(enrolled));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Wrong_codes_count_toward_lockout_so_the_second_factor_cannot_be_guessed()
    {
        var enrolled = await EnrolAsync();
        var challenge = await ChallengeAsync(enrolled);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var wrong = await CompleteAsync(challenge, "000000");
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        // Now locked: even the right code is refused.
        var right = await CompleteAsync(challenge, Totp.Code(enrolled.SharedKey));
        Assert.Equal(HttpStatusCode.Unauthorized, right.StatusCode);
        Assert.True(await Factory.ReadUserAsync(enrolled.Account.Email, u => u.LockoutEnd > DateTimeOffset.UtcNow));
        Assert.Equal(5, (await AuditAsync(AuditAction.TwoFactorChallengeFailed, enrolled.Account.Id)).Count);
    }

    [Fact]
    public async Task A_wrong_recovery_code_is_refused_and_counted()
    {
        var enrolled = await EnrolAsync();

        var response = await CompleteAsync(await ChallengeAsync(enrolled), recoveryCode: "AAAAA-AAAAA");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(1, await Factory.ReadUserAsync(enrolled.Account.Email, u => u.AccessFailedCount));
    }

    [Fact]
    public async Task A_challenge_cannot_outlive_the_account_it_was_issued_for()
    {
        var enrolled = await EnrolAsync();
        var challenge = await ChallengeAsync(enrolled);
        await Factory.UpdateUserAsync(enrolled.Account.Email, u => u.IsDeleted = true);

        var response = await CompleteAsync(challenge, Totp.Code(enrolled.SharedKey));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_challenge_cannot_be_completed_once_the_account_has_been_locked()
    {
        var enrolled = await EnrolAsync();
        var challenge = await ChallengeAsync(enrolled);
        await Factory.UpdateUserAsync(enrolled.Account.Email, u => u.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1));

        var response = await CompleteAsync(challenge, Totp.Code(enrolled.SharedKey));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_challenge_stops_working_if_two_factor_was_turned_off_meanwhile()
    {
        var enrolled = await EnrolAsync();
        var challenge = await ChallengeAsync(enrolled);
        await Factory.UpdateUserAsync(enrolled.Account.Email, u => u.TwoFactorEnabled = false);

        var response = await CompleteAsync(challenge, Totp.Code(enrolled.SharedKey));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ─── Recovery codes ──────────────────────────────────────────────────────

    [Fact]
    public async Task Regenerating_recovery_codes_retires_the_old_set()
    {
        var enrolled = await EnrolAsync();
        var client = Factory.ClientFor(enrolled.Account.Tokens);

        var response = await client.PostAsync("/api/v1/auth/2fa/recovery-codes", null);
        var fresh = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("recoveryCodes")
            .EnumerateArray().Select(c => c.GetString()!).ToList();

        Assert.Equal(10, fresh.Count);
        Assert.Empty(fresh.Intersect(enrolled.RecoveryCodes));
        var old = await CompleteAsync(await ChallengeAsync(enrolled), recoveryCode: enrolled.RecoveryCodes[0]);
        var current = await CompleteAsync(await ChallengeAsync(enrolled), recoveryCode: fresh[0]);
        Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
        Assert.Equal(HttpStatusCode.OK, current.StatusCode);
    }

    [Fact]
    public async Task Recovery_codes_exist_only_while_two_factor_is_on()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PostAsync("/api/v1/auth/2fa/recovery-codes", null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ─── Turning it off ──────────────────────────────────────────────────────

    [Fact]
    public async Task Disabling_needs_the_password_and_a_live_code_and_ends_every_session()
    {
        var enrolled = await EnrolAsync();
        var client = Factory.ClientFor(enrolled.Account.Tokens);

        var wrongPassword = await client.PostAsJsonAsync("/api/v1/auth/2fa/disable",
            new { password = "Wr0ng-password!", code = Totp.Code(enrolled.SharedKey) });
        var wrongCode = await client.PostAsJsonAsync("/api/v1/auth/2fa/disable",
            new { password = TestData.ValidPassword, code = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, wrongCode.StatusCode);
        Assert.True(await Factory.ReadUserAsync(enrolled.Account.Email, u => u.TwoFactorEnabled));

        var disabled = await client.PostAsJsonAsync("/api/v1/auth/2fa/disable",
            new { password = TestData.ValidPassword, code = Totp.Code(enrolled.SharedKey) });

        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        Assert.False(await Factory.ReadUserAsync(enrolled.Account.Email, u => u.TwoFactorEnabled));
        var refresh = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/refresh",
            new { refreshToken = enrolled.Account.Tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
        Assert.Single(await AuditAsync(AuditAction.TwoFactorDisabled, enrolled.Account.Id));
    }

    [Fact]
    public async Task Disabling_gives_a_new_authenticator_key_so_the_old_device_is_worthless()
    {
        var enrolled = await EnrolAsync();
        var client = Factory.ClientFor(enrolled.Account.Tokens);
        await client.PostAsJsonAsync("/api/v1/auth/2fa/disable",
            new { password = TestData.ValidPassword, code = Totp.Code(enrolled.SharedKey) });
        var again = Factory.ClientFor(await Factory.ClientFor().LoginAsync(enrolled.Account.Email));

        var restart = await (await again.PostAsync("/api/v1/auth/2fa/enable", null)).Content.ReadFromJsonAsync<JsonElement>();

        Assert.NotEqual(enrolled.SharedKey, restart.GetProperty("sharedKey").GetString());
    }

    [Fact]
    public async Task A_recovery_code_can_stand_in_for_the_authenticator_when_disabling()
    {
        var enrolled = await EnrolAsync();

        var response = await Factory.ClientFor(enrolled.Account.Tokens).PostAsJsonAsync("/api/v1/auth/2fa/disable",
            new { password = TestData.ValidPassword, code = enrolled.RecoveryCodes[0] });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(await Factory.ReadUserAsync(enrolled.Account.Email, u => u.TwoFactorEnabled));
    }

    [Fact]
    public async Task Disabling_when_it_is_off_is_a_bad_request()
    {
        var account = await Factory.CreateAccountAsync();

        var response = await Factory.ClientFor(account.Tokens).PostAsJsonAsync("/api/v1/auth/2fa/disable",
            new { password = TestData.ValidPassword, code = "123456" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task An_account_with_no_password_can_disable_with_a_code_alone()
    {
        var enrolled = await EnrolAsync();
        await Factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            await users.RemovePasswordAsync((await users.FindByEmailAsync(enrolled.Account.Email))!);
        });

        var response = await Factory.ClientFor(enrolled.Account.Tokens).PostAsJsonAsync("/api/v1/auth/2fa/disable",
            new { password = "unused", code = Totp.Code(enrolled.SharedKey) });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
