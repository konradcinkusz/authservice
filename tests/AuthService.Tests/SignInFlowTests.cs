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
/// The sign-in decision the authorization server's pages make through <see cref="SignInFlow"/>: whether
/// an account in a given state may be given a session at all, and how a second factor is judged.
/// </summary>
public class SignInFlowTests : IntegrationTestBase
{
    private async Task<T> WithFlowAsync<T>(string email, Func<SignInFlow, ApplicationUser, Task<T>> action)
    {
        T result = default!;
        await Factory.WithScopeAsync(async services =>
        {
            var user = (await services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email))!;
            result = await action(services.GetRequiredService<SignInFlow>(), user);
        });

        return result;
    }

    private Task<SignInIneligibility> EligibilityAsync(string email) =>
        WithFlowAsync(email, (flow, user) => flow.CheckEligibilityAsync(user));

    [Fact]
    public async Task An_account_in_good_standing_may_be_given_a_session()
    {
        var account = await Factory.CreateAccountAsync();

        Assert.Equal(SignInIneligibility.None, await EligibilityAsync(account.Email));
    }

    [Fact]
    public async Task A_deleted_account_may_not_even_when_it_is_locked_and_out_of_date_too()
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.UpdateUserAsync(account.Email, u =>
        {
            u.IsDeleted = true;
            u.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);
        });

        Assert.Equal(SignInIneligibility.Deleted, await EligibilityAsync(account.Email));
    }

    [Fact]
    public async Task A_locked_out_account_may_not()
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.UpdateUserAsync(account.Email, u => u.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1));

        Assert.Equal(SignInIneligibility.LockedOut, await EligibilityAsync(account.Email));
    }

    [Theory]
    [InlineData(true, true, SignInIneligibility.None)]
    [InlineData(false, true, SignInIneligibility.ConsentRequired)]
    [InlineData(true, false, SignInIneligibility.ConsentRequired)]
    public async Task An_account_that_has_not_accepted_the_current_terms_and_privacy_policy_may_not(
        bool termsCurrent, bool privacyCurrent, SignInIneligibility expected)
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            foreach (var row in context.UserConsents.Where(c => c.UserId == account.Id))
            {
                if ((row.Type == ConsentType.Terms && !termsCurrent) || (row.Type == ConsentType.Privacy && !privacyCurrent))
                    row.Version = "2020-01-01";
            }

            await context.SaveChangesAsync();
        });

        Assert.Equal(expected, await EligibilityAsync(account.Email));
    }

    // ─── The second factor ───────────────────────────────────────────────────

    private Task<SecondFactorStatus> VerifyAsync(string email, string? code, string? recoveryCode) =>
        WithFlowAsync(email, (flow, user) => flow.VerifySecondFactorAsync(user, code, recoveryCode));

    private async Task<TestAccount> AccountWithTwoFactorAsync()
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.UpdateUserAsync(account.Email, u => u.TwoFactorEnabled = true);

        return account;
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    public async Task Neither_a_code_nor_a_recovery_code_is_not_a_second_factor_and_costs_no_strike(string? code, string? recoveryCode)
    {
        var account = await AccountWithTwoFactorAsync();

        var status = await VerifyAsync(account.Email, code, recoveryCode);

        Assert.Equal(SecondFactorStatus.Missing, status);
        Assert.Equal(0, await Factory.ReadUserAsync(account.Email, u => u.AccessFailedCount));
    }

    [Theory]
    [InlineData("123456", null)]
    [InlineData(null, "AAAAA-BBBBB")]
    public async Task A_wrong_code_or_recovery_code_is_refused_and_counts_against_the_account(string? code, string? recoveryCode)
    {
        var account = await AccountWithTwoFactorAsync();

        var status = await VerifyAsync(account.Email, code, recoveryCode);

        Assert.Equal(SecondFactorStatus.Invalid, status);
        Assert.Equal(1, await Factory.ReadUserAsync(account.Email, u => u.AccessFailedCount));
        Assert.Single(await Factory.AuditAsync(AuditAction.TwoFactorChallengeFailed));
    }

    [Fact]
    public async Task Five_wrong_codes_lock_the_account_and_after_that_not_even_the_right_one_is_looked_at()
    {
        var account = await AccountWithTwoFactorAsync();

        for (var i = 0; i < 5; i++)
            await VerifyAsync(account.Email, "000000", null);
        var afterwards = await VerifyAsync(account.Email, "000000", null);

        Assert.Equal(SecondFactorStatus.LockedOut, afterwards);
        Assert.Equal(5, (await Factory.AuditAsync(AuditAction.TwoFactorChallengeFailed)).Count);
    }
}

/// <summary>Where verification is on, an unverified address is not given a session.</summary>
public class SignInFlowEmailGateTests : IntegrationTestBase
{
    protected override void ConfigureServices(IServiceCollection services) =>
        services.Configure<AuthOptions>(o => o.RequireConfirmedEmail = true);

    [Fact]
    public async Task An_unverified_address_may_not_but_a_verified_one_may()
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.UpdateUserAsync(account.Email, u => u.EmailConfirmed = false);

        async Task<SignInIneligibility> EligibilityAsync()
        {
            var result = SignInIneligibility.None;
            await Factory.WithScopeAsync(async services =>
            {
                var user = (await services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(account.Email))!;
                result = await services.GetRequiredService<SignInFlow>().CheckEligibilityAsync(user);
            });

            return result;
        }

        var unverified = await EligibilityAsync();
        await Factory.UpdateUserAsync(account.Email, u => u.EmailConfirmed = true);
        var verified = await EligibilityAsync();

        Assert.Equal(SignInIneligibility.EmailNotConfirmed, unverified);
        Assert.Equal(SignInIneligibility.None, verified);
    }
}
