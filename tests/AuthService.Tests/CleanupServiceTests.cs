using System.Net.Http.Json;
using AuthService.Data;
using AuthService.Extensions;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The account reaper: a deleted account is kept for its retention period and then removed for
/// good with what belongs to it. The steps are run directly rather than waited for on the hourly loop.
/// </summary>
public class AccountCleanupTests : IntegrationTestBase
{
    private UserCleanupService NewReaper() => ActivatorUtilities.CreateInstance<UserCleanupService>(Factory.Services);

    private Task ScheduleDeletionAsync(string email, DateTime? at) =>
        Factory.UpdateUserAsync(email, u =>
        {
            u.IsDeleted = true;
            u.DeletedAt = DateTime.UtcNow.AddDays(-31);
            u.ScheduledPermanentDeletionAt = at;
        });

    private async Task<bool> ExistsAsync(string email)
    {
        var exists = false;
        await Factory.WithScopeAsync(async services =>
            exists = await services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email) is not null);

        return exists;
    }

    private async Task<T> QueryAsync<T>(Func<ApplicationDbContext, Task<T>> query)
    {
        T result = default!;
        await Factory.WithScopeAsync(async services => result = await query(services.GetRequiredService<ApplicationDbContext>()));

        return result;
    }

    [Fact]
    public async Task An_account_past_its_retention_period_is_deleted_for_good()
    {
        var account = await Factory.CreateAccountAsync();
        await ScheduleDeletionAsync(account.Email, DateTime.UtcNow.AddMinutes(-1));

        await NewReaper().CleanupExpiredUsersAsync(CancellationToken.None);

        Assert.False(await ExistsAsync(account.Email));
    }

    [Fact]
    public async Task Accounts_that_are_live_or_still_inside_their_retention_period_are_kept()
    {
        var live = await Factory.CreateAccountAsync();
        var waiting = await Factory.CreateAccountAsync();
        var unscheduled = await Factory.CreateAccountAsync();
        var restored = await Factory.CreateAccountAsync();
        await ScheduleDeletionAsync(waiting.Email, DateTime.UtcNow.AddDays(3));
        await ScheduleDeletionAsync(unscheduled.Email, null);
        // A schedule left behind on an account that was restored must not take it.
        await Factory.UpdateUserAsync(restored.Email, u =>
        {
            u.IsDeleted = false;
            u.ScheduledPermanentDeletionAt = DateTime.UtcNow.AddMinutes(-1);
        });

        await NewReaper().CleanupExpiredUsersAsync(CancellationToken.None);

        Assert.True(await ExistsAsync(live.Email));
        Assert.True(await ExistsAsync(waiting.Email));
        Assert.True(await ExistsAsync(unscheduled.Email));
        Assert.True(await ExistsAsync(restored.Email));
    }

    [Fact]
    public async Task What_belongs_to_the_account_goes_with_it_and_the_audit_trail_stays()
    {
        var leaving = await Factory.CreateAccountAsync();
        var staying = await Factory.CreateAccountAsync();
        var organization = await Factory.ClientFor(staying.Tokens).CreateOrganizationAsync();
        await Factory.AddMemberAsync(organization, leaving.Id, OrganizationRole.Member);
        await Factory.ClientFor().LoginAsync(leaving.Email);
        Assert.True(await QueryAsync(c => c.RefreshTokens.CountAsync(t => t.UserId == leaving.Id)) >= 2);
        Assert.Equal(2, await QueryAsync(c => c.UserConsents.CountAsync(x => x.UserId == leaving.Id)));
        var auditBefore = await QueryAsync(c => c.AuditEvents.CountAsync(a => a.ActorUserId == leaving.Id || a.TargetUserId == leaving.Id));
        Assert.True(auditBefore > 0);
        await ScheduleDeletionAsync(leaving.Email, DateTime.UtcNow.AddMinutes(-1));

        await NewReaper().CleanupExpiredUsersAsync(CancellationToken.None);

        Assert.Equal(0, await QueryAsync(c => c.RefreshTokens.CountAsync(t => t.UserId == leaving.Id)));
        Assert.Equal(0, await QueryAsync(c => c.UserConsents.CountAsync(x => x.UserId == leaving.Id)));
        Assert.Null(await Factory.RoleInAsync(organization, leaving.Id));
        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(organization, staying.Id));
        Assert.True(await QueryAsync(c => c.AuditEvents.CountAsync(a => a.ActorUserId == leaving.Id || a.TargetUserId == leaving.Id)) >= auditBefore);
        Assert.True(await ExistsAsync(staying.Email));
    }

    [Fact]
    public async Task One_account_that_cannot_be_deleted_does_not_hold_up_the_rest()
    {
        var stuck = await Factory.CreateAccountAsync();
        var other = await Factory.CreateAccountAsync();
        await ScheduleDeletionAsync(stuck.Email, DateTime.UtcNow.AddDays(-2));
        await ScheduleDeletionAsync(other.Email, DateTime.UtcNow.AddMinutes(-1));
        await Factory.MakeUndeletableAsync("AspNetUsers", stuck.Id);

        await NewReaper().CleanupExpiredUsersAsync(CancellationToken.None);

        Assert.True(await ExistsAsync(stuck.Email));
        Assert.False(await ExistsAsync(other.Email));
    }

    [Fact]
    public async Task The_service_runs_a_pass_as_soon_as_it_starts_and_stops_when_asked()
    {
        var account = await Factory.CreateAccountAsync();
        await ScheduleDeletionAsync(account.Email, DateTime.UtcNow.AddMinutes(-1));
        var log = new ListLogger<UserCleanupService>();
        using var reaper = new UserCleanupService(
            Factory.Services.GetRequiredService<IServiceScopeFactory>(), log, Factory.Services.GetRequiredService<IMigrationCompletionSignal>());

        await reaper.StartAsync(CancellationToken.None);
        // Waits on its log, not on the database: the in-memory test database is one connection,
        // and the service and this thread must not use it at the same time.
        await TestWait.UntilAsync(() => Task.FromResult(log.Messages.Any(m => m.Contains("Permanently deleted user account"))),
            "the first pass has deleted the account");
        await reaper.StopAsync(CancellationToken.None);

        Assert.False(await ExistsAsync(account.Email));
        Assert.True(reaper.ExecuteTask!.IsCompleted);
    }

    [Fact]
    public async Task Interactions_an_hour_past_their_expiry_are_pruned_and_fresher_ones_are_kept()
    {
        AuthorizationInteraction Interaction(string name, TimeSpan expiresIn) => new()
        {
            HandleHash = TokenHasher.Hash($"{name}-{Guid.NewGuid()}"),
            BrowserBindingHash = TokenHasher.Hash("binding"),
            ClientId = "claude-test",
            RequestQuery = "?client_id=claude-test",
            Scopes = "mcp",
            Resource = "https://mcp.example.test",
            CreatedAt = DateTime.UtcNow.AddHours(-3),
            ExpiresAt = DateTime.UtcNow + expiresIn
        };

        var stale = Interaction("stale", TimeSpan.FromHours(-2));
        var justExpired = Interaction("just-expired", TimeSpan.FromMinutes(-10));
        var live = Interaction("live", TimeSpan.FromMinutes(5));
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            context.AuthorizationInteractions.AddRange(stale, justExpired, live);
            await context.SaveChangesAsync();
        });

        await NewReaper().PruneAuthorizationServerAsync(CancellationToken.None);

        var kept = await QueryAsync(c => c.AuthorizationInteractions.Select(i => i.Id).ToListAsync());
        Assert.Equal(new[] { justExpired.Id, live.Id }.Order(), kept.Order());
    }
}

/// <summary>
/// The organization reaper: a deleted organization is kept for its retention period and then
/// removed for good with its members and invitations, while the people themselves stay.
/// </summary>
public class OrganizationCleanupTests : IntegrationTestBase
{
    private OrganizationCleanupService NewReaper() =>
        ActivatorUtilities.CreateInstance<OrganizationCleanupService>(Factory.Services);

    private Task ScheduleDeletionAsync(string organizationId, bool deleted, DateTime? at) =>
        Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var organization = await context.Organizations.IgnoreQueryFilters().SingleAsync(o => o.Id == organizationId);
            organization.IsDeleted = deleted;
            organization.DeletedAt = deleted ? DateTime.UtcNow.AddDays(-31) : null;
            organization.ScheduledPermanentDeletionAt = at;
            await context.SaveChangesAsync();
        });

    [Fact]
    public async Task An_organization_past_its_retention_period_is_deleted_for_good_with_its_members_and_invitations()
    {
        var team = await Factory.CreateTeamAsync();
        (await team.As(Who.Owner).PostAsJsonAsync(team.Url("/invite"), new { email = TestData.NewEmail("invitee") }))
            .EnsureSuccessStatusCode();
        await ScheduleDeletionAsync(team.Id, deleted: true, DateTime.UtcNow.AddMinutes(-1));

        await NewReaper().CleanupExpiredOrganizationsAsync(CancellationToken.None);

        Assert.Null(await Factory.StoredOrganizationAsync(team.Id));
        Assert.Empty(await Factory.StoredInvitationsAsync(team.Id));
        foreach (var who in new[] { Who.Owner, Who.Admin, Who.Member })
            Assert.Null(await Factory.RoleInAsync(team.Id, team[who].Id));
        await Factory.ClientFor().LoginAsync(team.Owner.Email);
    }

    [Fact]
    public async Task Organizations_that_are_live_or_still_inside_their_retention_period_are_kept()
    {
        var live = await Factory.CreateTeamAsync("Live");
        var waiting = await Factory.CreateTeamAsync("Waiting");
        var unscheduled = await Factory.CreateTeamAsync("Unscheduled");
        await ScheduleDeletionAsync(waiting.Id, deleted: true, DateTime.UtcNow.AddDays(3));
        await ScheduleDeletionAsync(unscheduled.Id, deleted: true, null);
        // A schedule left behind on an organization that was restored must not take it.
        await ScheduleDeletionAsync(live.Id, deleted: false, DateTime.UtcNow.AddMinutes(-1));

        await NewReaper().CleanupExpiredOrganizationsAsync(CancellationToken.None);

        Assert.NotNull(await Factory.StoredOrganizationAsync(live.Id));
        Assert.NotNull(await Factory.StoredOrganizationAsync(waiting.Id));
        Assert.NotNull(await Factory.StoredOrganizationAsync(unscheduled.Id));
    }

    [Fact]
    public async Task One_organization_that_cannot_be_deleted_does_not_hold_up_the_rest()
    {
        var owner = Factory.ClientFor((await Factory.CreateAccountAsync()).Tokens);
        var stuck = await owner.CreateOrganizationAsync("Stuck");
        var other = await owner.CreateOrganizationAsync("Other");
        await ScheduleDeletionAsync(stuck, deleted: true, DateTime.UtcNow.AddDays(-2));
        await ScheduleDeletionAsync(other, deleted: true, DateTime.UtcNow.AddMinutes(-1));
        await Factory.MakeUndeletableAsync("Organizations", stuck);

        await NewReaper().CleanupExpiredOrganizationsAsync(CancellationToken.None);

        Assert.NotNull(await Factory.StoredOrganizationAsync(stuck));
        Assert.Null(await Factory.StoredOrganizationAsync(other));
    }

    [Fact]
    public async Task The_service_runs_a_pass_as_soon_as_it_starts_and_stops_when_asked()
    {
        var team = await Factory.CreateTeamAsync();
        await ScheduleDeletionAsync(team.Id, deleted: true, DateTime.UtcNow.AddMinutes(-1));
        var log = new ListLogger<OrganizationCleanupService>();
        using var reaper = new OrganizationCleanupService(
            Factory.Services.GetRequiredService<IServiceScopeFactory>(), log, Factory.Services.GetRequiredService<IMigrationCompletionSignal>());

        await reaper.StartAsync(CancellationToken.None);
        // Waits on its log, not on the database: the in-memory test database is one connection,
        // and the service and this thread must not use it at the same time.
        await TestWait.UntilAsync(() => Task.FromResult(log.Messages.Any(m => m.Contains("Permanently deleted organization"))),
            "the first pass has deleted the organization");
        await reaper.StopAsync(CancellationToken.None);

        Assert.Null(await Factory.StoredOrganizationAsync(team.Id));
        Assert.True(reaper.ExecuteTask!.IsCompleted);
    }
}
