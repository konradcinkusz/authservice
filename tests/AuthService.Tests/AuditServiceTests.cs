using System.Text.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The audit trail's own promises: detail is kept as JSON, an audit failure never fails the
/// operation being audited, and an enqueued row commits with the change it describes or not at all.
/// </summary>
public class AuditServiceTests : IntegrationTestBase
{
    /// <summary>Cannot be serialized, which is how a row fails to build.</summary>
    private sealed class Cyclic
    {
        public Cyclic Self => this;
    }

    private async Task<int> RowCountAsync(string action)
    {
        var count = 0;
        await Factory.WithScopeAsync(async services =>
            count = await services.GetRequiredService<ApplicationDbContext>().AuditEvents.CountAsync(a => a.Action == action));

        return count;
    }

    [Fact]
    public async Task Detail_is_stored_as_json_and_a_row_without_detail_stores_none()
    {
        await Factory.WithScopeAsync(async services =>
        {
            var audit = services.GetRequiredService<IAuditService>();
            await audit.LogAsync("test.with-detail", actorUserId: "a", actorEmail: "a@example.test", targetUserId: "t",
                targetOrganizationId: "o", succeeded: false, metadata: new { reason = "because", count = 3 });
            await audit.LogAsync("test.without-detail");
        });

        var with = Assert.Single(await Factory.AuditAsync("test.with-detail"));
        Assert.Equal(("a", "a@example.test", "t", "o", false), (with.ActorUserId, with.ActorEmail, with.TargetUserId, with.TargetOrganizationId, with.Succeeded));
        using var detail = JsonDocument.Parse(with.Metadata!);
        Assert.Equal("because", detail.RootElement.GetProperty("reason").GetString());
        Assert.Equal(3, detail.RootElement.GetProperty("count").GetInt32());
        var without = Assert.Single(await Factory.AuditAsync("test.without-detail"));
        Assert.Null(without.Metadata);
        Assert.True(without.Succeeded);
    }

    [Fact]
    public async Task A_row_written_outside_a_request_has_no_address_and_no_user_agent()
    {
        await Factory.WithScopeAsync(services => services.GetRequiredService<IAuditService>().LogAsync("test.background"));

        var row = Assert.Single(await Factory.AuditAsync("test.background"));
        Assert.Null(row.IpAddress);
        Assert.Null(row.UserAgent);
    }

    [Fact]
    public async Task A_row_that_cannot_be_built_is_dropped_without_failing_the_caller()
    {
        await Factory.WithScopeAsync(services =>
            services.GetRequiredService<IAuditService>().LogAsync("test.unbuildable", metadata: new Cyclic()));

        Assert.Equal(0, await RowCountAsync("test.unbuildable"));
    }

    [Fact]
    public async Task An_enqueued_row_that_cannot_be_built_is_dropped_and_the_callers_own_changes_still_save()
    {
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var audit = services.GetRequiredService<IAuditService>();
            context.Organizations.Add(new Organization { Id = "kept-org", Name = "Kept" });

            audit.Enqueue("test.unbuildable", metadata: new Cyclic());
            await context.SaveChangesAsync();
        });

        Assert.Equal(0, await RowCountAsync("test.unbuildable"));
        Assert.NotNull(await Factory.StoredOrganizationAsync("kept-org"));
    }

    [Fact]
    public async Task An_enqueued_row_commits_with_the_callers_changes_and_not_before()
    {
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            services.GetRequiredService<IAuditService>().Enqueue("test.enqueued", targetOrganizationId: "queued-org");
            context.Organizations.Add(new Organization { Id = "queued-org", Name = "Queued" });

            Assert.Equal(0, await RowCountAsync("test.enqueued"));
            await context.SaveChangesAsync();
        });

        Assert.Equal(1, await RowCountAsync("test.enqueued"));
    }

    [Fact]
    public async Task An_enqueued_row_is_lost_with_the_change_when_that_change_is_not_saved()
    {
        await Factory.WithScopeAsync(services =>
        {
            services.GetRequiredService<IAuditService>().Enqueue("test.abandoned");

            return Task.CompletedTask;
        });

        Assert.Equal(0, await RowCountAsync("test.abandoned"));
    }
}
