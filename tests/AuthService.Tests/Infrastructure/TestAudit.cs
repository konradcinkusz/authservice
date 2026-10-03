using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Tests.Infrastructure;

public static class TestAudit
{
    /// <summary>The audit rows recorded for <paramref name="action"/>, oldest first, optionally narrowed.</summary>
    public static async Task<List<AuditEvent>> AuditAsync(
        this AuthServiceFactory factory, string action, Func<AuditEvent, bool>? where = null)
    {
        List<AuditEvent> rows = [];

        await factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var stored = await context.AuditEvents.AsNoTracking()
                .Where(a => a.Action == action).OrderBy(a => a.OccurredAt).ToListAsync();
            rows = stored.Where(a => where is null || where(a)).ToList();
        });

        return rows;
    }
}
