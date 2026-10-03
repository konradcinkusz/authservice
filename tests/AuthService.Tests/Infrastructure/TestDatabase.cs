using AuthService.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Tests.Infrastructure;

public static class TestDatabase
{
    /// <summary>
    /// Makes one row impossible to delete, the way a constraint nothing here knows about would,
    /// so a test can see what a process that deletes rows does about the one it cannot.
    /// </summary>
    public static Task MakeUndeletableAsync(this AuthServiceFactory factory, string table, string id) =>
        factory.OnDeleteAsync(table, id, "RAISE(ABORT, 'cannot delete')");

    /// <summary>
    /// Makes the database skip the delete of one row without an error, as when someone else has
    /// just changed or removed it: the statement runs and affects nothing, which a caller sees as
    /// a concurrency failure (Identity turns that into a failed result) rather than an exception.
    /// </summary>
    public static Task MakeDeleteLostAsync(this AuthServiceFactory factory, string table, string id) =>
        factory.OnDeleteAsync(table, id, "RAISE(IGNORE)");

    private static Task OnDeleteAsync(this AuthServiceFactory factory, string table, string id, string outcome) =>
        factory.WithScopeAsync(async services =>
        {
            var connection = services.GetRequiredService<ApplicationDbContext>().Database.GetDbConnection();
            await using var command = connection.CreateCommand();
            command.CommandText =
                $"CREATE TRIGGER undeletable_{Guid.NewGuid():N} BEFORE DELETE ON {table} WHEN OLD.Id = '{id}' " +
                $"BEGIN SELECT {outcome}; END;";
            await command.ExecuteNonQueryAsync();
        });
}
