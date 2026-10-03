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
        factory.WithScopeAsync(async services =>
        {
            var connection = services.GetRequiredService<ApplicationDbContext>().Database.GetDbConnection();
            await using var command = connection.CreateCommand();
            command.CommandText =
                $"CREATE TRIGGER undeletable_{Guid.NewGuid():N} BEFORE DELETE ON {table} WHEN OLD.Id = '{id}' " +
                "BEGIN SELECT RAISE(ABORT, 'cannot delete'); END;";
            await command.ExecuteNonQueryAsync();
        });
}
