using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthService.Extensions;

/// <summary>
/// Supported database providers. Selected via the <c>DATABASE_PROVIDER</c> environment
/// variable (or <c>DatabaseProvider</c> configuration key), defaulting to PostgreSQL.
/// </summary>
public enum DatabaseProviderType
{
    PostgreSQL,
    SqlServer
}

public static class DatabaseProviderExtensions
{
    public static DatabaseProviderType GetDatabaseProvider(this IConfiguration configuration)
    {
        var provider = configuration["DATABASE_PROVIDER"]
            ?? configuration["DatabaseProvider"];

        if (string.Equals(provider, "SqlServer", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(provider, "MsSql", StringComparison.OrdinalIgnoreCase))
        {
            return DatabaseProviderType.SqlServer;
        }

        return DatabaseProviderType.PostgreSQL;
    }

    /// <summary>
    /// Configures the EF Core provider (PostgreSQL or SQL Server) with retry-on-failure
    /// resilience suitable for cloud database backends that can cold-start or fail over.
    /// </summary>
    public static void ConfigureProvider(
        DbContextOptionsBuilder options,
        string connectionString,
        DatabaseProviderType provider)
    {
        switch (provider)
        {
            case DatabaseProviderType.SqlServer:
                options.UseSqlServer(connectionString, sqlOptions =>
                {
                    sqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 10,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null);
                    sqlOptions.CommandTimeout(60);
                });
                break;

            case DatabaseProviderType.PostgreSQL:
            default:
                options.UseNpgsql(connectionString, npgsqlOptions =>
                {
                    npgsqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 10,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorCodesToAdd: null);
                    npgsqlOptions.CommandTimeout(60);
                });
                break;
        }
    }

    /// <summary>
    /// Initializes the database schema using <c>EnsureCreated</c>. This project ships without
    /// versioned EF migrations so it can bootstrap against either supported provider out of the
    /// box; if you need migration-based schema evolution for production, run
    /// <c>dotnet ef migrations add InitialCreate</c> after cloning and switch this to
    /// <c>Database.MigrateAsync()</c>.
    /// </summary>
    public static async Task InitializeDatabaseAsync<TContext>(
        TContext context,
        ILogger logger,
        CancellationToken cancellationToken = default)
        where TContext : DbContext
    {
        logger.LogInformation("Ensuring database schema is created...");
        await context.Database.EnsureCreatedAsync(cancellationToken);
        logger.LogInformation("Database schema ready.");
    }
}
