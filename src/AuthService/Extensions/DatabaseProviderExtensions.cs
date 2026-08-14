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

/// <summary>
/// How the schema is brought into existence at startup.
/// </summary>
public enum SchemaInitializationMode
{
    /// <summary>
    /// <c>EnsureCreated</c> — creates the schema when the database is empty and does nothing
    /// otherwise. Zero ceremony, works against both providers, and has no upgrade path: once
    /// the database exists, model changes are silently not applied. Fine for demos and tests.
    /// </summary>
    EnsureCreated,

    /// <summary>
    /// <c>Migrate</c> — applies EF Core migrations from the assembly named by
    /// <c>Database:MigrationsAssembly</c>. The only mode with an upgrade path; requires
    /// generating a provider-specific migration set first (see docs/schema/README.md).
    /// </summary>
    Migrate,

    /// <summary>
    /// Do nothing. For deployments where schema changes are applied out-of-band by a DBA,
    /// a Helm hook, or a separate job.
    /// </summary>
    None
}

public static class DatabaseProviderExtensions
{
    /// <summary>
    /// Reads <c>Database:SchemaMode</c>. Defaults to <see cref="SchemaInitializationMode.EnsureCreated"/>,
    /// which preserves the historical behaviour of this repository.
    /// </summary>
    public static SchemaInitializationMode GetSchemaMode(this IConfiguration configuration)
    {
        var mode = configuration["Database:SchemaMode"] ?? configuration["DATABASE_SCHEMA_MODE"];

        if (string.Equals(mode, "Migrate", StringComparison.OrdinalIgnoreCase))
            return SchemaInitializationMode.Migrate;

        if (string.Equals(mode, "None", StringComparison.OrdinalIgnoreCase))
            return SchemaInitializationMode.None;

        return SchemaInitializationMode.EnsureCreated;
    }

    /// <summary>
    /// Assembly holding the EF Core migrations for the active provider, from
    /// <c>Database:MigrationsAssembly</c>. Null when migrations live in the main assembly.
    /// </summary>
    public static string? GetMigrationsAssembly(this IConfiguration configuration)
    {
        var assembly = configuration["Database:MigrationsAssembly"];
        return string.IsNullOrWhiteSpace(assembly) ? null : assembly;
    }

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
        DatabaseProviderType provider,
        string? migrationsAssembly = null)
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

                    if (!string.IsNullOrWhiteSpace(migrationsAssembly))
                        sqlOptions.MigrationsAssembly(migrationsAssembly);
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

                    if (!string.IsNullOrWhiteSpace(migrationsAssembly))
                        npgsqlOptions.MigrationsAssembly(migrationsAssembly);
                });
                break;
        }
    }

    /// <summary>
    /// Brings the schema up according to <paramref name="mode"/>.
    ///
    /// <c>EnsureCreated</c> remains the default so a fresh clone still starts against either
    /// provider with no ceremony — but it is explicitly a bootstrap, not an upgrade path:
    /// against an existing database it does nothing at all, including nothing about columns
    /// added since. Production deployments should run <c>Migrate</c> (or <c>None</c> and apply
    /// schema changes out of band). See docs/schema/README.md.
    /// </summary>
    public static async Task InitializeDatabaseAsync<TContext>(
        TContext context,
        ILogger logger,
        SchemaInitializationMode mode = SchemaInitializationMode.EnsureCreated,
        CancellationToken cancellationToken = default)
        where TContext : DbContext
    {
        switch (mode)
        {
            case SchemaInitializationMode.Migrate:
                logger.LogInformation("Applying EF Core migrations...");
                await context.Database.MigrateAsync(cancellationToken);
                logger.LogInformation("Database migrations applied.");
                break;

            case SchemaInitializationMode.None:
                logger.LogInformation(
                    "Database:SchemaMode is None — skipping schema initialization. " +
                    "The schema is expected to be managed out of band.");
                break;

            case SchemaInitializationMode.EnsureCreated:
            default:
                logger.LogInformation("Ensuring database schema is created...");
                var created = await context.Database.EnsureCreatedAsync(cancellationToken);
                if (created)
                {
                    logger.LogInformation("Database schema created.");
                }
                else
                {
                    logger.LogWarning(
                        "Database already exists — EnsureCreated made no changes. Any schema change " +
                        "since it was created has NOT been applied. Set Database:SchemaMode=Migrate " +
                        "for an upgrade path (see docs/schema/README.md).");
                }
                break;
        }
    }
}
