using AuthService.Data;
using AuthService.Extensions;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AuthService.Tests;

/// <summary>How the database settings are read, and what each provider is given.</summary>
public class DatabaseSettingsTests
{
    private static IConfiguration Configuration(params (string Key, string? Value)[] settings) =>
        new ConfigurationBuilder().AddInMemoryCollection(settings.ToDictionary(s => s.Key, s => s.Value)).Build();

    [Theory]
    [InlineData(null, SchemaInitializationMode.EnsureCreated)]
    [InlineData("", SchemaInitializationMode.EnsureCreated)]
    [InlineData("EnsureCreated", SchemaInitializationMode.EnsureCreated)]
    [InlineData("migrate", SchemaInitializationMode.Migrate)]
    [InlineData("MIGRATE", SchemaInitializationMode.Migrate)]
    [InlineData("None", SchemaInitializationMode.None)]
    [InlineData("none", SchemaInitializationMode.None)]
    [InlineData("something-else", SchemaInitializationMode.EnsureCreated)]
    public void The_schema_mode_is_read_without_regard_to_case_and_defaults_to_ensure_created(
        string? value, SchemaInitializationMode expected)
    {
        Assert.Equal(expected, Configuration(("Database:SchemaMode", value)).GetSchemaMode());
    }

    [Fact]
    public void The_schema_mode_can_be_given_as_the_plain_environment_variable_and_the_section_wins()
    {
        Assert.Equal(SchemaInitializationMode.None, Configuration(("DATABASE_SCHEMA_MODE", "None")).GetSchemaMode());
        Assert.Equal(SchemaInitializationMode.Migrate,
            Configuration(("Database:SchemaMode", "Migrate"), ("DATABASE_SCHEMA_MODE", "None")).GetSchemaMode());
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("AuthService.Migrations.PostgreSQL", "AuthService.Migrations.PostgreSQL")]
    public void A_blank_migrations_assembly_is_no_assembly(string? value, string? expected)
    {
        Assert.Equal(expected, Configuration(("Database:MigrationsAssembly", value)).GetMigrationsAssembly());
    }

    [Fact]
    public void The_provider_can_be_given_as_the_plain_environment_variable_and_it_wins_over_the_key()
    {
        Assert.Equal(DatabaseProviderType.SqlServer, Configuration(("DATABASE_PROVIDER", "SqlServer")).GetDatabaseProvider());
        Assert.Equal(DatabaseProviderType.SqlServer,
            Configuration(("DATABASE_PROVIDER", "mssql"), ("DatabaseProvider", "PostgreSQL")).GetDatabaseProvider());
    }

    [Theory]
    [InlineData(DatabaseProviderType.PostgreSQL, "Npgsql", "Host=db;Database=auth")]
    [InlineData(DatabaseProviderType.SqlServer, "SqlServer", "Server=db;Database=auth")]
    public void Each_provider_is_configured_with_retry_on_failure_and_the_named_migrations_assembly(
        DatabaseProviderType provider, string providerName, string connectionString)
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>();

        DatabaseProviderExtensions.ConfigureProvider(options, connectionString, provider, "AuthService.Migrations.Test");

        var relational = options.Options.Extensions.OfType<RelationalOptionsExtension>().Single();
        Assert.Contains(providerName, relational.GetType().Name);
        Assert.Equal(connectionString, relational.ConnectionString);
        Assert.Equal("AuthService.Migrations.Test", relational.MigrationsAssembly);
        Assert.Equal(60, relational.CommandTimeout);
        Assert.NotNull(relational.ExecutionStrategyFactory);
    }

    [Fact]
    public void Without_a_migrations_assembly_the_migrations_are_expected_in_the_main_one()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>();

        DatabaseProviderExtensions.ConfigureProvider(options, "Host=db;Database=auth", DatabaseProviderType.PostgreSQL);

        Assert.Null(options.Options.Extensions.OfType<RelationalOptionsExtension>().Single().MigrationsAssembly);
    }
}

/// <summary>What startup does to the schema in each mode, on a database that starts out empty.</summary>
public class SchemaInitializationTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly ListLogger<SchemaInitializationTests> _log = new();

    public SchemaInitializationTests() => _connection.Open();

    public void Dispose() => _connection.Dispose();

    private ApplicationDbContext NewContext() =>
        new(new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(_connection).Options);

    [Fact]
    public async Task Ensure_created_builds_the_schema_and_warns_the_second_time_that_nothing_was_upgraded()
    {
        await using var context = NewContext();

        await DatabaseProviderExtensions.InitializeDatabaseAsync(context, _log, SchemaInitializationMode.EnsureCreated);
        Assert.Equal(0, await context.Users.CountAsync());
        Assert.Contains(_log.Messages, m => m.Contains("Database schema created"));

        await DatabaseProviderExtensions.InitializeDatabaseAsync(context, _log, SchemaInitializationMode.EnsureCreated);
        Assert.Contains(_log.Messages, m => m.Contains("EnsureCreated made no changes") && m.Contains("NOT been applied"));
    }

    [Fact]
    public async Task None_leaves_an_empty_database_empty_for_whoever_manages_the_schema()
    {
        await using var context = NewContext();

        await DatabaseProviderExtensions.InitializeDatabaseAsync(context, _log, SchemaInitializationMode.None);

        await Assert.ThrowsAsync<SqliteException>(() => context.Users.CountAsync());
        Assert.Contains(_log.Messages, m => m.Contains("skipping schema initialization"));
    }

    [Fact]
    public async Task Ensure_created_is_the_mode_when_none_is_given()
    {
        await using var context = NewContext();

        await DatabaseProviderExtensions.InitializeDatabaseAsync(context, _log);

        Assert.Equal(0, await context.Users.CountAsync());
    }
}

/// <summary>
/// The service that prepares the database after the web server is already listening. It runs
/// here against a database that starts out empty, which is what a first start looks like.
/// </summary>
public class MigrationBackgroundServiceTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly ListLogger<MigrationBackgroundService> _log = new();
    private readonly MigrationCompletionSignal _signal = new();

    public MigrationBackgroundServiceTests() => _connection.Open();

    public void Dispose() => _connection.Dispose();

    private ServiceProvider Host(string schemaMode, string? connectionString = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ILogger<MigrationBackgroundService>>(_log);
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Database:SchemaMode"] = schemaMode }).Build());
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            if (connectionString is null)
                options.UseSqlite(_connection);
            else
                options.UseSqlite(connectionString);
        });
        services.AddIdentityCore<ApplicationUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();

        return services.BuildServiceProvider();
    }

    private static async Task<List<string>> RolesAsync(IServiceProvider host)
    {
        using var scope = host.CreateScope();

        return await scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>().Roles
            .Select(r => r.Name!).ToListAsync();
    }

    [Fact]
    public async Task A_first_start_creates_the_schema_seeds_the_roles_and_reports_ready()
    {
        await using var host = Host("EnsureCreated");
        using var service = new MigrationBackgroundService(host, _signal);

        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!;

        Assert.True(_signal.IsCompleted);
        Assert.Equal(DbSeeder.DefaultRoles.Order(), (await RolesAsync(host)).Order());
        Assert.Contains(_log.Messages, m => m.Contains("Database seeding completed"));
    }

    [Fact]
    public async Task A_seeding_failure_does_not_stop_the_service_or_take_back_the_ready_signal()
    {
        // With the schema left to someone else and not yet there, seeding has nothing to write to.
        await using var host = Host("None");
        using var service = new MigrationBackgroundService(host, _signal);

        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!;

        Assert.True(_signal.IsCompleted);
        Assert.Contains(_log.Messages, m => m.Contains("Database seeding failed") || m.Contains("seeding failed"));
    }

    [Fact]
    public async Task A_database_that_cannot_be_reached_is_retried_and_never_reported_ready()
    {
        await using var host = Host("EnsureCreated", $"Data Source={Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}", "auth.db")}");
        using var service = new MigrationBackgroundService(host, _signal);

        await service.StartAsync(CancellationToken.None);
        await TestWait.UntilAsync(() => Task.FromResult(_log.Messages.Any(m => m.Contains("attempt 1/10") && m.Contains("Retrying"))),
            "the first failed attempt is logged");
        await service.StopAsync(CancellationToken.None);

        Assert.False(_signal.IsCompleted);
    }
}
