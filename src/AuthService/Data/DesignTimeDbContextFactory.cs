using AuthService.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace AuthService.Data;

/// <summary>
/// Lets <c>dotnet ef</c> build a context without starting the app, so generating migrations
/// does not require a reachable database or a fully configured environment.
///
/// The provider comes from <c>DATABASE_PROVIDER</c> / <c>DatabaseProvider</c> exactly as at
/// runtime, which is what makes provider-specific migration sets possible:
///
///   DATABASE_PROVIDER=PostgreSQL dotnet ef migrations add InitialCreate \
///     --project src/AuthService.Migrations.PostgreSQL \
///     --startup-project src/AuthService
///
/// See docs/schema/README.md for the full procedure.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    private const string PlaceholderPostgres = "Host=localhost;Database=authservice;Username=postgres;Password=postgres";
    private const string PlaceholderSqlServer = "Server=localhost;Database=authservice;User Id=sa;Password=Placeholder1!;TrustServerCertificate=True";

    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var provider = configuration.GetDatabaseProvider();

        // Migrations are generated from the model, not from the database, so a placeholder
        // connection string is enough when none is configured.
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            connectionString = provider == DatabaseProviderType.SqlServer
                ? PlaceholderSqlServer
                : PlaceholderPostgres;
        }

        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
        DatabaseProviderExtensions.ConfigureProvider(
            optionsBuilder,
            connectionString,
            provider,
            configuration.GetMigrationsAssembly());

        return new ApplicationDbContext(optionsBuilder.Options);
    }
}
