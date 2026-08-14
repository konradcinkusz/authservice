using System.Security.Cryptography;
using AuthService.Data;
using AuthService.Extensions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthService.Tests.Infrastructure;

/// <summary>
/// Boots the real application — real controllers, real Identity, real token service — against
/// an in-memory SQLite database.
///
/// SQLite rather than the InMemory provider because the model uses filtered indexes and unique
/// constraints that InMemory silently ignores, and those constraints are part of what the
/// tests are checking. SQLite rather than Testcontainers-Postgres because these tests must run
/// in CI with no Docker daemon and no network; the provider-specific surface SQLite cannot
/// represent is covered by the schema documentation and the Docker build job instead.
/// </summary>
public class AuthServiceFactory : WebApplicationFactory<Program>
{
    /// <summary>
    /// Required settings go in via environment variables rather than
    /// <c>ConfigureAppConfiguration</c>.
    ///
    /// Program.cs validates its configuration in top-level statements, which run while the
    /// builder is being constructed — before the factory's configuration delegates are
    /// applied. Environment variables are already in the configuration by then, because
    /// <c>WebApplication.CreateBuilder</c> adds that source itself.
    /// </summary>
    static AuthServiceFactory()
    {
        Set("ASPNETCORE_ENVIRONMENT", "Testing");

        // Generated rather than a literal: 48 bytes of randomness, comfortably over the
        // 32-byte floor the startup guard enforces, and nothing in the repository that
        // looks like — or could be mistaken for — a real signing key.
        Set("Jwt__SecretKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)));
        Set("Jwt__Issuer", "AuthService");
        Set("Jwt__Audience", "AuthService");
        Set("Jwt__ExpirationMinutes", "60");

        // Replaced with a SQLite connection in ConfigureWebHost; this only has to satisfy
        // the startup guard.
        Set("ConnectionStrings__DefaultConnection", "DataSource=:memory:");

        // No email provider in tests, so verification would otherwise auto-enable and every
        // registration would stop at 202 instead of returning tokens.
        Set("Auth__RequireConfirmedEmail", "false");

        Set("Swagger__Enabled", "false");
        Set("OAuth__PostLoginRedirectBaseUrl", "http://localhost:3000");
        Set("ConsentVersions__Terms", TestData.TermsVersion);
        Set("ConsentVersions__Privacy", TestData.PrivacyVersion);
        Set("ConsentVersions__Cookies", TestData.CookiesVersion);

        static void Set(string key, string value) => Environment.SetEnvironmentVariable(key, value);
    }

    // Held open for the lifetime of the factory: an in-memory SQLite database exists only as
    // long as a connection to it does.
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    private bool _databaseInitialized;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            // Swap the configured provider (PostgreSQL) for SQLite.
            //
            // The options *configuration* registration has to go too, not just the options:
            // EF Core 9 stores the AddDbContext callback as its own service, so leaving it in
            // place would apply UseNpgsql alongside UseSqlite and EF would refuse to resolve a
            // context with two providers configured. Matched by name so this keeps working
            // across EF versions that rename the type.
            var contextDescriptors = services
                .Where(d => d.ServiceType == typeof(ApplicationDbContext)
                         || d.ServiceType == typeof(DbContextOptions)
                         || (d.ServiceType.IsGenericType
                             && d.ServiceType.GetGenericTypeDefinition() == typeof(DbContextOptions<>))
                         || (d.ServiceType.FullName?.Contains("DbContextOptionsConfiguration", StringComparison.Ordinal) ?? false))
                .ToList();

            foreach (var descriptor in contextDescriptors)
                services.Remove(descriptor);

            _connection.Open();
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(_connection));

            // Drop the app's own background services. Schema creation and seeding happen
            // deterministically in InitializeAsync instead of racing the first request, and the
            // cleanup loops have nothing to do here.
            //
            // Removing them individually rather than clearing IHostedService wholesale — the
            // test server itself is registered as a hosted service.
            var hostedToRemove = services
                .Where(d => d.ServiceType == typeof(IHostedService)
                            && d.ImplementationType is not null
                            && d.ImplementationType.Assembly == typeof(Program).Assembly)
                .ToList();

            foreach (var descriptor in hostedToRemove)
                services.Remove(descriptor);
        });
    }

    /// <summary>Creates the schema, seeds roles, and marks the service ready.</summary>
    public async Task InitializeAsync()
    {
        if (_databaseInitialized)
            return;

        using var scope = Services.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync();

        await DbSeeder.SeedAsync(scope.ServiceProvider);

        Services.GetRequiredService<IMigrationCompletionSignal>().SetCompleted();

        _databaseInitialized = true;
    }

    /// <summary>Runs <paramref name="action"/> against a fresh service scope.</summary>
    public async Task WithScopeAsync(Func<IServiceProvider, Task> action)
    {
        using var scope = Services.CreateScope();
        await action(scope.ServiceProvider);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _connection.Dispose();

        base.Dispose(disposing);
    }
}
