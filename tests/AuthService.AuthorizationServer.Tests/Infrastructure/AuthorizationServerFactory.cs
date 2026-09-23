using System.Collections.Concurrent;
using System.Security.Cryptography;
using AuthService.Data;
using AuthService.Extensions;
using AuthService.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthService.AuthorizationServer.Tests.Infrastructure;

/// <summary>
/// Boots the real application with RS256 signing and one MCP client configured, against an
/// in-memory SQLite database, as <c>AuthServiceFactory</c> does for the HS256 suite.
///
/// Every setting goes in through <c>UseSetting</c>, which Program.cs sees during its top-level
/// configuration reads. Nothing is process-wide, so each host carries its own keys, clients and
/// interaction mode, and test classes run in parallel without racing one another.
/// </summary>
public class AuthorizationServerFactory : WebApplicationFactory<Program>
{
    /// <summary>The public origin, and so the issuer of MCP tokens (A1). TestServer ignores the scheme.</summary>
    public const string Issuer = "https://localhost";

    public const string ClientId = "claude-test";
    public const string ClientDisplayName = "Claude (test)";
    public const string RedirectUri = "https://claude.example.test/api/mcp/auth_callback";
    public const string Resource = "https://mcp.example.test/mcp";
    public const string Scope = "notes:read";
    public const string ScopeDescription = "Read your notes";

    public const string TermsVersion = "2026-01-01";
    public const string PrivacyVersion = "2026-01-01";

    private readonly SqliteConnection _connection;
    private readonly bool _ownsConnection;
    private bool _databaseInitialized;

    /// <param name="configure">Adjusts the settings before the host is built; a null value removes a key.</param>
    /// <param name="signingKey">The current signing key; generated when not supplied.</param>
    /// <param name="sharedConnection">A database another factory already created, to model a restart.</param>
    public AuthorizationServerFactory(
        Action<IDictionary<string, string?>>? configure = null,
        RSA? signingKey = null,
        SqliteConnection? sharedConnection = null)
    {
        SigningKey = signingKey ?? RSA.Create(2048);

        // Generated, never literal: nothing in the repository that looks like a real credential.
        ClientSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        EncryptionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        Settings = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["Jwt:Algorithm"] = "RS256",
            ["Jwt:PrivateKeyPem"] = SigningKey.ExportPkcs8PrivateKeyPem(),
            ["Jwt:Issuer"] = "AuthService",
            ["Jwt:Audience"] = "AuthService",
            ["Jwt:ExpirationMinutes"] = "60",
            ["Jwt:PublicBaseUrl"] = Issuer,

            // Replaced with SQLite below; this only has to satisfy the startup guard.
            ["ConnectionStrings:DefaultConnection"] = "DataSource=:memory:",
            ["Auth:RequireConfirmedEmail"] = "false",
            ["Swagger:Enabled"] = "false",
            ["OAuth:PostLoginRedirectBaseUrl"] = "http://localhost:3000",
            ["ConsentVersions:Terms"] = TermsVersion,
            ["ConsentVersions:Privacy"] = PrivacyVersion,
            ["ConsentVersions:Cookies"] = TermsVersion,

            ["AuthorizationServer:Clients:0:ClientId"] = ClientId,
            ["AuthorizationServer:Clients:0:DisplayName"] = ClientDisplayName,
            ["AuthorizationServer:Clients:0:ClientSecret"] = ClientSecret,
            ["AuthorizationServer:Clients:0:RedirectUris:0"] = RedirectUri,
            ["AuthorizationServer:Clients:0:AllowedScopes:0"] = Scope,
            ["AuthorizationServer:Clients:0:AllowedScopes:1"] = "offline_access",
            ["AuthorizationServer:Clients:0:AllowedResources:0"] = Resource,
            ["AuthorizationServer:Scopes:0:Name"] = Scope,
            ["AuthorizationServer:Scopes:0:Description"] = ScopeDescription,
            ["AuthorizationServer:EncryptionKey"] = EncryptionKey,
        };

        configure?.Invoke(Settings);

        _ownsConnection = sharedConnection is null;
        _connection = sharedConnection ?? new SqliteConnection("DataSource=:memory:");
    }

    public RSA SigningKey { get; }

    /// <summary>Every log line the host writes, through the host's own filters, for the "nothing secret is logged" check (N5).</summary>
    public CapturingLoggerProvider Logs { get; } = new();

    public string ClientSecret { get; }
    public string EncryptionKey { get; }
    public Dictionary<string, string?> Settings { get; }

    /// <summary>The database, for a second factory that models the same deployment restarted.</summary>
    public SqliteConnection Connection => _connection;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        foreach (var (key, value) in Settings)
        {
            if (value is not null)
                builder.UseSetting(key, value);
        }

        builder.ConfigureLogging(logging => logging.AddProvider(Logs));

        builder.ConfigureServices(services =>
        {
            // Swap the configured provider for SQLite — see AuthServiceFactory for why each of
            // these registrations has to go.
            var contextDescriptors = services
                .Where(d => d.ServiceType == typeof(ApplicationDbContext)
                         || d.ServiceType == typeof(DbContextOptions)
                         || (d.ServiceType.IsGenericType
                             && d.ServiceType.GetGenericTypeDefinition() == typeof(DbContextOptions<>))
                         || (d.ServiceType.FullName?.Contains("DbContextOptionsConfiguration", StringComparison.Ordinal) ?? false))
                .ToList();

            foreach (var descriptor in contextDescriptors)
                services.Remove(descriptor);

            if (_connection.State != System.Data.ConnectionState.Open)
                _connection.Open();

            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(_connection));

            // The app's own background services go: schema, seeding and client registration
            // happen deterministically in InitializeAsync instead of racing the first request.
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

        // What AuthorizationClientSync does at startup, run here rather than in the background.
        await ActivatorUtilities.CreateInstance<AuthorizationClientSync>(Services).SyncAsync();

        _databaseInitialized = true;
    }

    /// <summary>Runs <paramref name="action"/> against a fresh service scope.</summary>
    public async Task WithScopeAsync(Func<IServiceProvider, Task> action)
    {
        using var scope = Services.CreateScope();
        await action(scope.ServiceProvider);
    }

    /// <summary>A client with cookies, no automatic redirects, and an https base address so Secure cookies round-trip.</summary>
    public HttpClient CreateBrowserClient() => CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = new Uri(Issuer),
        HandleCookies = true
    });

    protected override void Dispose(bool disposing)
    {
        if (disposing && _ownsConnection)
            _connection.Dispose();

        base.Dispose(disposing);
    }
}

/// <summary>Collects every log entry a host writes, formatted and with its structured values.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _entries = new();

    public IReadOnlyCollection<string> Entries => _entries.ToArray();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _entries);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(string category, ConcurrentQueue<string> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        // The host's filter rules decide what reaches this provider, as they do for the console.
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            entries.Enqueue($"{logLevel} {category}: {formatter(state, exception)} {exception}");

            if (state is IEnumerable<KeyValuePair<string, object?>> values)
            {
                foreach (var (key, value) in values)
                    entries.Enqueue($"  {key}={value}");
            }
        }
    }
}
