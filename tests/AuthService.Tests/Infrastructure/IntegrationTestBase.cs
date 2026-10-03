using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests.Infrastructure;

/// <summary>
/// Base class that gives each test class its own application instance and database, so tests
/// cannot leak state into one another through the shared SQLite connection.
/// </summary>
public abstract class IntegrationTestBase : IAsyncLifetime
{
    protected AuthServiceFactory Factory { get; private set; } = null!;
    protected HttpClient Client { get; private set; } = null!;

    /// <summary>
    /// Override to change how the application is configured for this class: a setting the
    /// environment-wide defaults do not cover, or a service replaced with a fake. Applied after
    /// the application's own registrations, so it wins.
    /// </summary>
    protected virtual void ConfigureServices(IServiceCollection services)
    {
    }

    /// <summary>
    /// Settings this class wants different from the environment-wide defaults. Applied as host
    /// settings, so they reach anything the application reads from configuration while serving
    /// a request; the ones it reads while starting up (signing keys, the database) need
    /// <see cref="ConfigureServices"/> or the process environment instead.
    /// </summary>
    protected virtual IReadOnlyDictionary<string, string?> Settings => new Dictionary<string, string?>();

    public async Task InitializeAsync()
    {
        Factory = new ConfiguredFactory(ConfigureServices, Settings);
        await Factory.InitializeAsync();

        // AllowAutoRedirect off so redirect-based flows can be asserted on directly.
        Client = Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    public Task DisposeAsync()
    {
        Client?.Dispose();
        Factory?.Dispose();
        return Task.CompletedTask;
    }

    private sealed class ConfiguredFactory(
        Action<IServiceCollection> configure, IReadOnlyDictionary<string, string?> settings) : AuthServiceFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            foreach (var (key, value) in settings)
                builder.UseSetting(key, value);

            builder.ConfigureTestServices(configure);
        }
    }
}
