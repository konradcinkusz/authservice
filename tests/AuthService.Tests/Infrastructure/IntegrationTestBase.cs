using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
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
    /// Settings this class wants different from the environment-wide defaults. They are host
    /// settings, which the application sees while it starts up, and an in-memory source added
    /// last, which wins over the process environment for everything it reads after that. A
    /// setting the application reads while starting up and that the process environment already
    /// gives a value (signing keys, the database) still needs <see cref="ConfigureServices"/> or
    /// the process environment itself.
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

            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(settings));
            builder.ConfigureTestServices(configure);
        }
    }
}
