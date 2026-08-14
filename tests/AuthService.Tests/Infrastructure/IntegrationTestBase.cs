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

    public async Task InitializeAsync()
    {
        Factory = new AuthServiceFactory();
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
}
