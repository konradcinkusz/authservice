using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Data;
using AuthService.Extensions;
using AuthService.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// The background service that puts the configured clients in the store at startup. The test host
/// takes the application's own background services out and registers the clients itself
/// (<see cref="AuthorizationServerFactory"/>), so these start the service by hand, on a schema that
/// exists but holds no client yet.
/// </summary>
public class ClientSyncServiceTests
{
    private const string Category = "AuthService.Services.AuthorizationClientSync";
    private const string RegistrationFailed = $"Error {Category}: Registering the authorization server's clients failed";

    private static async Task<AuthorizationServerFactory> HostWithAnEmptySchemaAsync(Action<IDictionary<string, string?>>? configure = null)
    {
        var factory = new AuthorizationServerFactory(configure);
        await factory.WithScopeAsync(services => services.GetRequiredService<ApplicationDbContext>().Database.EnsureCreatedAsync());

        return factory;
    }

    private static AuthorizationClientSync NewService(AuthorizationServerFactory factory, IMigrationCompletionSignal signal) =>
        ActivatorUtilities.CreateInstance<AuthorizationClientSync>(factory.Services, signal);

    private static async Task<bool> IsRegisteredAsync(AuthorizationServerFactory factory)
    {
        var registered = false;
        await factory.WithScopeAsync(async services =>
            registered = await services.GetRequiredService<IOpenIddictApplicationManager>()
                .FindByClientIdAsync(AuthorizationServerFactory.ClientId) is not null);

        return registered;
    }

    private static Task DropTheAuthorizationServersTablesAsync(AuthorizationServerFactory factory) =>
        factory.WithScopeAsync(services => services.GetRequiredService<ApplicationDbContext>().Database.ExecuteSqlRawAsync(
            "DROP TABLE OpenIddictTokens; DROP TABLE OpenIddictAuthorizations; DROP TABLE OpenIddictScopes; " +
            "DROP TABLE OpenIddictApplications; DROP TABLE AuthorizationInteractions;"));

    private static bool IsClientSyncError(string entry) => entry.StartsWith($"Error {Category}", StringComparison.Ordinal);

    [Fact]
    public void The_application_starts_the_service_with_the_host()
    {
        using var factory = new AuthorizationServerFactory();

        _ = factory.Services; // builds the host, which is when the registrations are read

        Assert.Contains(typeof(AuthorizationClientSync), factory.AppHostedServices);
    }

    [Fact]
    public async Task The_configured_client_is_registered_once_the_schema_is_ready_and_not_before()
    {
        using var factory = await HostWithAnEmptySchemaAsync();
        var signal = new MigrationCompletionSignal();
        using var service = NewService(factory, signal);

        await service.StartAsync(CancellationToken.None);

        // Until the migrations have run the client table may not exist: nothing is read or written.
        // (Parked on the signal, the service is not using the test database, so this thread may.)
        await Task.Delay(250);
        Assert.False(service.ExecuteTask!.IsCompleted);
        Assert.False(await IsRegisteredAsync(factory));

        signal.SetCompleted();
        await service.ExecuteTask.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.True(await IsRegisteredAsync(factory));
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_registration_that_fails_is_logged_and_never_takes_the_host_down()
    {
        using var factory = await HostWithAnEmptySchemaAsync();
        using var service = NewService(factory, new FailingSignal(new InvalidOperationException("the schema never arrived")));

        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(30)); // completes: an exception here would stop the host

        Assert.Contains(factory.Logs.Entries, e =>
            e.StartsWith(RegistrationFailed, StringComparison.Ordinal) && e.Contains("the schema never arrived", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Stopping_while_it_waits_for_the_schema_is_a_clean_stop_and_not_an_error()
    {
        using var factory = await HostWithAnEmptySchemaAsync();
        using var service = NewService(factory, new MigrationCompletionSignal());
        await service.StartAsync(CancellationToken.None);

        await service.StopAsync(CancellationToken.None);

        Assert.True(service.ExecuteTask!.IsCompleted);
        Assert.DoesNotContain(factory.Logs.Entries, IsClientSyncError);
    }

    [Fact]
    public async Task With_the_server_on_a_database_without_its_tables_is_an_error_in_the_log()
    {
        using var factory = new AuthorizationServerFactory();
        await factory.InitializeAsync();
        await DropTheAuthorizationServersTablesAsync(factory);
        using var service = NewService(factory, factory.Services.GetRequiredService<IMigrationCompletionSignal>());

        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Contains(factory.Logs.Entries, e => e.StartsWith(RegistrationFailed, StringComparison.Ordinal));
    }

    [Fact]
    public async Task With_the_server_off_the_same_missing_tables_are_let_go_without_an_error()
    {
        // No client configured: the sync only clears out clients an earlier release registered, and
        // a database that predates the library's tables has none (AuthorizationServerPosture).
        using var factory = new AuthorizationServerFactory(settings =>
        {
            foreach (var key in settings.Keys.Where(k => k.StartsWith("AuthorizationServer:", StringComparison.Ordinal)).ToList())
                settings.Remove(key);
        });
        await factory.InitializeAsync();
        await DropTheAuthorizationServersTablesAsync(factory);
        using var service = NewService(factory, factory.Services.GetRequiredService<IMigrationCompletionSignal>());

        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.DoesNotContain(factory.Logs.Entries, IsClientSyncError);
    }

    private sealed class FailingSignal(Exception failure) : IMigrationCompletionSignal
    {
        public Task WaitAsync(CancellationToken cancellationToken = default) => Task.FromException(failure);

        public void SetCompleted()
        {
        }

        public bool IsCompleted => false;
    }
}
