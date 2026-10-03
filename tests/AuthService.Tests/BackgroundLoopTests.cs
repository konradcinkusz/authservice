using AuthService.Data;
using AuthService.Extensions;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// What the readiness probe says, and why. Liveness asks whether the process is up; this asks whether
/// it can serve a request, and a platform that points its check at the wrong one rolls traffic onto a
/// machine whose database is half set up or gone.
/// </summary>
public class ReadinessProbeTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly MigrationCompletionSignal _signal = new();

    public ReadinessProbeTests() => _connection.Open();

    public void Dispose() => _connection.Dispose();

    private ApplicationDbContext NewContext(string? connectionString = null) =>
        new(connectionString is null
            ? new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(_connection).Options
            : new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connectionString).Options);

    private static Task<HealthCheckResult> CheckAsync(ApplicationDbContext context, IMigrationCompletionSignal signal) =>
        new DatabaseReadyHealthCheck(context, signal).CheckHealthAsync(new HealthCheckContext());

    [Fact]
    public async Task It_is_not_ready_until_the_schema_has_been_initialised_even_though_the_database_answers()
    {
        await using var context = NewContext();

        var result = await CheckAsync(context, _signal);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("has not completed", result.Description);
    }

    [Fact]
    public async Task It_is_ready_once_the_schema_is_initialised_and_the_database_answers()
    {
        await using var context = NewContext();
        _signal.SetCompleted();

        var result = await CheckAsync(context, _signal);

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task It_is_not_ready_when_the_database_cannot_be_reached()
    {
        await using var context = NewContext($"Data Source={Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}", "auth.db")}");
        _signal.SetCompleted();

        var result = await CheckAsync(context, _signal);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("not reachable", result.Description);
    }

    [Fact]
    public async Task A_probe_that_throws_is_an_unhealthy_answer_not_an_error()
    {
        var context = NewContext();
        await context.DisposeAsync();
        _signal.SetCompleted();

        var result = await CheckAsync(context, _signal);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.NotNull(result.Exception);
    }
}

/// <summary>The signal that holds every background service back until the schema is there.</summary>
public class MigrationCompletionSignalTests
{
    [Fact]
    public async Task Waiting_ends_when_the_signal_is_set_and_setting_it_twice_changes_nothing()
    {
        var signal = new MigrationCompletionSignal();
        var waiting = signal.WaitAsync();
        var waitingWithToken = signal.WaitAsync(new CancellationTokenSource().Token);
        Assert.False(signal.IsCompleted);
        Assert.False(waiting.IsCompleted);

        signal.SetCompleted();
        signal.SetCompleted();

        await waiting;
        await waitingWithToken;
        Assert.True(signal.IsCompleted);
    }

    [Fact]
    public async Task Waiting_can_be_cancelled_while_the_schema_is_not_ready()
    {
        var signal = new MigrationCompletionSignal();
        using var cancellation = new CancellationTokenSource();
        var waiting = signal.WaitAsync(cancellation.Token);

        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.False(signal.IsCompleted);
    }
}

/// <summary>
/// The hourly loops. Neither may start before the schema exists, and a pass that fails (the database
/// down for a minute) is logged and tried again next hour rather than ending the service.
/// </summary>
public class ReaperLoopTests
{
    private sealed class FailingScopeFactory : IServiceScopeFactory
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public IServiceScope CreateScope()
        {
            Interlocked.Increment(ref _calls);
            throw new InvalidOperationException("database unavailable");
        }
    }

    private static MigrationCompletionSignal Ready()
    {
        var signal = new MigrationCompletionSignal();
        signal.SetCompleted();

        return signal;
    }

    private static Task<bool> Logged(ListLogger<UserCleanupService> log, string text) =>
        Task.FromResult(log.Messages.Any(m => m.Contains(text)));

    [Fact]
    public async Task A_pass_over_accounts_that_fails_is_logged_and_the_pruning_step_still_runs()
    {
        var scopes = new FailingScopeFactory();
        var log = new ListLogger<UserCleanupService>();
        using var reaper = new UserCleanupService(scopes, log, Ready());

        await reaper.StartAsync(CancellationToken.None);
        await TestWait.UntilAsync(() => Logged(log, "Error pruning the authorization server's expired rows"), "both steps have failed");
        await reaper.StopAsync(CancellationToken.None);

        Assert.Contains(log.Messages, m => m.Contains("Error during user account cleanup"));
        Assert.Equal(2, scopes.Calls);
    }

    [Fact]
    public async Task A_pass_over_organizations_that_fails_is_logged_and_the_service_keeps_running()
    {
        var scopes = new FailingScopeFactory();
        var log = new ListLogger<OrganizationCleanupService>();
        using var reaper = new OrganizationCleanupService(scopes, log, Ready());

        await reaper.StartAsync(CancellationToken.None);
        await TestWait.UntilAsync(() => Task.FromResult(log.Messages.Any(m => m.Contains("Error during organization cleanup"))),
            "the failure is logged");

        Assert.False(reaper.ExecuteTask!.IsCompleted);
        await reaper.StopAsync(CancellationToken.None);
        Assert.Equal(1, scopes.Calls);
    }

    [Fact]
    public async Task Neither_service_runs_a_pass_until_the_schema_is_ready()
    {
        var signal = new MigrationCompletionSignal();
        var userScopes = new FailingScopeFactory();
        var organizationScopes = new FailingScopeFactory();
        using var users = new UserCleanupService(userScopes, new ListLogger<UserCleanupService>(), signal);
        using var organizations = new OrganizationCleanupService(organizationScopes, new ListLogger<OrganizationCleanupService>(), signal);

        await users.StartAsync(CancellationToken.None);
        await organizations.StartAsync(CancellationToken.None);
        await Task.Delay(300);
        var callsWhileWaiting = userScopes.Calls + organizationScopes.Calls;
        signal.SetCompleted();
        await TestWait.UntilAsync(() => Task.FromResult(userScopes.Calls > 0 && organizationScopes.Calls > 0), "both have run once ready");

        await users.StopAsync(CancellationToken.None);
        await organizations.StopAsync(CancellationToken.None);
        Assert.Equal(0, callsWhileWaiting);
    }

    [Fact]
    public async Task Stopping_before_the_schema_is_ready_ends_the_service_without_a_pass()
    {
        var scopes = new FailingScopeFactory();
        using var reaper = new UserCleanupService(scopes, new ListLogger<UserCleanupService>(), new MigrationCompletionSignal());

        await reaper.StartAsync(CancellationToken.None);
        await reaper.StopAsync(CancellationToken.None);

        Assert.True(reaper.ExecuteTask!.IsCompleted);
        Assert.Equal(0, scopes.Calls);
    }
}

/// <summary>Guards in services that the controllers in front of them make hard to reach.</summary>
public class ServiceGuardTests : IntegrationTestBase
{
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task A_blank_exchange_code_is_redeemed_by_nobody(string code)
    {
        string? redeemedBy = "unset";
        await Factory.WithScopeAsync(async services =>
            redeemedBy = await services.GetRequiredService<IOAuthExchangeCodeService>().RedeemAsync(code));

        Assert.Null(redeemedBy);
    }

    [Fact]
    public async Task Resending_an_invitation_that_does_not_exist_says_so()
    {
        (bool Success, string? Error) result = default;
        await Factory.WithScopeAsync(async services =>
            result = await services.GetRequiredService<InvitationService>().ResendInvitationEmailAsync("no-such-invitation", "someone"));

        Assert.False(result.Success);
        Assert.Equal("Invitation not found", result.Error);
    }
}
