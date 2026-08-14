using AuthService.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthService.Extensions;

/// <summary>
/// Background service that initializes the database schema and seeds roles after the web
/// server starts. This ensures Kestrel is listening and health probes can pass while the
/// database is being prepared.
/// </summary>
public class MigrationBackgroundService(
    IServiceProvider serviceProvider,
    IMigrationCompletionSignal migrationSignal) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var scope = serviceProvider.CreateScope();
        var services = scope.ServiceProvider;
        var logger = services.GetRequiredService<ILogger<MigrationBackgroundService>>();

        const int maxAttempts = 10;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var mode = services.GetRequiredService<IConfiguration>().GetSchemaMode();
                logger.LogInformation("Initializing AuthService database in {Mode} mode (attempt {Attempt}/{Max})...",
                    mode, attempt, maxAttempts);

                await DatabaseProviderExtensions.InitializeDatabaseAsync(context, logger, mode, stoppingToken);

                migrationSignal.SetCompleted();

                logger.LogInformation("Starting database seeding...");
                try
                {
                    await DbSeeder.SeedAsync(services);
                    logger.LogInformation("Database seeding completed.");
                }
                catch (Exception seedEx)
                {
                    logger.LogWarning(seedEx, "Database seeding failed — the service will continue running.");
                }
                return;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                if (attempt == maxAttempts)
                {
                    logger.LogError(ex, "AuthService database initialization failed after {Max} attempts. The service will continue without a ready database.", maxAttempts);
                    return;
                }

                var delay = TimeSpan.FromSeconds(Math.Min(5 * attempt, 30));
                logger.LogWarning(ex, "AuthService database initialization failed (attempt {Attempt}/{Max}). Retrying in {Delay}s...", attempt, maxAttempts, delay.TotalSeconds);
                await Task.Delay(delay, stoppingToken);
            }
        }
    }
}
