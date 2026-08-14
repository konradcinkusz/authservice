using AuthService.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AuthService.Extensions;

/// <summary>
/// Readiness probe: reports healthy only once schema initialisation has finished *and* the
/// database answers.
///
/// Liveness (<c>/health</c>) and readiness (<c>/health/ready</c>) are deliberately different
/// questions. The process being up is not the same as the process being able to serve a
/// request, and pointing a platform health check at the former is how a machine with a
/// half-initialised — or permanently failed — database gets rolling traffic.
/// </summary>
public class DatabaseReadyHealthCheck(
    ApplicationDbContext _context,
    IMigrationCompletionSignal _migrationSignal
) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        if (!_migrationSignal.IsCompleted)
        {
            return HealthCheckResult.Unhealthy(
                "Database schema initialization has not completed yet.");
        }

        try
        {
            if (!await _context.Database.CanConnectAsync(cancellationToken))
                return HealthCheckResult.Unhealthy("Database is not reachable.");

            return HealthCheckResult.Healthy("Database schema initialized and reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database connectivity probe failed.", ex);
        }
    }
}
