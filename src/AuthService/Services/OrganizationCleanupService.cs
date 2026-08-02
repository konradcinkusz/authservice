using Microsoft.EntityFrameworkCore;
using AuthService.Data;
using AuthService.Extensions;

namespace AuthService.Services;

/// <summary>
/// Background service that permanently deletes soft-deleted organizations after their retention period expires.
/// Runs periodically to clean up organizations scheduled for permanent deletion.
/// </summary>
public class OrganizationCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<OrganizationCleanupService> _logger;
    private readonly IMigrationCompletionSignal _migrationSignal;
    private readonly TimeSpan _checkInterval = TimeSpan.FromHours(1);

    public OrganizationCleanupService(
        IServiceScopeFactory scopeFactory,
        ILogger<OrganizationCleanupService> logger,
        IMigrationCompletionSignal migrationSignal)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _migrationSignal = migrationSignal;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Organization cleanup service started");

        await _migrationSignal.WaitAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupExpiredOrganizationsAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during organization cleanup");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }

        _logger.LogInformation("Organization cleanup service stopped");
    }

    private async Task CleanupExpiredOrganizationsAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var now = DateTime.UtcNow;

        var expiredOrganizations = await context.Organizations
            .IgnoreQueryFilters()
            .Where(o => o.IsDeleted && o.ScheduledPermanentDeletionAt != null && o.ScheduledPermanentDeletionAt <= now)
            .ToListAsync(cancellationToken);

        if (expiredOrganizations.Count == 0)
        {
            _logger.LogDebug("No organizations to permanently delete");
            return;
        }

        _logger.LogInformation("Found {Count} organizations to permanently delete", expiredOrganizations.Count);

        foreach (var organization in expiredOrganizations)
        {
            try
            {
                context.Organizations.Remove(organization);
                await context.SaveChangesAsync(cancellationToken);

                _logger.LogInformation(
                    "Permanently deleted organization {OrganizationId} (Name: {OrganizationName}). " +
                    "Was deleted at {DeletedAt} by user {DeletedByUserId}",
                    organization.Id,
                    organization.Name,
                    organization.DeletedAt,
                    organization.DeletedByUserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to permanently delete organization {OrganizationId}",
                    organization.Id);
            }
        }
    }
}
