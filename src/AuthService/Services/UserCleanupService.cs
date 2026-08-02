using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthService.Extensions;
using AuthService.Models;

namespace AuthService.Services;

/// <summary>
/// Background service that permanently deletes soft-deleted user accounts after their retention period expires.
/// Runs periodically to clean up accounts scheduled for permanent deletion.
/// </summary>
public class UserCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<UserCleanupService> _logger;
    private readonly IMigrationCompletionSignal _migrationSignal;
    private readonly TimeSpan _checkInterval = TimeSpan.FromHours(1);

    public UserCleanupService(
        IServiceScopeFactory scopeFactory,
        ILogger<UserCleanupService> logger,
        IMigrationCompletionSignal migrationSignal)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _migrationSignal = migrationSignal;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("User cleanup service started");

        await _migrationSignal.WaitAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupExpiredUsersAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user account cleanup");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }

        _logger.LogInformation("User cleanup service stopped");
    }

    private async Task CleanupExpiredUsersAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();

        var now = DateTime.UtcNow;

        var expiredUsers = await userManager.Users
            .Where(u => u.IsDeleted &&
                        u.ScheduledPermanentDeletionAt != null &&
                        u.ScheduledPermanentDeletionAt <= now)
            .ToListAsync(cancellationToken);

        if (expiredUsers.Count == 0)
        {
            _logger.LogDebug("No user accounts to permanently delete");
            return;
        }

        _logger.LogInformation("Found {Count} user accounts to permanently delete", expiredUsers.Count);

        foreach (var user in expiredUsers)
        {
            try
            {
                // Ensure all refresh tokens are revoked before deleting
                await tokenService.RevokeRefreshTokensAsync(user.Id);

                var result = await userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    _logger.LogInformation(
                        "Permanently deleted user account {UserId} (Email: {Email}). " +
                        "Was soft-deleted at {DeletedAt}",
                        user.Id, user.Email, user.DeletedAt);
                }
                else
                {
                    _logger.LogWarning(
                        "Failed to permanently delete user {UserId}: {Errors}",
                        user.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to permanently delete user account {UserId}", user.Id);
            }
        }
    }
}
