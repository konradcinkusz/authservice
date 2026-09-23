using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthService.Data;
using AuthService.Extensions;
using AuthService.Models;
using OpenIddict.Abstractions;

namespace AuthService.Services;

/// <summary>
/// Background service that permanently deletes soft-deleted user accounts after their retention period expires.
/// Runs periodically to clean up accounts scheduled for permanent deletion, and prunes the
/// authorization server's expired and revoked rows on the same schedule.
/// </summary>
public class UserCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<UserCleanupService> _logger;
    private readonly IMigrationCompletionSignal _migrationSignal;
    private readonly TimeSpan _checkInterval = TimeSpan.FromHours(1);

    /// <summary>
    /// How long a revoked, redeemed or expired authorization-server row is kept before pruning:
    /// the library's own default. A redeemed refresh token is what lets a replay be detected, so
    /// it is not pruned the moment it is used.
    /// </summary>
    private static readonly TimeSpan AuthorizationServerRetention = TimeSpan.FromDays(14);

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

            try
            {
                await PruneAuthorizationServerAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "Error pruning the authorization server's expired rows");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }

        _logger.LogInformation("User cleanup service stopped");
    }

    internal async Task CleanupExpiredUsersAsync(CancellationToken cancellationToken)
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

                // The authorization server keeps the user id as a plain subject string with no
                // foreign key, so the cascade that clears RefreshTokens never reaches these rows.
                await DeleteAuthorizationServerRowsAsync(scope.ServiceProvider, user.Id, cancellationToken);

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

    /// <summary>Deletes every authorization and token the authorization server holds for the user.</summary>
    internal static async Task DeleteAuthorizationServerRowsAsync(IServiceProvider services, string userId, CancellationToken cancellationToken)
    {
        var authorizations = services.GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = services.GetRequiredService<IOpenIddictTokenManager>();

        // An authorization is deleted together with its tokens.
        var ownAuthorizations = new List<object>();
        await foreach (var authorization in authorizations.FindBySubjectAsync(userId, cancellationToken))
            ownAuthorizations.Add(authorization);
        foreach (var authorization in ownAuthorizations)
            await authorizations.DeleteAsync(authorization, cancellationToken);

        var ownTokens = new List<object>();
        await foreach (var token in tokens.FindBySubjectAsync(userId, cancellationToken))
            ownTokens.Add(token);
        foreach (var token in ownTokens)
            await tokens.DeleteAsync(token, cancellationToken);
    }

    internal async Task PruneAuthorizationServerAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var services = scope.ServiceProvider;

        var threshold = DateTimeOffset.UtcNow - AuthorizationServerRetention;
        var tokens = await services.GetRequiredService<IOpenIddictTokenManager>().PruneAsync(threshold, cancellationToken);
        var authorizations = await services.GetRequiredService<IOpenIddictAuthorizationManager>().PruneAsync(threshold, cancellationToken);

        // An interaction lives ten minutes; one an hour past its expiry is litter.
        var cutoff = DateTime.UtcNow.AddHours(-1);
        var interactions = await services.GetRequiredService<ApplicationDbContext>().AuthorizationInteractions
            .Where(i => i.ExpiresAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);

        if (tokens + authorizations + interactions > 0)
        {
            _logger.LogInformation(
                "Pruned {Tokens} token(s), {Authorizations} authorization(s) and {Interactions} interaction(s) from the authorization server",
                tokens, authorizations, interactions);
        }
    }
}
