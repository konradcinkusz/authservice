using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthService.Services;

/// <summary>
/// Service for managing organization invitations and email sending with retry logic
/// </summary>
public class InvitationService
{
    private readonly ApplicationDbContext _context;
    private readonly IEmailService _emailService;
    private readonly ILogger<InvitationService> _logger;

    // Cooldown periods before allowing manual resend attempts
    private static readonly TimeSpan[] RetryCooldowns = new[]
    {
        TimeSpan.FromMinutes(10),  // After 1st failure, wait 10 minutes before allowing resend
        TimeSpan.FromHours(1),      // After 2nd failure, wait 1 hour before allowing resend
        TimeSpan.FromHours(24)      // After 3rd+ failure, wait 24 hours before allowing resend
    };

    public InvitationService(
        ApplicationDbContext context,
        IEmailService emailService,
        ILogger<InvitationService> logger)
    {
        _context = context;
        _emailService = emailService;
        _logger = logger;
    }

    /// <summary>
    /// Attempts to send invitation email and tracks the attempt
    /// </summary>
    public async Task<(bool success, string? errorMessage)> SendInvitationEmailAsync(
        OrganizationInvitation invitation,
        string organizationName,
        string? inviterName)
    {
        var attemptNumber = invitation.EmailAttemptCount + 1;

        var emailAttempt = new InvitationEmailAttempt
        {
            InvitationId = invitation.Id,
            AttemptNumber = attemptNumber,
            AttemptedAt = DateTime.UtcNow
        };

        try
        {
            await _emailService.SendInvitationEmailAsync(
                invitation.Email,
                organizationName,
                invitation.Token,
                inviterName
            );

            // Success
            emailAttempt.IsSuccessful = true;
            invitation.EmailStatus = InvitationEmailStatus.Sent;
            invitation.LastEmailAttemptAt = DateTime.UtcNow;
            invitation.EmailAttemptCount = attemptNumber;
            invitation.NextRetryAt = null;
            invitation.LastEmailError = null;

            _context.InvitationEmailAttempts.Add(emailAttempt);
            await _context.SaveChangesAsync();

            _logger.LogInformation(
                "Successfully sent invitation email to {Email} for invitation {InvitationId} (attempt {AttemptNumber})",
                invitation.Email, invitation.Id, attemptNumber);

            return (true, null);
        }
        catch (Exception ex)
        {
            // Failure
            var errorMessage = ex.Message;
            var errorDetails = ex.ToString();

            emailAttempt.IsSuccessful = false;
            emailAttempt.ErrorMessage = errorMessage;
            emailAttempt.ErrorDetails = errorDetails;

            invitation.LastEmailAttemptAt = DateTime.UtcNow;
            invitation.EmailAttemptCount = attemptNumber;
            invitation.LastEmailError = errorMessage;
            invitation.EmailStatus = InvitationEmailStatus.Failed;

            // Set cooldown period before next manual resend is allowed
            var cooldownIndex = Math.Min(attemptNumber - 1, RetryCooldowns.Length - 1);
            var cooldown = RetryCooldowns[cooldownIndex];
            invitation.NextRetryAt = DateTime.UtcNow.Add(cooldown);

            _logger.LogError(
                "Failed to send invitation email to {Email} for invitation {InvitationId} (attempt {AttemptNumber}). " +
                "Manual resend available after {NextRetryAt}. Error: {ErrorMessage}",
                invitation.Email, invitation.Id, attemptNumber, invitation.NextRetryAt, errorMessage);

            _context.InvitationEmailAttempts.Add(emailAttempt);
            await _context.SaveChangesAsync();

            return (false, errorMessage);
        }
    }

    /// <summary>
    /// Manually resends an invitation email (bypasses retry schedule)
    /// </summary>
    public async Task<(bool success, string? errorMessage)> ResendInvitationEmailAsync(string invitationId, string? inviterName)
    {
        var invitation = await _context.OrganizationInvitations
            .Include(i => i.Organization)
            .FirstOrDefaultAsync(i => i.Id == invitationId);

        if (invitation == null)
        {
            return (false, "Invitation not found");
        }

        if (invitation.IsAccepted)
        {
            return (false, "Invitation has already been accepted");
        }

        if (invitation.ExpiresAt < DateTime.UtcNow)
        {
            return (false, "Invitation has expired");
        }

        // Check if invitation is already successfully sent recently (within 5 minutes)
        if (invitation.EmailStatus == InvitationEmailStatus.Sent &&
            invitation.LastEmailAttemptAt.HasValue &&
            DateTime.UtcNow - invitation.LastEmailAttemptAt.Value < TimeSpan.FromMinutes(5))
        {
            return (false, "Invitation email was recently sent successfully. Please wait before resending.");
        }

        // Check if we're within the cooldown period after a failure
        if (invitation.EmailStatus == InvitationEmailStatus.Failed &&
            invitation.NextRetryAt.HasValue &&
            DateTime.UtcNow < invitation.NextRetryAt.Value)
        {
            var waitTime = invitation.NextRetryAt.Value - DateTime.UtcNow;
            var waitMinutes = (int)waitTime.TotalMinutes;
            var waitHours = (int)waitTime.TotalHours;

            string waitMessage = waitHours > 0
                ? $"Please wait {waitHours} hour(s) before resending"
                : $"Please wait {waitMinutes} minute(s) before resending";

            return (false, $"Too many recent attempts. {waitMessage}.");
        }

        return await SendInvitationEmailAsync(invitation, invitation.Organization.Name, inviterName);
    }

    /// <summary>
    /// Gets all invitations for an organization with their email status
    /// </summary>
    public async Task<List<OrganizationInvitation>> GetOrganizationInvitationsAsync(string organizationId)
    {
        return await _context.OrganizationInvitations
            .Include(i => i.Organization)
            .Include(i => i.EmailAttempts.OrderByDescending(ea => ea.AttemptedAt))
            .Where(i => i.OrganizationId == organizationId && !i.IsAccepted && i.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(i => i.CreatedAt)
            .ToListAsync();
    }
}
