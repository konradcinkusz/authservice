using Microsoft.Extensions.Logging;

namespace AuthService.Services;

/// <summary>
/// Logs email sends instead of dispatching them. Used when no email provider is configured
/// so the service still starts and functions (minus actual email delivery).
/// </summary>
public class NoOpEmailService(ILogger<NoOpEmailService> _logger) : IEmailService
{
    public Task SendInvitationEmailAsync(string toEmail, string organizationName, string invitationToken, string? inviterName)
    {
        _logger.LogWarning(
            "Email sending is not configured. Invitation email to {Email} for organization {Organization} was not sent. " +
            "Invitation token: {Token}. Inviter name: {Name}",
            toEmail, organizationName, invitationToken, inviterName ?? string.Empty);

        return Task.CompletedTask;
    }

    public Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string resetUrl)
    {
        _logger.LogWarning(
            "Email sending is not configured. Password reset email to {Email} was not sent. Reset URL: {ResetUrl}, reset token {Token}",
            toEmail, resetUrl, resetToken);

        return Task.CompletedTask;
    }

    public Task SendOAuthAccountLinkedEmailAsync(string toEmail, string providerName)
    {
        _logger.LogWarning(
            "Email sending is not configured. OAuth account linked notification to {Email} for provider {Provider} was not sent.",
            toEmail, providerName);

        return Task.CompletedTask;
    }

    public Task SendWelcomeEmailAsync(string toEmail, string userName)
    {
        _logger.LogWarning(
            "Email sending is not configured. Welcome email to {Email} for user {UserName} was not sent.",
            toEmail, userName);

        return Task.CompletedTask;
    }
}
