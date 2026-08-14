using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthService.Services;

/// <summary>
/// Logs email sends instead of dispatching them. Used when no email provider is configured
/// so the service still starts and functions (minus actual email delivery).
///
/// Tokens are only written to the log in Development. They are bearer credentials — a
/// password-reset token in a log file is a password-reset token in whatever aggregates that
/// log — and this implementation is the *default* whenever SendGrid is unconfigured, which
/// includes production deployments that simply never set it. Outside Development the log
/// says what happened and withholds the secret.
/// </summary>
public class NoOpEmailService(
    IHostEnvironment _environment,
    ILogger<NoOpEmailService> _logger
) : IEmailService
{
    private bool IncludeTokens => _environment.IsDevelopment();

    private const string WithheldNotice =
        "The token is withheld outside Development; configure SendGrid:ApiKey to deliver email.";

    public Task SendInvitationEmailAsync(string toEmail, string organizationName, string invitationToken, string? inviterName)
    {
        if (IncludeTokens)
        {
            _logger.LogWarning(
                "Email sending is not configured. Invitation email to {Email} for organization {Organization} was not sent. " +
                "Invitation token: {Token}. Inviter name: {Name}",
                toEmail, organizationName, invitationToken, inviterName ?? string.Empty);
        }
        else
        {
            _logger.LogWarning(
                "Email sending is not configured. Invitation email to {Email} for organization {Organization} was not sent. {Notice}",
                toEmail, organizationName, WithheldNotice);
        }

        return Task.CompletedTask;
    }

    public Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string resetUrl)
    {
        if (IncludeTokens)
        {
            _logger.LogWarning(
                "Email sending is not configured. Password reset email to {Email} was not sent. Reset URL: {ResetUrl}, reset token {Token}",
                toEmail, resetUrl, resetToken);
        }
        else
        {
            _logger.LogWarning(
                "Email sending is not configured. Password reset email to {Email} was not sent. {Notice}",
                toEmail, WithheldNotice);
        }

        return Task.CompletedTask;
    }

    public Task SendOAuthAccountLinkedEmailAsync(string toEmail, string providerName)
    {
        // Carries no credential, so it is safe to log in full anywhere.
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

    public Task SendEmailVerificationAsync(string toEmail, string verificationToken, string verificationUrl)
    {
        if (IncludeTokens)
        {
            _logger.LogWarning(
                "Email sending is not configured. Verification email to {Email} was not sent. " +
                "Verification URL: {VerificationUrl}, verification token: {Token}",
                toEmail, verificationUrl, verificationToken);
        }
        else
        {
            _logger.LogWarning(
                "Email sending is not configured. Verification email to {Email} was not sent. {Notice}",
                toEmail, WithheldNotice);
        }

        return Task.CompletedTask;
    }
}
