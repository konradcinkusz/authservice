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
/// says what happened and substitutes a placeholder for the secret.
/// </summary>
public class NoOpEmailService(
    IHostEnvironment _environment,
    ILogger<NoOpEmailService> _logger
) : IEmailService
{
    private const string Withheld = "(withheld — set SendGrid:ApiKey to deliver email, or run in Development to log it)";

    /// <summary>
    /// Returns the value to log in place of a credential: the real thing in Development,
    /// a placeholder everywhere else.
    ///
    /// Applied at the argument rather than by branching the log call, so each message keeps
    /// exactly one call site — duplicating the statement per environment doubles the surface
    /// that log-analysis tooling has to reason about, for no behavioural gain.
    /// </summary>
    private string Redact(string secret) => _environment.IsDevelopment() ? secret : Withheld;

    public Task SendInvitationEmailAsync(string toEmail, string organizationName, string invitationToken, string? inviterName)
    {
        _logger.LogWarning(
            "Email sending is not configured. Invitation email to {Email} for organization {Organization} was not sent. " +
            "Invitation token: {Token}. Inviter name: {Name}",
            toEmail, organizationName, Redact(invitationToken), inviterName ?? string.Empty);

        return Task.CompletedTask;
    }

    public Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string resetUrl)
    {
        _logger.LogWarning(
            "Email sending is not configured. Password reset email to {Email} was not sent. Reset URL: {ResetUrl}, reset token {Token}",
            toEmail, Redact(resetUrl), Redact(resetToken));

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

    public Task SendEmailVerificationAsync(string toEmail, string verificationToken, string verificationUrl)
    {
        _logger.LogWarning(
            "Email sending is not configured. Verification email to {Email} was not sent. " +
            "Verification URL: {VerificationUrl}, verification token: {Token}",
            toEmail, Redact(verificationUrl), Redact(verificationToken));

        return Task.CompletedTask;
    }
}
