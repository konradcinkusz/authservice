namespace AuthService.Services;

/// <summary>
/// Interface for email sending operations
/// </summary>
public interface IEmailService
{
    /// <summary>
    /// Sends an invitation email to a user
    /// </summary>
    /// <param name="toEmail">Recipient email address</param>
    /// <param name="organizationName">Name of the organization</param>
    /// <param name="invitationToken">Unique invitation token</param>
    /// <param name="inviterName">Name of the person who sent the invitation</param>
    Task SendInvitationEmailAsync(string toEmail, string organizationName, string invitationToken, string? inviterName);

    /// <summary>
    /// Sends a password reset email to a user
    /// </summary>
    /// <param name="toEmail">Recipient email address</param>
    /// <param name="resetToken">Password reset token</param>
    /// <param name="resetUrl">Full URL for the password reset page</param>
    Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string resetUrl);

    /// <summary>
    /// Sends a security notification email when an existing account is linked to an OAuth provider
    /// </summary>
    /// <param name="toEmail">Recipient email address</param>
    /// <param name="providerName">Name of the OAuth provider (e.g. Google, GitHub)</param>
    Task SendOAuthAccountLinkedEmailAsync(string toEmail, string providerName);

    /// <summary>
    /// Sends a welcome email after a new account is created (email/password or OAuth)
    /// </summary>
    /// <param name="toEmail">Recipient email address</param>
    /// <param name="userName">Display name used in the greeting</param>
    Task SendWelcomeEmailAsync(string toEmail, string userName);

    /// <summary>
    /// Sends an address-verification email for a newly registered account
    /// </summary>
    /// <param name="toEmail">Recipient email address</param>
    /// <param name="verificationToken">Identity-generated email confirmation token</param>
    /// <param name="verificationUrl">Full frontend URL that completes the verification</param>
    Task SendEmailVerificationAsync(string toEmail, string verificationToken, string verificationUrl);
}

/// <summary>
/// Whether this deployment can actually deliver email. Registered as a singleton alongside
/// the chosen <see cref="IEmailService"/> so features that are meaningless without delivery
/// (email verification above all) can default themselves off instead of locking users out.
/// </summary>
/// <param name="CanSendEmail">True when a real email provider is configured.</param>
public record EmailCapabilities(bool CanSendEmail);
