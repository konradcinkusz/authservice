using AuthService.Services;

namespace AuthService.Tests.Infrastructure;

/// <summary>
/// Stands in for the email provider and keeps what would have been sent, so a test can follow a
/// reset, verification or invitation link the way a user would. Registered by
/// <see cref="AuthServiceFactory"/> for every test; the real provider is never reached.
/// </summary>
public sealed class CapturingEmailService : IEmailService
{
    private readonly object _gate = new();
    private readonly List<SentEmail> _sent = [];

    /// <summary>Set to make the next sends throw, as a failing provider would.</summary>
    public Exception? FailWith { get; set; }

    public IReadOnlyList<SentEmail> Sent
    {
        get
        {
            lock (_gate)
                return [.. _sent];
        }
    }

    public IEnumerable<SentEmail> To(string email, EmailKind? kind = null) =>
        Sent.Where(e => string.Equals(e.To, email, StringComparison.OrdinalIgnoreCase)
                        && (kind is null || e.Kind == kind));

    public Task SendInvitationEmailAsync(string toEmail, string organizationName, string invitationToken, string? inviterName) =>
        Record(new SentEmail(EmailKind.Invitation, toEmail, invitationToken, null, organizationName, inviterName));

    public Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string resetUrl) =>
        Record(new SentEmail(EmailKind.PasswordReset, toEmail, resetToken, resetUrl, null, null));

    public Task SendOAuthAccountLinkedEmailAsync(string toEmail, string providerName) =>
        Record(new SentEmail(EmailKind.OAuthLinked, toEmail, null, null, providerName, null));

    public Task SendWelcomeEmailAsync(string toEmail, string userName) =>
        Record(new SentEmail(EmailKind.Welcome, toEmail, null, null, userName, null));

    public Task SendEmailVerificationAsync(string toEmail, string verificationToken, string verificationUrl) =>
        Record(new SentEmail(EmailKind.Verification, toEmail, verificationToken, verificationUrl, null, null));

    private Task Record(SentEmail email)
    {
        if (FailWith is { } failure)
            throw failure;

        lock (_gate)
            _sent.Add(email);

        return Task.CompletedTask;
    }
}

public enum EmailKind { Invitation, PasswordReset, OAuthLinked, Welcome, Verification }

/// <summary>One message the application tried to send, in the parts a test reads.</summary>
/// <param name="Kind">Which message it was.</param>
/// <param name="To">The address it was sent to.</param>
/// <param name="Token">The credential in the message, when it carries one.</param>
/// <param name="Url">The link in the message, when it carries one.</param>
/// <param name="Detail">The organization, provider or display name, depending on the kind.</param>
/// <param name="Inviter">Who sent the invitation, for an invitation.</param>
public sealed record SentEmail(EmailKind Kind, string To, string? Token, string? Url, string? Detail, string? Inviter);
