using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace AuthService.Services;

public class SendGridEmailService(IConfiguration _configuration, ILogger<SendGridEmailService> _logger) : IEmailService
{
    private string AppName => _configuration["App:Name"] ?? "your account";

    private ISendGridClient CreateClient()
    {
        var apiKey = _configuration["SendGrid:ApiKey"]
            ?? throw new InvalidOperationException("SendGrid:ApiKey is not configured.");
        return NewClient(apiKey);
    }

    /// <summary>
    /// A message SendGrid refused was not sent, and the caller is told so: callers record what became
    /// of an email (an invitation's delivery status and the pause before a resend) and read a call
    /// that returns as one that worked. The provider's own words stay in the log; this message can
    /// reach people who administer an organization but not this deployment.
    /// </summary>
    private static InvalidOperationException Refused(HttpStatusCode status) =>
        new($"The email provider refused the message (HTTP {(int)status}).");

    /// <summary>The client that talks to SendGrid. Replaced in tests so that no message leaves the machine.</summary>
    protected virtual ISendGridClient NewClient(string apiKey) => new SendGridClient(apiKey);

    /// <summary>
    /// Text placed in the HTML part of a message. Some of it is typed by users: an organization's
    /// name is whatever its creator chose, and the email carrying it comes from this service's own
    /// address, so unencoded it is a way to put a stranger's markup and links in front of the recipient.
    /// </summary>
    private static string Html(string? text) => WebUtility.HtmlEncode(text ?? string.Empty);

    private EmailAddress GetFromAddress()
    {
        var from = _configuration["SendGrid:FromEmail"]
            ?? throw new InvalidOperationException("SendGrid:FromEmail is not configured.");
        var name = _configuration["SendGrid:FromName"] ?? AppName;
        return new EmailAddress(from, name);
    }

    public async Task SendInvitationEmailAsync(string toEmail, string organizationName, string invitationToken, string? inviterName)
    {
        var client = CreateClient();
        var from = GetFromAddress();
        var to = new EmailAddress(toEmail);
        var subject = $"You've been invited to join {organizationName}";
        var inviter = string.IsNullOrWhiteSpace(inviterName) ? "A team member" : inviterName;
        var plainText = $"{inviter} has invited you to join {organizationName}.\n\nYour invitation token: {invitationToken}";
        var html = $"<p><strong>{Html(inviter)}</strong> has invited you to join <strong>{Html(organizationName)}</strong>.</p>" +
                   $"<p>Your invitation token: <code>{Html(invitationToken)}</code></p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send invitation email to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
            throw Refused(response.StatusCode);
        }
        else
        {
            _logger.LogInformation("Invitation email sent to {Email} for organization {Organization}", toEmail, organizationName);
        }
    }

    public async Task SendPasswordResetEmailAsync(string toEmail, string resetToken, string resetUrl)
    {
        var client = CreateClient();
        var from = GetFromAddress();
        var to = new EmailAddress(toEmail);
        const string subject = "Reset your password";
        var plainText = $"Click the link below to reset your password:\n\n{resetUrl}\n\nIf you did not request a password reset, please ignore this email.";
        var html = $"<p>Click the link below to reset your password:</p>" +
                   $"<p><a href=\"{Html(resetUrl)}\">Reset Password</a></p>" +
                   $"<p>If you did not request a password reset, please ignore this email.</p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send password reset email to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
            throw Refused(response.StatusCode);
        }
        else
        {
            _logger.LogInformation("Password reset email sent to {Email}", toEmail);
        }
    }

    public async Task SendOAuthAccountLinkedEmailAsync(string toEmail, string providerName)
    {
        var client = CreateClient();
        var from = GetFromAddress();
        var to = new EmailAddress(toEmail);
        var subject = $"Your account was linked to {providerName}";
        var plainText = $"Your {AppName} account has been linked to {providerName}.\n\nIf you did not do this, please contact support immediately.";
        var html = $"<p>Your <strong>{Html(AppName)}</strong> account has been linked to <strong>{Html(providerName)}</strong>.</p>" +
                   $"<p>If you did not do this, please contact support immediately.</p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send OAuth linked notification to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
            throw Refused(response.StatusCode);
        }
        else
        {
            _logger.LogInformation("OAuth account linked notification sent to {Email} for provider {Provider}", toEmail, providerName);
        }
    }

    public async Task SendEmailVerificationAsync(string toEmail, string verificationToken, string verificationUrl)
    {
        var client = CreateClient();
        var from = GetFromAddress();
        var to = new EmailAddress(toEmail);
        var subject = $"Verify your email address for {AppName}";
        var plainText = $"Confirm this address to finish setting up your {AppName} account:\n\n{verificationUrl}\n\n" +
                        "If you did not create this account, you can safely ignore this email.";
        var html = $"<p>Confirm this address to finish setting up your <strong>{Html(AppName)}</strong> account:</p>" +
                   $"<p><a href=\"{Html(verificationUrl)}\">Verify email address</a></p>" +
                   $"<p>If you did not create this account, you can safely ignore this email.</p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send verification email to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
            throw Refused(response.StatusCode);
        }
        else
        {
            _logger.LogInformation("Verification email sent to {Email}", toEmail);
        }
    }

    public async Task SendWelcomeEmailAsync(string toEmail, string userName)
    {
        var client = CreateClient();
        var from = GetFromAddress();
        var to = new EmailAddress(toEmail);
        var subject = $"Welcome to {AppName}!";
        var plainText = $"Hi {userName},\n\nWelcome to {AppName}! Your account has been created successfully.\n\nIf you did not create this account, please contact support immediately.";
        var html = $"<p>Hi <strong>{Html(userName)}</strong>,</p>" +
                   $"<p>Welcome to <strong>{Html(AppName)}</strong>! Your account has been created successfully.</p>" +
                   $"<p>If you did not create this account, please contact support immediately.</p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send welcome email to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
            throw Refused(response.StatusCode);
        }
        else
        {
            _logger.LogInformation("Welcome email sent to {Email}", toEmail);
        }
    }
}
