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
        return new SendGridClient(apiKey);
    }

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
        var html = $"<p><strong>{inviter}</strong> has invited you to join <strong>{organizationName}</strong>.</p>" +
                   $"<p>Your invitation token: <code>{invitationToken}</code></p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send invitation email to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
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
                   $"<p><a href=\"{resetUrl}\">Reset Password</a></p>" +
                   $"<p>If you did not request a password reset, please ignore this email.</p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send password reset email to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
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
        var html = $"<p>Your <strong>{AppName}</strong> account has been linked to <strong>{providerName}</strong>.</p>" +
                   $"<p>If you did not do this, please contact support immediately.</p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send OAuth linked notification to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
        }
        else
        {
            _logger.LogInformation("OAuth account linked notification sent to {Email} for provider {Provider}", toEmail, providerName);
        }
    }

    public async Task SendWelcomeEmailAsync(string toEmail, string userName)
    {
        var client = CreateClient();
        var from = GetFromAddress();
        var to = new EmailAddress(toEmail);
        var subject = $"Welcome to {AppName}!";
        var plainText = $"Hi {userName},\n\nWelcome to {AppName}! Your account has been created successfully.\n\nIf you did not create this account, please contact support immediately.";
        var html = $"<p>Hi <strong>{userName}</strong>,</p>" +
                   $"<p>Welcome to <strong>{AppName}</strong>! Your account has been created successfully.</p>" +
                   $"<p>If you did not create this account, please contact support immediately.</p>";

        var msg = MailHelper.CreateSingleEmail(from, to, subject, plainText, html);
        var response = await client.SendEmailAsync(msg);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync();
            _logger.LogError("SendGrid failed to send welcome email to {Email}. Status: {Status}. Body: {Body}",
                toEmail, response.StatusCode, body);
        }
        else
        {
            _logger.LogInformation("Welcome email sent to {Email}", toEmail);
        }
    }
}
