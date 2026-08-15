using System.Security.Cryptography;

namespace AuthService.Models;

/// <summary>
/// Status of the invitation email delivery
/// </summary>
public enum InvitationEmailStatus
{
    Pending,        // Email not yet sent
    Sent,           // Email sent successfully
    Failed          // Email failed to send - manual resend required
}

public class OrganizationInvitation
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string OrganizationId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public OrganizationRole Role { get; set; } = OrganizationRole.Member;
    public string InvitedByUserId { get; set; } = string.Empty;
    public string Token { get; set; } = GenerateSecureToken();
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddDays(7);
    public bool IsAccepted { get; set; }
    public DateTime? AcceptedAt { get; set; }

    // Email sending tracking
    public InvitationEmailStatus EmailStatus { get; set; } = InvitationEmailStatus.Pending;
    public DateTime? LastEmailAttemptAt { get; set; }
    public DateTime? NextRetryAt { get; set; }
    public int EmailAttemptCount { get; set; } = 0;
    public string? LastEmailError { get; set; }

    // Navigation properties
    public Organization Organization { get; set; } = null!;
    public ICollection<InvitationEmailAttempt> EmailAttempts { get; set; } = new List<InvitationEmailAttempt>();

    /// <summary>
    /// Generates a cryptographically secure random token for invitations
    /// </summary>
    private static string GenerateSecureToken()
    {
        var randomBytes = new byte[32]; // 256 bits of randomness
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        // Convert to URL-safe Base64
        return Convert.ToBase64String(randomBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }
}
