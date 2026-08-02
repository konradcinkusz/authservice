namespace AuthService.Models;

/// <summary>
/// Tracks email sending attempts for organization invitations
/// </summary>
public class InvitationEmailAttempt
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string InvitationId { get; set; } = string.Empty;
    public DateTime AttemptedAt { get; set; } = DateTime.UtcNow;
    public bool IsSuccessful { get; set; }
    public string? ErrorMessage { get; set; }
    public string? ErrorDetails { get; set; }
    public int AttemptNumber { get; set; }

    // Navigation property
    public OrganizationInvitation Invitation { get; set; } = null!;
}
