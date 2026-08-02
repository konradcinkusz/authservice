using Microsoft.AspNetCore.Identity;

namespace AuthService.Models;

public class ApplicationUser : IdentityUser
{
    public string? ProfileImageUrl { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    // Soft delete properties
    public bool IsDeleted { get; set; } = false;
    public DateTime? DeletedAt { get; set; }
    public DateTime? ScheduledPermanentDeletionAt { get; set; }

    /// <summary>
    /// Default retention period in days before permanent deletion
    /// </summary>
    public const int DefaultRetentionDays = 30;

    // Navigation properties
    public ICollection<OrganizationMembership> OrganizationMemberships { get; set; } = new List<OrganizationMembership>();
}
