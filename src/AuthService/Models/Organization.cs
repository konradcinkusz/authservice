namespace AuthService.Models;

/// <summary>
/// A tenant boundary that groups users together. Users join an organization via
/// <see cref="OrganizationMembership"/> and can hold different roles within it.
/// </summary>
public class Organization
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? ImageUrl { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string CreatedByUserId { get; set; } = string.Empty;

    // Soft delete properties
    public bool IsDeleted { get; set; } = false;
    public DateTime? DeletedAt { get; set; }
    public string? DeletedByUserId { get; set; }
    public DateTime? ScheduledPermanentDeletionAt { get; set; }

    /// <summary>
    /// Default retention period in days before permanent deletion
    /// </summary>
    public const int DefaultRetentionDays = 30;

    // Navigation property
    public ICollection<OrganizationMembership> Members { get; set; } = new List<OrganizationMembership>();
}
