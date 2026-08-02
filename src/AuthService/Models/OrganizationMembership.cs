namespace AuthService.Models;

public class OrganizationMembership
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string UserId { get; set; } = string.Empty;
    public string OrganizationId { get; set; } = string.Empty;
    public OrganizationRole Role { get; set; } = OrganizationRole.Member;
    public DateTime JoinedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public ApplicationUser User { get; set; } = null!;
    public Organization Organization { get; set; } = null!;
}

public enum OrganizationRole
{
    Member = 0,
    Admin = 1,
    Owner = 2
}
