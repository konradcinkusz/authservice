using System.ComponentModel.DataAnnotations;

namespace AuthService.DTOs;

/// <summary>
/// Request model for creating a new organization
/// </summary>
public record CreateOrganizationRequest(
    /// <summary>Organization name</summary>
    [Required(ErrorMessage = "Organization name is required")]
    [StringLength(100, MinimumLength = 1, ErrorMessage = "Organization name must be between 1 and 100 characters")]
    string Name,

    /// <summary>Organization description (optional)</summary>
    [StringLength(500, ErrorMessage = "Description cannot exceed 500 characters")]
    string? Description = null,

    /// <summary>URL to organization's image/logo (optional)</summary>
    [Url(ErrorMessage = "Invalid image URL format")]
    [StringLength(500, ErrorMessage = "Image URL cannot exceed 500 characters")]
    string? ImageUrl = null
);

/// <summary>
/// Organization information with membership details
/// </summary>
public record OrganizationDto(
    /// <summary>Organization's unique identifier</summary>
    string Id,
    /// <summary>Organization name</summary>
    string Name,
    /// <summary>Organization description</summary>
    string? Description,
    /// <summary>URL to organization's image/logo</summary>
    string? ImageUrl,
    /// <summary>Organization creation timestamp</summary>
    DateTime CreatedAt,
    /// <summary>Total number of members in the organization</summary>
    int MemberCount,
    /// <summary>Current user's role in the organization</summary>
    string UserRole,
    /// <summary>Whether the organization is marked for deletion</summary>
    bool IsDeleted = false,
    /// <summary>When the organization will be permanently deleted (if marked for deletion)</summary>
    DateTime? ScheduledPermanentDeletionAt = null
);

/// <summary>
/// Detailed organization information including full member list
/// </summary>
public record OrganizationDetailDto(
    /// <summary>Organization's unique identifier</summary>
    string Id,
    /// <summary>Organization name</summary>
    string Name,
    /// <summary>Organization description</summary>
    string? Description,
    /// <summary>URL to organization's image/logo</summary>
    string? ImageUrl,
    /// <summary>Organization creation timestamp</summary>
    DateTime CreatedAt,
    /// <summary>List of all organization members with their roles</summary>
    List<OrganizationMemberDto> Members
);

/// <summary>
/// Member information within an organization
/// </summary>
public record OrganizationMemberDto(
    /// <summary>User's unique identifier</summary>
    string UserId,
    /// <summary>User's email address</summary>
    string Email,
    /// <summary>User's display name</summary>
    string? UserName,
    /// <summary>URL to user's profile image</summary>
    string? ProfileImageUrl,
    /// <summary>User's role in the organization (Owner, Admin, Member)</summary>
    string Role,
    /// <summary>Timestamp when user joined the organization</summary>
    DateTime JoinedAt
);

/// <summary>
/// Request model for inviting a user to an organization
/// </summary>
public record InviteMemberRequest(
    /// <summary>Email address of the user to invite</summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
    string Email,

    /// <summary>Role to assign (Owner, Admin, or Member). Default is Member</summary>
    [RegularExpression("^(Owner|Admin|Member)$", ErrorMessage = "Role must be Owner, Admin, or Member")]
    string Role = "Member"
);

/// <summary>
/// Organization invitation details
/// </summary>
public record InvitationDto(
    /// <summary>Invitation's unique identifier</summary>
    string Id,
    /// <summary>Organization's unique identifier</summary>
    string OrganizationId,
    /// <summary>Organization name</summary>
    string OrganizationName,
    /// <summary>Email address of the invitee</summary>
    string Email,
    /// <summary>Role to be assigned when invitation is accepted</summary>
    string Role,
    /// <summary>Invitation creation timestamp</summary>
    DateTime CreatedAt,
    /// <summary>Invitation expiration timestamp</summary>
    DateTime ExpiresAt,
    /// <summary>Whether the invitation has been accepted</summary>
    bool IsAccepted,
    /// <summary>Email delivery status (Pending, Sent, Failed)</summary>
    string EmailStatus,
    /// <summary>Number of email sending attempts</summary>
    int EmailAttemptCount,
    /// <summary>Timestamp of last email sending attempt</summary>
    DateTime? LastEmailAttemptAt,
    /// <summary>Timestamp when next retry is scheduled</summary>
    DateTime? NextRetryAt,
    /// <summary>Last error message if email sending failed</summary>
    string? LastEmailError
);

/// <summary>
/// Request model for accepting an organization invitation
/// </summary>
public record AcceptInvitationRequest(
    /// <summary>Invitation token from the invitation email</summary>
    [Required(ErrorMessage = "Invitation token is required")]
    [StringLength(100, ErrorMessage = "Invalid token format")]
    string Token
);

/// <summary>
/// Request model for updating a member's role
/// </summary>
public record UpdateMemberRoleRequest(
    /// <summary>New role to assign (Owner, Admin, or Member)</summary>
    [Required(ErrorMessage = "Role is required")]
    [RegularExpression("^(Owner|Admin|Member)$", ErrorMessage = "Role must be Owner, Admin, or Member")]
    string Role
);

/// <summary>
/// Request model for transferring organization ownership to another existing member
/// </summary>
public record TransferOwnershipRequest(
    /// <summary>User id of the member who becomes the new Owner. Must already be a member.</summary>
    [Required(ErrorMessage = "toUserId is required")]
    string ToUserId,

    /// <summary>
    /// Whether the outgoing owner keeps Admin (default) or steps down to Member.
    /// </summary>
    bool RetainAdminRole = true
);
