using System.ComponentModel.DataAnnotations;

namespace AuthService.DTOs;

/// <summary>
/// Summary info for a user in the admin user list
/// </summary>
public record AdminUserSummaryDto(
    string Id,
    string Email,
    string? UserName,
    string? ProfileImageUrl,
    DateTime CreatedAt,
    DateTime? LastLoginAt,
    IReadOnlyList<string> Roles
);

/// <summary>
/// Full user details for the admin user detail view
/// </summary>
public record AdminUserDetailDto(
    string Id,
    string Email,
    string? UserName,
    string? ProfileImageUrl,
    DateTime CreatedAt,
    DateTime? LastLoginAt,
    IReadOnlyList<string> Roles,
    bool IsLockedOut,
    DateTimeOffset? LockoutEnd,
    int AccessFailedCount,
    bool EmailConfirmed,
    IReadOnlyList<AdminOrgMembershipDto> Organizations
);

/// <summary>
/// Organization membership summary for the admin user detail view
/// </summary>
public record AdminOrgMembershipDto(
    string OrgId,
    string OrgName,
    string? OrgImageUrl,
    string Role
);

/// <summary>
/// Platform-wide statistics shown on the admin dashboard overview
/// </summary>
public record AdminStatsDto(
    int TotalUsers,
    int NewUsersLast7Days,
    int NewUsersLast30Days,
    int TotalOrganizations
);

/// <summary>
/// Paginated list response for users
/// </summary>
public record AdminUserListResponse(
    IReadOnlyList<AdminUserSummaryDto> Users,
    int TotalCount,
    int Page,
    int PageSize,
    int TotalPages
);

/// <summary>
/// Request to assign a role to a user
/// </summary>
public record AdminAssignRoleRequest(
    [Required] string Role
);

/// <summary>
/// Request to lock a user account.
/// </summary>
public record AdminLockUserRequest(
    /// <summary>
    /// When the lock expires. Null means indefinite — the account stays locked until an
    /// admin unlocks it.
    /// </summary>
    DateTimeOffset? Until
);

/// <summary>
/// A single security audit record.
/// </summary>
public record AuditEventDto(
    Guid Id,
    DateTime OccurredAt,
    string Action,
    string? ActorUserId,
    string? ActorEmail,
    string? TargetUserId,
    string? TargetOrganizationId,
    string? IpAddress,
    string? UserAgent,
    bool Succeeded,
    /// <summary>Action-specific JSON detail (old/new role, lockout end, provider name...)</summary>
    string? Metadata
);

/// <summary>
/// Paginated list response for audit events
/// </summary>
public record AuditEventListResponse(
    IReadOnlyList<AuditEventDto> Events,
    int TotalCount,
    int Page,
    int PageSize,
    int TotalPages
);

/// <summary>
/// Summary info for a soft-deleted user in the admin deleted-users list
/// </summary>
public record DeletedUserSummaryDto(
    string Id,
    string Email,
    string? UserName,
    string? ProfileImageUrl,
    DateTime CreatedAt,
    DateTime DeletedAt,
    DateTime ScheduledPermanentDeletionAt
);

/// <summary>
/// Paginated list response for soft-deleted users
/// </summary>
public record DeletedUserListResponse(
    IReadOnlyList<DeletedUserSummaryDto> Users,
    int TotalCount
);
