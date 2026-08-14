using System.ComponentModel.DataAnnotations;

namespace AuthService.Models;

/// <summary>
/// An append-only record of a security-relevant action, in the same spirit as
/// <see cref="UserConsent"/>: queryable, durable, and independent of log shipping.
///
/// Rows are never updated or deleted by application code. Purging is the operator's
/// decision (see <c>Audit:RetentionDays</c>).
/// </summary>
public class AuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    /// <summary>Dotted action name — see <see cref="AuditAction"/>.</summary>
    [Required]
    [MaxLength(64)]
    public string Action { get; set; } = string.Empty;

    /// <summary>The user who performed the action. Null for system/background actions.</summary>
    [MaxLength(450)]
    public string? ActorUserId { get; set; }

    /// <summary>Actor's email captured at the time of the event, so the record survives account deletion.</summary>
    [MaxLength(256)]
    public string? ActorEmail { get; set; }

    /// <summary>The user the action was performed on, when applicable.</summary>
    [MaxLength(450)]
    public string? TargetUserId { get; set; }

    /// <summary>The organization the action was performed on, when applicable.</summary>
    [MaxLength(450)]
    public string? TargetOrganizationId { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }

    [MaxLength(512)]
    public string? UserAgent { get; set; }

    public bool Succeeded { get; set; } = true;

    /// <summary>
    /// JSON blob with action-specific detail (old/new role, lockout end, provider name...).
    /// Never contains secrets, tokens, or password material.
    /// </summary>
    public string? Metadata { get; set; }
}

/// <summary>
/// Canonical audit action names. Kept as constants rather than an enum so that
/// adding an action never renumbers stored history.
/// </summary>
public static class AuditAction
{
    // Authentication
    public const string LoginSucceeded = "auth.login.succeeded";
    public const string LoginFailed = "auth.login.failed";
    public const string LoginLockedOut = "auth.login.locked_out";
    public const string Logout = "auth.logout";
    public const string PasswordChanged = "auth.password.changed";
    public const string PasswordResetRequested = "auth.password.reset_requested";
    public const string PasswordResetCompleted = "auth.password.reset_completed";
    public const string EmailVerificationSent = "auth.email.verification_sent";
    public const string EmailVerified = "auth.email.verified";
    public const string RefreshTokenReuseDetected = "auth.refresh.reuse_detected";
    public const string DataExported = "auth.data.exported";

    // Two-factor
    public const string TwoFactorEnabled = "auth.2fa.enabled";
    public const string TwoFactorDisabled = "auth.2fa.disabled";
    public const string TwoFactorChallengeFailed = "auth.2fa.challenge_failed";
    public const string TwoFactorRecoveryCodeUsed = "auth.2fa.recovery_code_used";

    // External / OAuth
    public const string OAuthAccountCreated = "oauth.account.created";
    public const string OAuthAccountLinked = "oauth.account.linked";
    public const string OAuthLinkRejectedUnverified = "oauth.link.rejected_unverified";

    // Account lifecycle
    public const string AccountSoftDeleted = "account.soft_deleted";
    public const string AccountRestored = "account.restored";

    // Admin
    public const string AdminRoleAssigned = "admin.role.assigned";
    public const string AdminRoleRemoved = "admin.role.removed";
    public const string AdminUserLocked = "admin.user.locked";
    public const string AdminUserUnlocked = "admin.user.unlocked";
    public const string AdminUserSessionsRevoked = "admin.user.sessions_revoked";
    public const string AdminUserSoftDeleted = "admin.user.soft_deleted";
    public const string AdminUserRestored = "admin.user.restored";

    // Organizations
    public const string OrganizationCreated = "org.created";
    public const string OrganizationDeleted = "org.deleted";
    public const string OrganizationRestored = "org.restored";
    public const string OrganizationHardDeleted = "org.hard_deleted";
    public const string OrgMemberInvited = "org.member.invited";
    public const string OrgMemberJoined = "org.member.joined";
    public const string OrgMemberRemoved = "org.member.removed";
    public const string OrgMemberRoleChanged = "org.member.role_changed";
    public const string OrgOwnershipTransferred = "org.ownership.transferred";
}
