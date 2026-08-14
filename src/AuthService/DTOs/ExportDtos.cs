namespace AuthService.DTOs;

/// <summary>
/// Everything this service holds about a single user, in one document.
///
/// Satisfies the access (GDPR Art. 15) and portability (Art. 20) side of the same story the
/// service already tells for erasure (Art. 17) — a user could delete their data here but not
/// obtain a copy of it first, which is the thing most people actually want before deleting.
///
/// Deliberately excluded: password hashes, refresh token values, OAuth provider keys, and
/// email confirmation tokens. Those are credentials or provider-side identifiers, not
/// personal data the user is entitled to re-export.
/// </summary>
public record UserDataExport(
    DateTime ExportedAt,
    ProfileExportDto Profile,
    IReadOnlyList<ExternalLoginExportDto> ExternalLogins,
    IReadOnlyList<ConsentExportDto> Consents,
    IReadOnlyList<OrganizationExportDto> Organizations,
    IReadOnlyList<InvitationExportDto> InvitationsReceived,
    IReadOnlyList<InvitationExportDto> InvitationsSent,
    IReadOnlyList<SessionExportDto> Sessions
);

public record ProfileExportDto(
    string Id,
    string Email,
    string? UserName,
    string? ProfileImageUrl,
    DateTime CreatedAt,
    DateTime? LastLoginAt,
    bool EmailConfirmed,
    bool TwoFactorEnabled,
    bool HasPassword,
    bool IsDeleted,
    DateTime? DeletedAt,
    DateTime? ScheduledPermanentDeletionAt,
    IReadOnlyList<string> Roles
);

public record ExternalLoginExportDto(
    string Provider,
    string? ProviderDisplayName
);

public record ConsentExportDto(
    string Type,
    string Version,
    bool Accepted,
    DateTime AcceptedAt,
    string? IpAddress,
    string? UserAgent,
    string? Locale,
    string? CookieCategories
);

public record OrganizationExportDto(
    string OrganizationId,
    string Name,
    string Role,
    DateTime JoinedAt
);

public record InvitationExportDto(
    string OrganizationId,
    string OrganizationName,
    string Email,
    string Role,
    DateTime CreatedAt,
    DateTime ExpiresAt,
    bool IsAccepted,
    DateTime? AcceptedAt
);

/// <summary>Session metadata only — the refresh tokens themselves are stored hashed.</summary>
public record SessionExportDto(
    DateTime CreatedAt,
    DateTime ExpiresAt,
    bool IsRevoked,
    DateTime? RevokedAt,
    string? RevokedReason
);
