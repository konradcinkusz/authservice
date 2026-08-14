namespace AuthService.Models;

/// <summary>
/// A rotating refresh token. Only the SHA-256 hash of the token is persisted — the raw
/// value exists once, in the response to the client, and is never stored or logged.
///
/// Tokens issued from the same login share a <see cref="FamilyId"/>. Presenting an
/// already-revoked token is treated as replay and revokes the whole family
/// (the OAuth 2.0 Security BCP refresh-token-rotation pattern).
/// </summary>
public class RefreshToken
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string UserId { get; set; } = string.Empty;

    /// <summary>Base64-encoded SHA-256 hash of the refresh token.</summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>Rotation family — every token descended from a single login shares this value.</summary>
    public string FamilyId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>Id of the token that superseded this one during rotation.</summary>
    public string? ReplacedByTokenId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? RevokedAt { get; set; }

    /// <summary>Why the token was revoked — "rotated", "logout", "password-change", "reuse-detected", ...</summary>
    public string? RevokedReason { get; set; }

    public ApplicationUser User { get; set; } = null!;
}

/// <summary>Reasons recorded on <see cref="RefreshToken.RevokedReason"/>.</summary>
public static class RefreshTokenRevocationReason
{
    public const string Rotated = "rotated";
    public const string Logout = "logout";
    public const string PasswordChanged = "password-changed";
    public const string PasswordReset = "password-reset";
    public const string AccountDeleted = "account-deleted";
    public const string AdminRevoked = "admin-revoked";
    public const string AdminLocked = "admin-locked";
    public const string ReuseDetected = "reuse-detected";
    public const string UserNotEligible = "user-not-eligible";
    public const string TwoFactorChanged = "two-factor-changed";
}
