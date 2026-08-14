using System.ComponentModel.DataAnnotations;

namespace AuthService.DTOs;

/// <summary>
/// Request model for user registration.
/// Username is automatically derived from the email address (local part before @).
/// </summary>
public record RegisterRequest(
    /// <summary>Email address for the new user account</summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
    string Email,

    /// <summary>Password for the new user account (minimum 8 characters)</summary>
    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 100 characters")]
    string Password,

    /// <summary>Version of the Terms of Use the user is accepting (e.g. "2026-01-01")</summary>
    [Required(ErrorMessage = "Terms acceptance is required")]
    [StringLength(50, ErrorMessage = "Terms version is invalid")]
    string AcceptedTermsVersion,

    /// <summary>Version of the Privacy Policy the user is accepting</summary>
    [Required(ErrorMessage = "Privacy acceptance is required")]
    [StringLength(50, ErrorMessage = "Privacy version is invalid")]
    string AcceptedPrivacyVersion,

    /// <summary>Locale shown to the user at acceptance time</summary>
    [StringLength(16)]
    string? Locale = null
);

/// <summary>
/// Request model for user login
/// </summary>
public record LoginRequest(
    /// <summary>User's email address</summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    string Email,

    /// <summary>User's password</summary>
    [Required(ErrorMessage = "Password is required")]
    string Password
);

/// <summary>
/// Response containing JWT authentication tokens
/// </summary>
public record TokenResponse(
    /// <summary>JWT access token used to authenticate API requests</summary>
    string AccessToken,
    /// <summary>Refresh token used to obtain new access tokens</summary>
    string RefreshToken,
    /// <summary>Access token expiration time in seconds</summary>
    int ExpiresIn,
    /// <summary>Token type (always "Bearer")</summary>
    string TokenType = "Bearer"
);

/// <summary>
/// Request model for refreshing an access token
/// </summary>
public record RefreshTokenRequest(
    /// <summary>Valid refresh token from previous authentication</summary>
    [Required(ErrorMessage = "Refresh token is required")]
    string RefreshToken
);

/// <summary>
/// User profile information including organization memberships
/// </summary>
public record UserInfoResponse(
    /// <summary>User's unique identifier</summary>
    string Id,
    /// <summary>User's email address</summary>
    string Email,
    /// <summary>User's display name</summary>
    string? UserName,
    /// <summary>URL to user's profile image</summary>
    string? ProfileImageUrl,
    /// <summary>Account creation timestamp</summary>
    DateTime CreatedAt,
    /// <summary>Last login timestamp</summary>
    DateTime? LastLoginAt,
    /// <summary>List of organizations the user belongs to</summary>
    List<UserOrganizationDto> Organizations,
    /// <summary>Whether the user has a password set (false for OAuth-only accounts)</summary>
    bool HasPassword,

    /// <summary>
    /// True when the user must accept the current Terms/Privacy versions before
    /// continuing to use the application (either never accepted or an old version).
    /// </summary>
    bool RequiresConsent,

    /// <summary>Whether the email address has been verified</summary>
    bool EmailConfirmed = true,

    /// <summary>Whether two-factor authentication is active on the account</summary>
    bool TwoFactorEnabled = false
);

/// <summary>
/// Returned by registration when the address must be verified before the account can be used.
/// No tokens are issued at this point.
/// </summary>
public record RegistrationPendingVerificationResponse(
    string UserId,
    string Email,
    string Message,
    bool EmailVerificationRequired = true
);

/// <summary>
/// Returned by login when the account has two-factor authentication enabled. The challenge
/// token is scoped to completing this login only and cannot be used as an access token.
/// </summary>
public record TwoFactorRequiredResponse(
    bool RequiresTwoFactor,
    string ChallengeToken,
    int ExpiresIn
);

/// <summary>
/// Redeems the single-use code from the OAuth callback redirect for a token pair.
/// </summary>
public record OAuthExchangeRequest(
    [Required(ErrorMessage = "Code is required")]
    string Code
);

/// <summary>Request to confirm an email address.</summary>
public record VerifyEmailRequest(
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    string Email,

    [Required(ErrorMessage = "Verification token is required")]
    string Token
);

/// <summary>Request a fresh verification email.</summary>
public record ResendVerificationRequest(
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    string Email
);

/// <summary>
/// Result of a password change, including a replacement token pair when the service is
/// configured to keep the calling session alive.
/// </summary>
public record ChangePasswordResponse(
    string Message,
    bool SessionsRevoked,
    TokenResponse? Tokens
);

/// <summary>
/// Organization membership information for a user
/// </summary>
public record UserOrganizationDto(
    /// <summary>Organization's unique identifier</summary>
    string Id,
    /// <summary>Organization name</summary>
    string Name,
    /// <summary>URL to organization's image/logo</summary>
    string? ImageUrl,
    /// <summary>User's role in the organization (Owner, Admin, Member)</summary>
    string Role
);

/// <summary>
/// Request model for requesting a password reset email
/// </summary>
public record ForgotPasswordRequest(
    /// <summary>Email address of the account to reset</summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
    string Email
);

/// <summary>
/// Request model for resetting the password using a reset token
/// </summary>
public record ResetPasswordRequest(
    /// <summary>Email address of the account</summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
    string Email,

    /// <summary>Password reset token received via email</summary>
    [Required(ErrorMessage = "Reset token is required")]
    string Token,

    /// <summary>New password (minimum 8 characters)</summary>
    [Required(ErrorMessage = "New password is required")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 100 characters")]
    string NewPassword
);

/// <summary>
/// Request model for updating user profile
/// </summary>
public record UpdateProfileRequest(
    /// <summary>New username (optional)</summary>
    [StringLength(50, ErrorMessage = "Username cannot exceed 50 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_-]*$", ErrorMessage = "Username can only contain letters, numbers, hyphens, and underscores")]
    string? UserName,

    /// <summary>New profile image URL (optional)</summary>
    [Url(ErrorMessage = "Invalid URL format")]
    [StringLength(500, ErrorMessage = "Profile image URL cannot exceed 500 characters")]
    string? ProfileImageUrl
);

/// <summary>
/// Request model for changing user password
/// </summary>
public record ChangePasswordRequest(
    /// <summary>Current password for verification</summary>
    [Required(ErrorMessage = "Current password is required")]
    string CurrentPassword,

    /// <summary>New password (minimum 8 characters)</summary>
    [Required(ErrorMessage = "New password is required")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "New password must be between 8 and 100 characters")]
    string NewPassword
);

/// <summary>
/// Request model for account deletion
/// </summary>
public record DeleteAccountRequest(
    /// <summary>Current password for verification (not required for OAuth-only accounts)</summary>
    string? Password,

    /// <summary>Confirmation text (must be "DELETE" to proceed)</summary>
    [Required(ErrorMessage = "Confirmation is required")]
    [RegularExpression("DELETE", ErrorMessage = "Confirmation must be exactly 'DELETE'")]
    string Confirmation
);

// ─── Legal / Consent DTOs ───────────────────────────────────────────────────

/// <summary>
/// Versions of legal documents currently required plus the latest version the
/// user has accepted for each type.
/// </summary>
public record ConsentStatusResponse(
    /// <summary>Terms of Use: required version / accepted version (null if never)</summary>
    ConsentStatusItem Terms,
    /// <summary>Privacy Policy: required version / accepted version</summary>
    ConsentStatusItem Privacy,
    /// <summary>Cookie Policy: required version / accepted version (optional — only set after banner interaction)</summary>
    ConsentStatusItem Cookies,
    /// <summary>
    /// True when the current Terms or Privacy version hasn't been accepted yet.
    /// Cookie consent is not gating; its absence only restricts non-essential cookies.
    /// </summary>
    bool RequiresConsent
);

public record ConsentStatusItem(
    string RequiredVersion,
    string? AcceptedVersion,
    DateTime? AcceptedAt,
    bool Accepted
);

/// <summary>
/// Request to record an authenticated user's acceptance of one or more legal documents.
/// </summary>
public record RecordConsentRequest(
    /// <summary>Whether the Terms of Use have been accepted</summary>
    bool? AcceptedTerms,
    /// <summary>Whether the Privacy Policy has been accepted</summary>
    bool? AcceptedPrivacy,
    /// <summary>Cookie consent details (optional — only for cookie banner submissions)</summary>
    CookieConsentDto? Cookies,
    /// <summary>Locale shown when the consent was given</summary>
    [StringLength(16)]
    string? Locale
);

public record CookieConsentDto(
    bool Necessary,
    bool Preferences,
    bool Analytics,
    bool ThirdParty
);
