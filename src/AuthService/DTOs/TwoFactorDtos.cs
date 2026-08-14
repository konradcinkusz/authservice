using System.ComponentModel.DataAnnotations;

namespace AuthService.DTOs;

/// <summary>
/// Everything needed to add the account to an authenticator app. Returned by
/// <c>POST /api/v1/auth/2fa/enable</c>; two-factor is not active until the first code is
/// confirmed, so a user who loses the QR code mid-setup is not locked out.
/// </summary>
public record TwoFactorSetupResponse(
    /// <summary>Base32 shared secret, for manual entry.</summary>
    string SharedKey,
    /// <summary>otpauth:// URI to render as a QR code.</summary>
    string AuthenticatorUri
);

/// <summary>Confirms the first generated code and activates two-factor.</summary>
public record TwoFactorVerifyRequest(
    [Required(ErrorMessage = "Verification code is required")]
    [StringLength(8, MinimumLength = 6, ErrorMessage = "Verification code must be 6-8 digits")]
    string Code
);

/// <summary>
/// Recovery codes, shown exactly once. Each is single-use and substitutes for the
/// authenticator when the device is lost.
/// </summary>
public record TwoFactorRecoveryCodesResponse(
    IReadOnlyList<string> RecoveryCodes,
    string Message = "Store these codes somewhere safe. Each can be used once, and they will not be shown again."
);

/// <summary>Turns two-factor off. Requires both the current password and a live code.</summary>
public record TwoFactorDisableRequest(
    [Required(ErrorMessage = "Current password is required")]
    string Password,

    /// <summary>Authenticator code, or a recovery code when the device is gone.</summary>
    [Required(ErrorMessage = "Verification code is required")]
    string Code
);

/// <summary>Completes a login that stopped at the two-factor challenge.</summary>
public record TwoFactorLoginRequest(
    [Required(ErrorMessage = "Challenge token is required")]
    string ChallengeToken,

    /// <summary>Authenticator code. Supply this or <see cref="RecoveryCode"/>.</summary>
    string? Code,

    /// <summary>Single-use recovery code. Supply this or <see cref="Code"/>.</summary>
    string? RecoveryCode
);
