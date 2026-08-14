using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;

namespace AuthService.Controllers;

/// <summary>
/// Time-based one-time password (TOTP) two-factor authentication.
///
/// The primitives all come from ASP.NET Core Identity, which was already registered with
/// <c>AddDefaultTokenProviders()</c> — this controller is the wiring, not new cryptography.
///
/// Enrolment is two-step on purpose: <c>enable</c> hands out a secret but leaves the account
/// alone, and only <c>verify</c> — proof that the authenticator actually works — switches
/// two-factor on. Abandoning setup halfway therefore cannot lock anyone out.
/// </summary>
[ApiController]
[Authorize]
[Route("api/v1/auth/2fa")]
[Route("api/auth/2fa")] // Unversioned alias. Prefer /api/v1.
public class TwoFactorController(
    UserManager<ApplicationUser> _userManager,
    ITokenService _tokenService,
    IAuditService _audit,
    IConfiguration _configuration,
    ILogger<TwoFactorController> _logger
) : ControllerBase
{
    private const int RecoveryCodeCount = 10;

    private string AppName => _configuration["App:Name"] ?? "AuthService";

    /// <summary>
    /// Starts enrolment: returns the shared secret and an otpauth:// URI for QR rendering.
    /// Two-factor is not active until <c>verify</c> succeeds.
    /// </summary>
    [HttpPost("enable")]
    [ProducesResponseType(typeof(TwoFactorSetupResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Enable()
    {
        var user = await GetCurrentUserAsync();
        if (user == null) return Unauthorized();

        if (user.TwoFactorEnabled)
            return BadRequest(new { error = "Two-factor authentication is already enabled." });

        // A fresh secret every time enrolment is restarted, so an abandoned setup leaves
        // nothing usable behind.
        await _userManager.ResetAuthenticatorKeyAsync(user);
        var key = await _userManager.GetAuthenticatorKeyAsync(user);

        if (string.IsNullOrWhiteSpace(key))
            return BadRequest(new { error = "Failed to generate an authenticator key." });

        return Ok(new TwoFactorSetupResponse(
            SharedKey: FormatKey(key),
            AuthenticatorUri: BuildAuthenticatorUri(user.Email!, key)));
    }

    /// <summary>
    /// Confirms the first authenticator code, activates two-factor, and returns recovery codes.
    /// </summary>
    [HttpPost("verify")]
    [ProducesResponseType(typeof(TwoFactorRecoveryCodesResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Verify([FromBody] TwoFactorVerifyRequest request)
    {
        var user = await GetCurrentUserAsync();
        if (user == null) return Unauthorized();

        if (user.TwoFactorEnabled)
            return BadRequest(new { error = "Two-factor authentication is already enabled." });

        var code = NormalizeCode(request.Code);

        var valid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);

        if (!valid)
            return BadRequest(new { error = "That code is not valid. Check your device clock and try again." });

        await _userManager.SetTwoFactorEnabledAsync(user, true);

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, RecoveryCodeCount);

        _logger.LogInformation("User {UserId} enabled two-factor authentication", user.Id);
        await _audit.LogAsync(AuditAction.TwoFactorEnabled, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id);

        return Ok(new TwoFactorRecoveryCodesResponse((recoveryCodes ?? Enumerable.Empty<string>()).ToList()));
    }

    /// <summary>
    /// Regenerates recovery codes, invalidating any previously issued set.
    /// </summary>
    [HttpPost("recovery-codes")]
    [ProducesResponseType(typeof(TwoFactorRecoveryCodesResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RegenerateRecoveryCodes()
    {
        var user = await GetCurrentUserAsync();
        if (user == null) return Unauthorized();

        if (!user.TwoFactorEnabled)
            return BadRequest(new { error = "Two-factor authentication is not enabled." });

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, RecoveryCodeCount);

        return Ok(new TwoFactorRecoveryCodesResponse((recoveryCodes ?? Enumerable.Empty<string>()).ToList()));
    }

    /// <summary>
    /// Turns two-factor off. Requires the current password *and* a live code, so a stolen
    /// session alone cannot remove the second factor.
    /// </summary>
    [HttpPost("disable")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Disable([FromBody] TwoFactorDisableRequest request)
    {
        var user = await GetCurrentUserAsync();
        if (user == null) return Unauthorized();

        if (!user.TwoFactorEnabled)
            return BadRequest(new { error = "Two-factor authentication is not enabled." });

        if (user.PasswordHash != null && !await _userManager.CheckPasswordAsync(user, request.Password))
            return BadRequest(new { error = "Invalid password." });

        var code = NormalizeCode(request.Code);

        var valid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);

        if (!valid)
        {
            // A recovery code is an acceptable substitute here: it proves possession of the
            // enrolment material even when the authenticator device is gone.
            var recoveryResult = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, request.Code);
            if (!recoveryResult.Succeeded)
                return BadRequest(new { error = "That code is not valid." });
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);

        // Removing a factor changes what every live session is worth, so they all end.
        await _tokenService.RevokeRefreshTokensAsync(user.Id, RefreshTokenRevocationReason.TwoFactorChanged);

        _logger.LogInformation("User {UserId} disabled two-factor authentication", user.Id);
        await _audit.LogAsync(AuditAction.TwoFactorDisabled, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id);

        return Ok(new { message = "Two-factor authentication disabled. All sessions have been signed out." });
    }

    /// <summary>
    /// Completes a login that returned a two-factor challenge, exchanging the challenge plus
    /// a code (or recovery code) for real tokens.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("login")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> LoginWithTwoFactor([FromBody] TwoFactorLoginRequest request)
    {
        var userId = _tokenService.GetUserIdFromTwoFactorChallengeToken(request.ChallengeToken);
        if (userId == null)
            return Unauthorized(new { error = "Invalid or expired challenge. Start the sign-in again." });

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null || user.IsDeleted || !user.TwoFactorEnabled)
            return Unauthorized(new { error = "Invalid or expired challenge. Start the sign-in again." });

        // The challenge only proves the first factor passed; lockout can have landed since.
        if (await _userManager.IsLockedOutAsync(user))
            return Unauthorized(new { error = "Account is temporarily locked after too many failed attempts." });

        var usedRecoveryCode = false;

        if (!string.IsNullOrWhiteSpace(request.Code))
        {
            var valid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, NormalizeCode(request.Code));

            if (!valid)
                return await RejectSecondFactorAsync(user, "invalid_code");
        }
        else if (!string.IsNullOrWhiteSpace(request.RecoveryCode))
        {
            var redeemed = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, request.RecoveryCode.Trim());
            if (!redeemed.Succeeded)
                return await RejectSecondFactorAsync(user, "invalid_recovery_code");

            usedRecoveryCode = true;
        }
        else
        {
            return BadRequest(new { error = "Provide either an authenticator code or a recovery code." });
        }

        await _userManager.ResetAccessFailedCountAsync(user);

        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        if (usedRecoveryCode)
        {
            var remaining = await _userManager.CountRecoveryCodesAsync(user);
            _logger.LogWarning("User {UserId} signed in with a recovery code ({Remaining} remaining)", user.Id, remaining);
            await _audit.LogAsync(AuditAction.TwoFactorRecoveryCodeUsed, actorUserId: user.Id,
                actorEmail: user.Email, targetUserId: user.Id, metadata: new { remainingRecoveryCodes = remaining });
        }

        await _audit.LogAsync(AuditAction.LoginSucceeded, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id, metadata: new { secondFactor = usedRecoveryCode ? "recovery_code" : "totp" });

        return Ok(await _tokenService.GenerateTokensAsync(user));
    }

    /// <summary>
    /// Counts a failed second factor against the lockout budget, so the second factor cannot
    /// be brute-forced from a challenge token the way it could if only the first factor
    /// incremented the counter.
    /// </summary>
    private async Task<IActionResult> RejectSecondFactorAsync(ApplicationUser user, string reason)
    {
        await _userManager.AccessFailedAsync(user);

        await _audit.LogAsync(AuditAction.TwoFactorChallengeFailed, targetUserId: user.Id,
            succeeded: false, metadata: new { reason });

        return Unauthorized(new { error = "That code is not valid." });
    }

    private async Task<ApplicationUser?> GetCurrentUserAsync()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return userId == null ? null : await _userManager.FindByIdAsync(userId);
    }

    /// <summary>Strips the spaces and dashes people paste in from authenticator apps.</summary>
    private static string NormalizeCode(string? code)
        => (code ?? string.Empty).Replace(" ", string.Empty).Replace("-", string.Empty).Trim();

    /// <summary>Groups the shared key into four-character blocks for manual entry.</summary>
    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        var position = 0;

        while (position + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(position, 4)).Append(' ');
            position += 4;
        }

        if (position < unformattedKey.Length)
            result.Append(unformattedKey.AsSpan(position));

        return result.ToString().ToLowerInvariant();
    }

    private string BuildAuthenticatorUri(string email, string unformattedKey)
        => string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
            UrlEncoder.Default.Encode(AppName),
            UrlEncoder.Default.Encode(email),
            unformattedKey);
}
