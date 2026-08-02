using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using AuthService.Data;
using AuthService.Models;
using AuthService.DTOs;
using AuthService.Services;

namespace AuthService.Controllers;

/// <summary>
/// Handles authentication and user account management operations
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController(
    UserManager<ApplicationUser> _userManager,
    SignInManager<ApplicationUser> _signInManager,
    ITokenService _tokenService,
    IEmailService _emailService,
    IConfiguration _configuration,
    ApplicationDbContext _db,
    IOptionsSnapshot<ConsentSettings> _consentSettings,
    ILogger<AuthController> _logger
) : ControllerBase
{
    private const int IpAddressMaxLength = 64;
    private const int UserAgentMaxLength = 512;

    private string? GetClientIp() =>
        HttpContext.Connection.RemoteIpAddress?.ToString() is { Length: > 0 } ip
            ? (ip.Length > IpAddressMaxLength ? ip[..IpAddressMaxLength] : ip)
            : null;

    private string? GetClientUserAgent()
    {
        var ua = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(ua)) return null;
        return ua.Length > UserAgentMaxLength ? ua[..UserAgentMaxLength] : ua;
    }

    private async Task<bool> UserRequiresConsentAsync(string userId)
    {
        var required = _consentSettings.Value;
        var latest = await _db.UserConsents
            .AsNoTracking()
            .Where(c => c.UserId == userId && (c.Type == ConsentType.Terms || c.Type == ConsentType.Privacy))
            .GroupBy(c => c.Type)
            .Select(g => new { Type = g.Key, Version = g.OrderByDescending(x => x.AcceptedAt).Select(x => x.Version).First() })
            .ToListAsync();

        var terms = latest.FirstOrDefault(x => x.Type == ConsentType.Terms)?.Version;
        var privacy = latest.FirstOrDefault(x => x.Type == ConsentType.Privacy)?.Version;

        return terms != required.Terms || privacy != required.Privacy;
    }

    /// <summary>
    /// Registers a new user account
    /// </summary>
    [HttpPost("register")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<TokenResponse>> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState.Values
                .SelectMany(v => v.Errors)
                .Select(e => e.ErrorMessage)
                .ToList();
            _logger.LogWarning("Registration validation failed: {Errors}", string.Join(", ", errors));
            return BadRequest(new { errors });
        }

        // Validate that the user accepted the currently required Terms/Privacy versions.
        var requiredVersions = _consentSettings.Value;
        if (!string.Equals(request.AcceptedTermsVersion, requiredVersions.Terms, StringComparison.Ordinal) ||
            !string.Equals(request.AcceptedPrivacyVersion, requiredVersions.Privacy, StringComparison.Ordinal))
        {
            return BadRequest(new { errors = new[] { "You must accept the current Terms of Use and Privacy Policy to register." } });
        }

        // Derive username from the email local part (before @)
        var userName = GenerateUserNameFromEmail(request.Email);

        // Ensure uniqueness by appending a numeric suffix if needed
        var baseUserName = userName;
        var suffix = 1;
        while (await _userManager.FindByNameAsync(userName) != null)
        {
            userName = $"{baseUserName}{suffix}";
            suffix++;
        }

        var user = new ApplicationUser
        {
            UserName = userName,
            Email = request.Email,
            EmailConfirmed = true // For simplicity; implement email confirmation in production
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("User creation failed for {Email}: {Errors}", request.Email, string.Join(", ", errors));
            return BadRequest(new { errors });
        }

        _logger.LogInformation("User {Email} registered successfully", request.Email);

        // Persist consent records for audit/accountability (GDPR Art. 7).
        var ip = GetClientIp();
        var ua = GetClientUserAgent();
        var now = DateTime.UtcNow;
        _db.UserConsents.Add(new UserConsent
        {
            UserId = user.Id,
            Type = ConsentType.Terms,
            Version = request.AcceptedTermsVersion,
            Accepted = true,
            AcceptedAt = now,
            IpAddress = ip,
            UserAgent = ua,
            Locale = request.Locale
        });
        _db.UserConsents.Add(new UserConsent
        {
            UserId = user.Id,
            Type = ConsentType.Privacy,
            Version = request.AcceptedPrivacyVersion,
            Accepted = true,
            AcceptedAt = now,
            IpAddress = ip,
            UserAgent = ua,
            Locale = request.Locale
        });
        await _db.SaveChangesAsync();

        // Send welcome email (fire-and-forget — do not block registration on email failure)
        try
        {
            await _emailService.SendWelcomeEmailAsync(user.Email!, user.UserName ?? user.Email!);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send welcome email to {Email}", user.Email);
        }

        var tokenResponse = await _tokenService.GenerateTokensAsync(user);

        return Ok(tokenResponse);
    }

    /// <summary>
    /// Authenticates a user and returns JWT tokens
    /// </summary>
    [HttpPost("login")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null || user.IsDeleted)
            return Unauthorized(new { error = "Invalid email or password" });

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
                return Unauthorized(new { error = "Account is locked out" });

            return Unauthorized(new { error = "Invalid email or password" });
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("User {Email} logged in successfully", request.Email);

        var tokenResponse = await _tokenService.GenerateTokensAsync(user);

        return Ok(tokenResponse);
    }

    /// <summary>
    /// Refreshes an expired access token using a valid refresh token
    /// </summary>
    [HttpPost("refresh")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<TokenResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return BadRequest(new { error = "Refresh token is required" });

        var tokenResponse = await _tokenService.RefreshTokenAsync(request.RefreshToken);

        if (tokenResponse == null)
            return Unauthorized(new { error = "Invalid or expired refresh token" });

        return Ok(tokenResponse);
    }

    /// <summary>
    /// Gets the authenticated user's profile information
    /// </summary>
    [Authorize]
    [HttpGet("me")]
    [ProducesResponseType(typeof(UserInfoResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserInfoResponse>> GetCurrentUser()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
            return Unauthorized();

        var user = await _userManager.Users
            .Include(u => u.OrganizationMemberships)
            .ThenInclude(om => om.Organization)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
            return NotFound();

        var organizations = user.OrganizationMemberships
            .Select(om => new UserOrganizationDto(
                om.Organization.Id,
                om.Organization.Name,
                om.Organization.ImageUrl,
                om.Role.ToString()
            ))
            .ToList();

        var requiresConsent = await UserRequiresConsentAsync(user.Id);

        var response = new UserInfoResponse(
            user.Id,
            user.Email!,
            user.UserName,
            user.ProfileImageUrl,
            user.CreatedAt,
            user.LastLoginAt,
            organizations,
            user.PasswordHash != null,
            requiresConsent
        );

        return Ok(response);
    }

    /// <summary>
    /// Returns the latest consent status for each legal document and the current required versions.
    /// </summary>
    [Authorize]
    [HttpGet("consents")]
    [ProducesResponseType(typeof(ConsentStatusResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<ConsentStatusResponse>> GetConsents()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
            return Unauthorized();

        var required = _consentSettings.Value;

        var latest = await _db.UserConsents
            .AsNoTracking()
            .Where(c => c.UserId == userId)
            .GroupBy(c => c.Type)
            .Select(g => g.OrderByDescending(x => x.AcceptedAt).First())
            .ToListAsync();

        ConsentStatusItem Build(ConsentType type, string requiredVersion)
        {
            var row = latest.FirstOrDefault(r => r.Type == type);
            var accepted = row != null && row.Accepted && row.Version == requiredVersion;
            return new ConsentStatusItem(requiredVersion, row?.Version, row?.AcceptedAt, accepted);
        }

        var terms = Build(ConsentType.Terms, required.Terms);
        var privacy = Build(ConsentType.Privacy, required.Privacy);
        var cookies = Build(ConsentType.Cookies, required.Cookies);

        return Ok(new ConsentStatusResponse(terms, privacy, cookies, !(terms.Accepted && privacy.Accepted)));
    }

    /// <summary>
    /// Records the authenticated user's acceptance of the current Terms / Privacy / Cookie versions.
    /// </summary>
    [Authorize]
    [HttpPost("consents")]
    [ProducesResponseType(typeof(ConsentStatusResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<ConsentStatusResponse>> RecordConsents([FromBody] RecordConsentRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
            return Unauthorized();

        var required = _consentSettings.Value;
        var ip = GetClientIp();
        var ua = GetClientUserAgent();
        var now = DateTime.UtcNow;

        if (request.AcceptedTerms == true)
        {
            _db.UserConsents.Add(new UserConsent
            {
                UserId = userId,
                Type = ConsentType.Terms,
                Version = required.Terms,
                Accepted = true,
                AcceptedAt = now,
                IpAddress = ip,
                UserAgent = ua,
                Locale = request.Locale
            });
        }

        if (request.AcceptedPrivacy == true)
        {
            _db.UserConsents.Add(new UserConsent
            {
                UserId = userId,
                Type = ConsentType.Privacy,
                Version = required.Privacy,
                Accepted = true,
                AcceptedAt = now,
                IpAddress = ip,
                UserAgent = ua,
                Locale = request.Locale
            });
        }

        if (request.Cookies != null)
        {
            _db.UserConsents.Add(new UserConsent
            {
                UserId = userId,
                Type = ConsentType.Cookies,
                Version = required.Cookies,
                Accepted = request.Cookies.Preferences || request.Cookies.Analytics || request.Cookies.ThirdParty,
                AcceptedAt = now,
                IpAddress = ip,
                UserAgent = ua,
                Locale = request.Locale,
                CookieCategories = JsonSerializer.Serialize(request.Cookies)
            });
        }

        await _db.SaveChangesAsync();

        _logger.LogInformation(
            "Consent recorded for user {UserId} (terms={Terms}, privacy={Privacy}, cookies={Cookies})",
            userId, request.AcceptedTerms == true, request.AcceptedPrivacy == true, request.Cookies != null);

        return await GetConsents();
    }

    /// <summary>
    /// Updates the authenticated user's profile information
    /// </summary>
    [Authorize]
    [HttpPut("profile")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
            return Unauthorized();

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        if (!string.IsNullOrWhiteSpace(request.UserName))
        {
            var setNameResult = await _userManager.SetUserNameAsync(user, request.UserName);
            if (!setNameResult.Succeeded)
                return BadRequest(new { errors = setNameResult.Errors.Select(e => e.Description) });
        }

        if (request.ProfileImageUrl != null)
        {
            user.ProfileImageUrl = request.ProfileImageUrl;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
                return BadRequest(new { errors = updateResult.Errors.Select(e => e.Description) });
        }

        return Ok(new { message = "Profile updated successfully" });
    }

    /// <summary>
    /// Requests a password reset email for the specified account
    /// </summary>
    [HttpPost("forgot-password")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (!ModelState.IsValid)
            return Ok(new { message = "If an account with that email exists, a password reset link has been sent." });

        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user != null)
        {
            // OAuth-only accounts have no password hash — a reset link would be useless.
            if (user.PasswordHash == null)
            {
                var logins = await _userManager.GetLoginsAsync(user);
                var providers = logins.Select(l => l.LoginProvider).Distinct().ToList();
                var providerList = providers.Count > 0 ? string.Join(" or ", providers) : "your social account";

                _logger.LogInformation(
                    "Password reset requested for OAuth-only account {Email} (providers: {Providers})",
                    request.Email, string.Join(", ", providers));

                return Ok(new
                {
                    message = $"This account was created using {providerList}. Please sign in with that provider — no password is needed.",
                    isOAuthOnly = true
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var frontendBaseUrl = _configuration["FrontendBaseUrl"] ?? "http://localhost:3000";
            var encodedToken = Uri.EscapeDataString(token);
            var encodedEmail = Uri.EscapeDataString(request.Email);
            var resetUrl = $"{frontendBaseUrl}/reset-password?token={encodedToken}&email={encodedEmail}";

            try
            {
                await _emailService.SendPasswordResetEmailAsync(request.Email, token, resetUrl);
                _logger.LogInformation("Password reset email sent to {Email}", request.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email to {Email}", request.Email);
            }
        }
        else
        {
            _logger.LogInformation("Password reset requested for non-existent email {Email}", request.Email);
        }

        // Always return success to prevent email enumeration
        return Ok(new { message = "If an account with that email exists, a password reset link has been sent.", isOAuthOnly = false });
    }

    /// <summary>
    /// Resets the user's password using a valid reset token
    /// </summary>
    [HttpPost("reset-password")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState.Values
                .SelectMany(v => v.Errors)
                .Select(e => e.ErrorMessage)
                .ToList();
            return BadRequest(new { errors });
        }

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return BadRequest(new { errors = new[] { "Invalid or expired reset token." } });
        }

        var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("Password reset failed for {Email}: {Errors}", request.Email, string.Join(", ", errors));
            return BadRequest(new { errors });
        }

        await _tokenService.RevokeRefreshTokensAsync(user.Id);

        _logger.LogInformation("Password reset successful for {Email}", request.Email);

        return Ok(new { message = "Password has been reset successfully. You can now sign in with your new password." });
    }

    /// <summary>
    /// Changes the authenticated user's password
    /// </summary>
    [Authorize]
    [HttpPost("change-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
            return Unauthorized();

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);

        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        return Ok(new { message = "Password changed successfully" });
    }

    /// <summary>
    /// Logs out the authenticated user and revokes all refresh tokens
    /// </summary>
    [Authorize]
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId != null)
        {
            await _tokenService.RevokeRefreshTokensAsync(userId);
        }

        await _signInManager.SignOutAsync();
        return Ok(new { message = "Logged out successfully" });
    }

    /// <summary>
    /// Deletes the authenticated user's account permanently
    /// </summary>
    [Authorize]
    [HttpDelete("account")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteAccount([FromBody] DeleteAccountRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
            return Unauthorized();

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound();

        if (request.Confirmation != "DELETE")
            return BadRequest(new { error = "Confirmation text must be 'DELETE'" });

        // For users with a password, verify it; OAuth-only users skip this check
        if (user.PasswordHash != null)
        {
            if (string.IsNullOrEmpty(request.Password))
                return BadRequest(new { error = "Password is required" });

            var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!passwordValid)
                return BadRequest(new { error = "Invalid password" });
        }

        await _tokenService.RevokeRefreshTokensAsync(userId);

        // Soft-delete the user (permanent deletion happens after the retention period)
        user.IsDeleted = true;
        user.DeletedAt = DateTime.UtcNow;
        user.ScheduledPermanentDeletionAt = DateTime.UtcNow.AddDays(ApplicationUser.DefaultRetentionDays);

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        _logger.LogInformation(
            "User {UserId} soft-deleted their account. Scheduled permanent deletion: {ScheduledAt}",
            userId, user.ScheduledPermanentDeletionAt);

        return Ok(new { message = "Account deleted successfully" });
    }

    /// <summary>
    /// Generates a username from an email address using the local part and domain name (without TLD).
    /// Example: jane.doe@gmail.com -> janedoe_gmail, jane@company.co.uk -> jane_company.
    /// Keeps only letters, digits, hyphens, and underscores. Falls back to "user" if empty.
    /// </summary>
    private static string GenerateUserNameFromEmail(string email)
    {
        var parts = email.Split('@');
        var localPart = parts[0];

        // Remove dots and plus-aliases (e.g. john.doe+test -> johndoetest)
        localPart = localPart.Replace(".", "").Replace("+", "");

        // Keep only allowed characters: letters, digits, hyphens, underscores
        var sanitizedLocal = Regex.Replace(localPart, @"[^a-zA-Z0-9_-]", "");

        // Extract domain name without TLD (e.g. gmail.com -> gmail, mail.company.co.uk -> mail)
        var domainPart = "";
        if (parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1]))
        {
            var domainName = parts[1].Split('.')[0];
            domainPart = Regex.Replace(domainName, @"[^a-zA-Z0-9_-]", "");
        }

        var sanitized = !string.IsNullOrWhiteSpace(domainPart)
            ? $"{sanitizedLocal}_{domainPart}"
            : sanitizedLocal;

        if (sanitized.Length > 50)
            sanitized = sanitized[..50];

        return string.IsNullOrWhiteSpace(sanitized) ? "user" : sanitized;
    }
}
