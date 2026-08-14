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
[Route("api/v1/[controller]")]
[Route("api/[controller]")] // Unversioned alias for the pre-v1 contract. Prefer /api/v1.
public class AuthController(
    UserManager<ApplicationUser> _userManager,
    SignInManager<ApplicationUser> _signInManager,
    ITokenService _tokenService,
    IEmailService _emailService,
    IConfiguration _configuration,
    ApplicationDbContext _db,
    IOptionsSnapshot<ConsentSettings> _consentSettings,
    IOptions<AuthOptions> _authOptions,
    IOptions<NetworkOptions> _networkOptions,
    EmailCapabilities _emailCapabilities,
    IAuditService _audit,
    ILogger<AuthController> _logger
) : ControllerBase
{
    private const int IpAddressMaxLength = 64;
    private const int UserAgentMaxLength = 512;

    /// <summary>
    /// Whether an unverified address is allowed to sign in. Defaults to "on when this
    /// deployment can actually send verification email", so the zero-config quick start
    /// does not lock users out of accounts they just created.
    /// </summary>
    private bool RequireConfirmedEmail =>
        _authOptions.Value.RequireConfirmedEmail ?? _emailCapabilities.CanSendEmail;

    private string? GetClientIp()
    {
        var ip = HttpContext.ResolveClientIp(_networkOptions.Value.ClientIpHeader);
        if (string.IsNullOrEmpty(ip)) return null;
        return ip.Length > IpAddressMaxLength ? ip[..IpAddressMaxLength] : ip;
    }

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
    [ProducesResponseType(typeof(RegistrationPendingVerificationResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
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

        var requireVerification = RequireConfirmedEmail;

        var user = new ApplicationUser
        {
            UserName = userName,
            Email = request.Email,
            // Trusted only when this deployment cannot send a verification message at all.
            EmailConfirmed = !requireVerification
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

        if (requireVerification)
        {
            await SendVerificationEmailAsync(user);

            // 202: the account exists but cannot be used until the address is confirmed.
            // No tokens are issued, because an unconfirmed address is not yet proof of anything.
            return Accepted(new RegistrationPendingVerificationResponse(
                user.Id,
                user.Email!,
                "Account created. Check your email for a verification link before signing in."));
        }

        var tokenResponse = await _tokenService.GenerateTokensAsync(user);

        return Ok(tokenResponse);
    }

    /// <summary>
    /// Authenticates a user and returns JWT tokens.
    /// When the account has two-factor authentication enabled this returns a short-lived
    /// challenge instead, to be completed at <c>POST /api/v1/auth/2fa/login</c>.
    /// </summary>
    [HttpPost("login")]
    [EnableRateLimiting("auth")]
    // A 2FA-enabled account gets TwoFactorRequiredResponse at this same 200 instead of tokens;
    // only one type can be declared per status code, so the common case is the documented one.
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null || user.IsDeleted)
        {
            await _audit.LogAsync(AuditAction.LoginFailed, succeeded: false,
                metadata: new { email = request.Email, reason = "unknown_or_deleted_account" });
            return Unauthorized(new { error = "Invalid email or password" });
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            // Only disclose lockout to a caller who already proved they know the password —
            // otherwise "locked out" is a free account-existence oracle for anyone willing to
            // burn five guesses, and lockout is trivially reachable by an attacker.
            if (result.IsLockedOut && await _userManager.CheckPasswordAsync(user, request.Password))
            {
                await _audit.LogAsync(AuditAction.LoginLockedOut, targetUserId: user.Id, succeeded: false,
                    metadata: new { lockoutEnd = user.LockoutEnd });

                return Unauthorized(new
                {
                    error = "Account is temporarily locked after too many failed sign-in attempts.",
                    lockedOut = true,
                    lockoutEnd = user.LockoutEnd
                });
            }

            await _audit.LogAsync(AuditAction.LoginFailed, targetUserId: user.Id, succeeded: false,
                metadata: new { reason = result.IsLockedOut ? "locked_out" : "invalid_password" });

            return Unauthorized(new { error = "Invalid email or password" });
        }

        if (RequireConfirmedEmail && !user.EmailConfirmed)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                error = "Email address has not been verified.",
                emailVerificationRequired = true
            });
        }

        // First factor passed. If a second is configured, stop here and hand back a challenge
        // that is useless for anything except completing this login.
        if (user.TwoFactorEnabled)
        {
            var challengeToken = _tokenService.GenerateTwoFactorChallengeToken(user);

            return Ok(new TwoFactorRequiredResponse(
                RequiresTwoFactor: true,
                ChallengeToken: challengeToken,
                ExpiresIn: 300));
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("User {Email} logged in successfully", request.Email);
        await _audit.LogAsync(AuditAction.LoginSucceeded, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id);

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

    // ─── Email verification ────────────────────────────────────────────────────

    /// <summary>
    /// Confirms an email address using the token from the verification email.
    /// </summary>
    [HttpPost("verify-email")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        // Same response whether or not the account exists — this endpoint must not become
        // an account-existence oracle.
        if (user == null || user.IsDeleted)
            return BadRequest(new { error = "Invalid or expired verification token." });

        if (user.EmailConfirmed)
            return Ok(new { message = "Email address is already verified." });

        var result = await _userManager.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
            return BadRequest(new { error = "Invalid or expired verification token." });

        await _audit.LogAsync(AuditAction.EmailVerified, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id);

        return Ok(new { message = "Email address verified. You can now sign in." });
    }

    /// <summary>
    /// Re-sends the verification email for an unconfirmed account.
    /// </summary>
    [HttpPost("resend-verification")]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user != null && !user.IsDeleted && !user.EmailConfirmed)
            await SendVerificationEmailAsync(user);

        // Always the same answer, for the same reason as forgot-password.
        return Ok(new { message = "If that address needs verification, a new link has been sent." });
    }

    private async Task SendVerificationEmailAsync(ApplicationUser user)
    {
        try
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var frontendBaseUrl = _configuration["FrontendBaseUrl"] ?? "http://localhost:3000";
            var verificationUrl = $"{frontendBaseUrl}/verify-email" +
                                  $"?token={Uri.EscapeDataString(token)}" +
                                  $"&email={Uri.EscapeDataString(user.Email!)}";

            await _emailService.SendEmailVerificationAsync(user.Email!, token, verificationUrl);

            await _audit.LogAsync(AuditAction.EmailVerificationSent, targetUserId: user.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send verification email to {Email}", user.Email);
        }
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
            requiresConsent,
            user.EmailConfirmed,
            user.TwoFactorEnabled
        );

        return Ok(response);
    }

    /// <summary>
    /// Exports everything this service holds about the authenticated user (GDPR Art. 15 / Art. 20).
    /// </summary>
    [Authorize]
    [HttpGet("export")]
    [ProducesResponseType(typeof(UserDataExport), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ExportMyData()
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

        var logins = await _userManager.GetLoginsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

        var consents = await _db.UserConsents
            .AsNoTracking()
            .Where(c => c.UserId == userId)
            .OrderBy(c => c.AcceptedAt)
            .Select(c => new ConsentExportDto(
                c.Type.ToString(),
                c.Version,
                c.Accepted,
                c.AcceptedAt,
                c.IpAddress,
                c.UserAgent,
                c.Locale,
                c.CookieCategories))
            .ToListAsync();

        var invitationsReceived = await _db.OrganizationInvitations
            .AsNoTracking()
            .IgnoreQueryFilters()
            .Where(i => i.Email == user.Email)
            .Select(i => new InvitationExportDto(
                i.OrganizationId,
                i.Organization.Name,
                i.Email,
                i.Role.ToString(),
                i.CreatedAt,
                i.ExpiresAt,
                i.IsAccepted,
                i.AcceptedAt))
            .ToListAsync();

        var invitationsSent = await _db.OrganizationInvitations
            .AsNoTracking()
            .IgnoreQueryFilters()
            .Where(i => i.InvitedByUserId == userId)
            .Select(i => new InvitationExportDto(
                i.OrganizationId,
                i.Organization.Name,
                i.Email,
                i.Role.ToString(),
                i.CreatedAt,
                i.ExpiresAt,
                i.IsAccepted,
                i.AcceptedAt))
            .ToListAsync();

        // Session *metadata* only. The tokens themselves are stored as hashes and would be
        // useless here anyway; exporting them would be handing out live credentials.
        var sessions = await _db.RefreshTokens
            .AsNoTracking()
            .Where(rt => rt.UserId == userId)
            .OrderByDescending(rt => rt.CreatedAt)
            .Select(rt => new SessionExportDto(
                rt.CreatedAt,
                rt.ExpiresAt,
                rt.IsRevoked,
                rt.RevokedAt,
                rt.RevokedReason))
            .ToListAsync();

        var export = new UserDataExport(
            ExportedAt: DateTime.UtcNow,
            Profile: new ProfileExportDto(
                user.Id,
                user.Email!,
                user.UserName,
                user.ProfileImageUrl,
                user.CreatedAt,
                user.LastLoginAt,
                user.EmailConfirmed,
                user.TwoFactorEnabled,
                user.PasswordHash != null,
                user.IsDeleted,
                user.DeletedAt,
                user.ScheduledPermanentDeletionAt,
                roles.ToList()),
            // Provider keys are deliberately excluded — they identify the account at the
            // provider and are not the user's data to re-export.
            ExternalLogins: logins
                .Select(l => new ExternalLoginExportDto(l.LoginProvider, l.ProviderDisplayName))
                .ToList(),
            Consents: consents,
            Organizations: user.OrganizationMemberships
                .Select(om => new OrganizationExportDto(
                    om.OrganizationId,
                    om.Organization.Name,
                    om.Role.ToString(),
                    om.JoinedAt))
                .ToList(),
            InvitationsReceived: invitationsReceived,
            InvitationsSent: invitationsSent,
            Sessions: sessions);

        await _audit.LogAsync(AuditAction.DataExported, actorUserId: userId, actorEmail: user.Email,
            targetUserId: userId);

        // Content-Disposition makes "download my data" a single link in a frontend.
        Response.Headers.ContentDisposition = "attachment; filename=\"authservice-export.json\"";
        return Ok(export);
    }

    /// <summary>
    /// Returns the consent document versions a registration must accept.
    ///
    /// Anonymous, and necessarily so: <c>POST /register</c> rejects any request that does not
    /// accept the exact versions this instance is configured with, and a sign-up form has no
    /// token yet. Without this a frontend has to hardcode the versions and silently breaks
    /// registration the moment one is bumped — which is the whole point of them being
    /// versioned.
    ///
    /// It discloses nothing: these are the identifiers of published legal documents.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("consents/versions")]
    [ProducesResponseType(typeof(ConsentVersionsResponse), StatusCodes.Status200OK)]
    public ActionResult<ConsentVersionsResponse> GetConsentVersions()
    {
        var required = _consentSettings.Value;
        return Ok(new ConsentVersionsResponse(required.Terms, required.Privacy, required.Cookies));
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
                await _audit.LogAsync(AuditAction.PasswordResetRequested, targetUserId: user.Id);
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

        await _tokenService.RevokeRefreshTokensAsync(user.Id, RefreshTokenRevocationReason.PasswordReset);

        _logger.LogInformation("Password reset successful for {Email}", request.Email);
        await _audit.LogAsync(AuditAction.PasswordResetCompleted, targetUserId: user.Id);

        return Ok(new { message = "Password has been reset successfully. You can now sign in with your new password." });
    }

    /// <summary>
    /// Changes the authenticated user's password.
    /// All other sessions are terminated; by default a fresh token pair is returned so the
    /// calling session survives (see <c>Auth:ReissueTokensOnPasswordChange</c>).
    /// </summary>
    [Authorize]
    [HttpPost("change-password")]
    [ProducesResponseType(typeof(ChangePasswordResponse), StatusCodes.Status200OK)]
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

        await _audit.LogAsync(AuditAction.PasswordChanged, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id);

        if (!_authOptions.Value.RevokeSessionsOnPasswordChange)
            return Ok(new ChangePasswordResponse("Password changed successfully", false, null));

        // Changing a password is how a user responds to "someone else has my session".
        // It has to actually end those sessions.
        await _tokenService.RevokeRefreshTokensAsync(user.Id, RefreshTokenRevocationReason.PasswordChanged);

        if (!_authOptions.Value.ReissueTokensOnPasswordChange)
        {
            return Ok(new ChangePasswordResponse(
                "Password changed successfully. All sessions have been signed out — please sign in again.",
                true,
                null));
        }

        // Hand the caller a new pair so the device that just changed the password stays
        // usable while every other device is signed out.
        var tokens = await _tokenService.GenerateTokensAsync(user);

        return Ok(new ChangePasswordResponse(
            "Password changed successfully. All other sessions have been signed out.",
            true,
            tokens));
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
            await _tokenService.RevokeRefreshTokensAsync(userId, RefreshTokenRevocationReason.Logout);
            await _audit.LogAsync(AuditAction.Logout, actorUserId: userId, targetUserId: userId);
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

        await _tokenService.RevokeRefreshTokensAsync(userId, RefreshTokenRevocationReason.AccountDeleted);

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

        await _audit.LogAsync(AuditAction.AccountSoftDeleted, actorUserId: userId, actorEmail: user.Email,
            targetUserId: userId,
            metadata: new { scheduledPermanentDeletionAt = user.ScheduledPermanentDeletionAt });

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
