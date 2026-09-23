using System.Security.Claims;
using AuthService.Data;
using AuthService.Extensions;
using AuthService.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthService.Services;

/// <summary>What the password step decided.</summary>
public enum PasswordSignInStatus
{
    Succeeded,

    /// <summary>Unknown account, wrong password, or refused before the password was checked. One answer for all three.</summary>
    Failed,

    /// <summary>Locked out, disclosed only because the caller gave the right password.</summary>
    LockedOut,

    EmailNotConfirmed,

    /// <summary>The first factor passed; the account needs its second.</summary>
    RequiresTwoFactor
}

public sealed record PasswordSignInResult(PasswordSignInStatus Status, ApplicationUser? User = null);

/// <summary>Why a user who authenticated may still not be issued a session by the authorization server.</summary>
public enum SignInIneligibility
{
    None,
    Deleted,
    LockedOut,
    EmailNotConfirmed,

    /// <summary>The accepted Terms or Privacy version is not the current one (IDENTITY-AND-ACCOUNTS.md §9).</summary>
    ConsentRequired
}

public enum SecondFactorStatus
{
    Succeeded,
    Invalid,
    LockedOut,
    Missing
}

/// <summary>
/// The sign-in decision, in one place for both surfaces that make it: <c>POST /api/v1/auth/login</c>
/// and the authorization server's sign-in page (AUTH-MCP-01, AC2). Extracted from
/// <c>AuthController.Login</c> unchanged, with <c>SignInCharacterizationTests</c> pinning the
/// behaviour first: one generic failure whether or not the account exists
/// (IDENTITY-AND-ACCOUNTS.md §5), and lockout disclosed only to a caller who knew the password (§6).
///
/// The authorization server's pages also use the steps around it: the second factor, the
/// eligibility checks a session has to pass, and their own cookie session.
/// </summary>
public class SignInFlow(
    UserManager<ApplicationUser> _userManager,
    SignInManager<ApplicationUser> _signInManager,
    ApplicationDbContext _db,
    IOptions<AuthOptions> _authOptions,
    EmailCapabilities _emailCapabilities,
    IOptionsSnapshot<ConsentSettings> _consentSettings,
    IAuditService _audit,
    ILogger<SignInFlow> _logger
)
{
    /// <summary>
    /// Whether an unverified address is allowed to sign in. Defaults to "on when this deployment
    /// can actually send verification email", as it always has.
    /// </summary>
    public bool RequireConfirmedEmail =>
        _authOptions.Value.RequireConfirmedEmail ?? _emailCapabilities.CanSendEmail;

    /// <summary>
    /// Checks an email and password. Writes the failure audit rows itself; a success is
    /// recorded by <see cref="CompleteSignInAsync"/> once the caller has finished any second step.
    /// </summary>
    public async Task<PasswordSignInResult> CheckPasswordAsync(string email, string password)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || user.IsDeleted)
        {
            await _audit.LogAsync(AuditAction.LoginFailed, succeeded: false,
                metadata: new { email, reason = "unknown_or_deleted_account" });
            return new PasswordSignInResult(PasswordSignInStatus.Failed);
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            // Only disclose lockout to a caller who already proved they know the password —
            // otherwise "locked out" is a free account-existence oracle for anyone willing to
            // burn five guesses, and lockout is trivially reachable by an attacker.
            if (result.IsLockedOut && await _userManager.CheckPasswordAsync(user, password))
            {
                await _audit.LogAsync(AuditAction.LoginLockedOut, targetUserId: user.Id, succeeded: false,
                    metadata: new { lockoutEnd = user.LockoutEnd });

                return new PasswordSignInResult(PasswordSignInStatus.LockedOut, user);
            }

            await _audit.LogAsync(AuditAction.LoginFailed, targetUserId: user.Id, succeeded: false,
                metadata: new { reason = result.IsLockedOut ? "locked_out" : "invalid_password" });

            return new PasswordSignInResult(PasswordSignInStatus.Failed);
        }

        // Reached only when Identity's own confirmation check is off while this one is on; with
        // both driven by one setting, Identity refuses the account first, as a failure above.
        if (RequireConfirmedEmail && !user.EmailConfirmed)
            return new PasswordSignInResult(PasswordSignInStatus.EmailNotConfirmed, user);

        // First factor passed. If a second is configured, the caller asks for it.
        if (user.TwoFactorEnabled)
            return new PasswordSignInResult(PasswordSignInStatus.RequiresTwoFactor, user);

        return new PasswordSignInResult(PasswordSignInStatus.Succeeded, user);
    }

    /// <summary>Records a completed sign-in: the last-login time and the audit row.</summary>
    public async Task CompleteSignInAsync(ApplicationUser user, object? metadata = null)
    {
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await _audit.LogAsync(AuditAction.LoginSucceeded, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id, metadata: metadata);
    }

    /// <summary>
    /// Checks a second factor for the authorization server's two-factor page, applying the rules
    /// <c>POST /api/v1/auth/2fa/login</c> applies: lockout still counts, and every failure is
    /// a strike against it, so the factor cannot be brute-forced.
    /// </summary>
    public async Task<SecondFactorStatus> VerifySecondFactorAsync(ApplicationUser user, string? code, string? recoveryCode)
    {
        if (await _userManager.IsLockedOutAsync(user))
            return SecondFactorStatus.LockedOut;

        var usedRecoveryCode = false;

        if (!string.IsNullOrWhiteSpace(code))
        {
            var normalized = code.Replace(" ", string.Empty).Replace("-", string.Empty).Trim();
            var valid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, normalized);

            if (!valid)
                return await RejectSecondFactorAsync(user, "invalid_code");
        }
        else if (!string.IsNullOrWhiteSpace(recoveryCode))
        {
            var redeemed = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, recoveryCode.Trim());
            if (!redeemed.Succeeded)
                return await RejectSecondFactorAsync(user, "invalid_recovery_code");

            usedRecoveryCode = true;
        }
        else
        {
            return SecondFactorStatus.Missing;
        }

        await _userManager.ResetAccessFailedCountAsync(user);

        if (usedRecoveryCode)
        {
            var remaining = await _userManager.CountRecoveryCodesAsync(user);
            _logger.LogWarning("User {UserId} signed in with a recovery code ({Remaining} remaining)", user.Id, remaining);
            await _audit.LogAsync(AuditAction.TwoFactorRecoveryCodeUsed, actorUserId: user.Id,
                actorEmail: user.Email, targetUserId: user.Id, metadata: new { remainingRecoveryCodes = remaining });
        }

        return SecondFactorStatus.Succeeded;
    }

    /// <summary>
    /// Whether a user who authenticated may be given an authorization-server session now. The
    /// token being valid, or the frontend vouching for the user, says nothing about the account
    /// still being in good standing (N6, N7).
    /// </summary>
    public async Task<SignInIneligibility> CheckEligibilityAsync(ApplicationUser user)
    {
        if (user.IsDeleted)
            return SignInIneligibility.Deleted;

        if (await _userManager.IsLockedOutAsync(user))
            return SignInIneligibility.LockedOut;

        if (RequireConfirmedEmail && !user.EmailConfirmed)
            return SignInIneligibility.EmailNotConfirmed;

        var required = _consentSettings.Value;
        var latest = await _db.UserConsents
            .AsNoTracking()
            .Where(c => c.UserId == user.Id && (c.Type == ConsentType.Terms || c.Type == ConsentType.Privacy))
            .GroupBy(c => c.Type)
            .Select(g => new { Type = g.Key, Version = g.OrderByDescending(x => x.AcceptedAt).Select(x => x.Version).First() })
            .ToListAsync();

        var terms = latest.FirstOrDefault(x => x.Type == ConsentType.Terms)?.Version;
        var privacy = latest.FirstOrDefault(x => x.Type == ConsentType.Privacy)?.Version;

        return terms != required.Terms || privacy != required.Privacy
            ? SignInIneligibility.ConsentRequired
            : SignInIneligibility.None;
    }

    /// <summary>
    /// Starts the authorization server's own cookie session. It carries the security stamp, so a
    /// password change or reset ends it too.
    /// </summary>
    public async Task SignInToAuthorizationServerAsync(HttpContext http, ApplicationUser user)
    {
        var identity = new ClaimsIdentity(AuthorizationServerDefaults.CookieScheme);
        identity.AddClaim(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject, user.Id));
        identity.AddClaim(new Claim(
            _userManager.Options.ClaimsIdentity.SecurityStampClaimType,
            await _userManager.GetSecurityStampAsync(user)));

        await http.SignInAsync(AuthorizationServerDefaults.CookieScheme, new ClaimsPrincipal(identity), new AuthenticationProperties
        {
            IsPersistent = false,
            AllowRefresh = false,
            ExpiresUtc = DateTimeOffset.UtcNow.Add(AuthorizationServerDefaults.SessionLifetime)
        });
    }

    /// <summary>The user signed in to the authorization server's cookie session, if the session is still good.</summary>
    public async Task<ApplicationUser?> GetAuthorizationServerUserAsync(HttpContext http)
    {
        var result = await http.AuthenticateAsync(AuthorizationServerDefaults.CookieScheme);
        if (!result.Succeeded)
            return null;

        var userId = result.Principal.FindFirstValue(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject);
        var stamp = result.Principal.FindFirstValue(_userManager.Options.ClaimsIdentity.SecurityStampClaimType);
        if (userId is null || stamp is null)
            return null;

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null || !string.Equals(await _userManager.GetSecurityStampAsync(user), stamp, StringComparison.Ordinal))
            return null;

        return user;
    }

    private async Task<SecondFactorStatus> RejectSecondFactorAsync(ApplicationUser user, string reason)
    {
        await _userManager.AccessFailedAsync(user);

        await _audit.LogAsync(AuditAction.TwoFactorChallengeFailed, targetUserId: user.Id,
            succeeded: false, metadata: new { reason });

        return SecondFactorStatus.Invalid;
    }
}
