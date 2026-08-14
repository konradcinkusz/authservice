using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.RegularExpressions;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;

namespace AuthService.Controllers;

/// <summary>
/// Handles external OAuth provider authentication (Google, GitHub, etc.)
/// </summary>
[ApiController]
[Route("api/v1/external-auth")]
[Route("api/external-auth")] // Unversioned alias. Prefer /api/v1.
public class ExternalAuthController(
    UserManager<ApplicationUser> _userManager,
    SignInManager<ApplicationUser> _signInManager,
    ITokenService _tokenService,
    IConfiguration _configuration,
    IOptions<AuthOptions> _authOptions,
    IProviderEmailVerifier _emailVerifier,
    IOAuthExchangeCodeService _exchangeCodes,
    IAuditService _audit,
    ILogger<ExternalAuthController> _logger,
    IEmailService _emailService
) : ControllerBase
{
    private static readonly string[] AllowedProviders = ["Google", "GitHub"];

    /// <summary>
    /// Initiates the OAuth flow by redirecting the user to the external provider.
    /// </summary>
    /// <param name="provider">OAuth provider name (Google or GitHub)</param>
    /// <param name="returnUrl">Frontend URL to redirect to after successful authentication</param>
    [HttpGet("login")]
    [EnableRateLimiting("auth")]
    public IActionResult Login([FromQuery] string provider, [FromQuery] string? returnUrl = null)
    {
        if (string.IsNullOrWhiteSpace(provider) || !AllowedProviders.Contains(provider, StringComparer.OrdinalIgnoreCase))
            return BadRequest(new { error = $"Unsupported provider. Allowed: {string.Join(", ", AllowedProviders)}" });

        var postLoginBase = _configuration["OAuth:PostLoginRedirectBaseUrl"]
            ?? throw new InvalidOperationException("OAuth:PostLoginRedirectBaseUrl is not configured.");

        // OAuth:PostLoginRedirectAllowedBaseUrls (array) allows additional frontends to use OAuth.
        // Falls back to just postLoginBase when the array is not configured.
        var additionalAllowed = _configuration
            .GetSection("OAuth:PostLoginRedirectAllowedBaseUrls")
            .Get<string[]>() ?? [];
        var allAllowedBaseUrls = new[] { postLoginBase }
            .Concat(additionalAllowed)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .ToArray();

        // Validate returnUrl against the allowed origins to prevent open-redirect attacks
        // where a crafted returnUrl could cause the exchange code to be sent to an attacker's server.
        if (returnUrl != null && !IsAllowedReturnUrl(returnUrl, allAllowedBaseUrls))
        {
            _logger.LogWarning("Rejected OAuth login with disallowed returnUrl: {ReturnUrl}", returnUrl);
            return BadRequest(new { error = "returnUrl is not from an allowed origin." });
        }

        var callbackReturnUrl = returnUrl ?? $"{postLoginBase}/oauth/callback";

        // Build the callback URL that Google/GitHub will redirect back to.
        // IMPORTANT: must be a clean URL with NO query parameters — Google does
        // an exact match against the registered redirect URI.
        var callbackBaseUrl = _configuration["OAuth:CallbackBaseUrl"];
        // Deliberately the unversioned path: this exact string is registered as the redirect
        // URI at Google and GitHub, and changing it would require re-registering it there.
        // The /api/... alias resolves to the same action as /api/v1/....
        var callbackUrl = string.IsNullOrWhiteSpace(callbackBaseUrl)
            ? Url.Action(nameof(Callback), "ExternalAuth", values: null, protocol: Request.Scheme)!
            : $"{callbackBaseUrl.TrimEnd('/')}/api/external-auth/callback";

        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, callbackUrl);

        // returnUrl is stored in the OAuth state (opaque to Google / GitHub), NOT in the
        // callback URL, so it never affects redirect URI matching.
        properties.Items["returnUrl"] = callbackReturnUrl;

        return Challenge(properties, provider);
    }

    /// <summary>
    /// Callback endpoint invoked by the external OAuth provider after authentication.
    /// Finds or creates the user, then redirects to the frontend with a single-use exchange
    /// code — never with the tokens themselves.
    /// </summary>
    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string? returnUrl = null)
    {
        var postLoginBase = _configuration["OAuth:PostLoginRedirectBaseUrl"]
            ?? throw new InvalidOperationException("OAuth:PostLoginRedirectBaseUrl is not configured.");
        var errorRedirectBase = $"{_configuration["OAuth:ErrorRedirectBaseUrl"] ?? postLoginBase}/login";

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            _logger.LogWarning("External login info not found in callback");
            return Redirect($"{errorRedirectBase}?error=oauth_failed");
        }

        var redirectTarget = info.AuthenticationProperties?.Items.TryGetValue("returnUrl", out var stateUrl) == true
            ? stateUrl ?? returnUrl ?? $"{postLoginBase}/oauth/callback"
            : returnUrl ?? $"{postLoginBase}/oauth/callback";

        // The second factor, when configured, is applied at exchange time — see Exchange().
        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

        ApplicationUser? user;

        if (signInResult.Succeeded)
        {
            // Already-linked provider identity: the provider key itself is the proof, so no
            // email verification is involved.
            user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        }
        else if (signInResult.IsLockedOut)
        {
            _logger.LogWarning("Locked out user attempted OAuth login via {Provider}", info.LoginProvider);
            return Redirect($"{errorRedirectBase}?error=locked_out");
        }
        else
        {
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogWarning("OAuth provider {Provider} did not return an email address", info.LoginProvider);
                return Redirect($"{errorRedirectBase}?error=no_email");
            }

            // SECURITY: the email address decides which local account this provider identity
            // gets attached to. An address the provider has not verified is an assertion by
            // whoever controls the provider account, not by the address owner — accepting it
            // is the classic pre-hijacking account-takeover path.
            if (_authOptions.Value.RequireVerifiedProviderEmail)
            {
                var verification = await _emailVerifier.VerifyAsync(info, email, HttpContext.RequestAborted);

                if (!verification.IsVerified)
                {
                    _logger.LogWarning(
                        "Refused to link {Provider} identity to {Email}: provider did not verify the address ({Reason})",
                        info.LoginProvider, email, verification.Reason);

                    await _audit.LogAsync(
                        AuditAction.OAuthLinkRejectedUnverified,
                        succeeded: false,
                        metadata: new { provider = info.LoginProvider, email, reason = verification.Reason });

                    return Redirect($"{errorRedirectBase}?error=email_not_verified&provider={Uri.EscapeDataString(info.LoginProvider)}");
                }
            }

            user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                var userName = GenerateUserNameFromEmail(email);
                var baseUserName = userName;
                var suffix = 1;
                while (await _userManager.FindByNameAsync(userName) != null)
                {
                    userName = $"{baseUserName}{suffix}";
                    suffix++;
                }

                var rawPictureUrl = info.Principal.FindFirstValue("picture")
                    ?? info.Principal.FindFirstValue("avatar_url");
                var pictureUrl = NormalizeProfilePictureUrl(rawPictureUrl);

                user = new ApplicationUser
                {
                    UserName = userName,
                    Email = email,
                    // The provider verified this address (checked above), so it is confirmed here.
                    EmailConfirmed = true,
                    ProfileImageUrl = pictureUrl,
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to create user from OAuth: {Errors}", errors);
                    return Redirect($"{errorRedirectBase}?error=creation_failed");
                }

                _logger.LogInformation("Created new user {Email} via {Provider} OAuth", email, info.LoginProvider);

                await _audit.LogAsync(AuditAction.OAuthAccountCreated, actorUserId: user.Id, actorEmail: email,
                    targetUserId: user.Id, metadata: new { provider = info.LoginProvider });

                try
                {
                    await _emailService.SendWelcomeEmailAsync(email, user.UserName ?? email);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send welcome email to {Email}", email);
                }
            }
            else
            {
                _logger.LogInformation("Linked existing account {Email} to {Provider} OAuth", email, info.LoginProvider);

                await _audit.LogAsync(AuditAction.OAuthAccountLinked, actorUserId: user.Id, actorEmail: email,
                    targetUserId: user.Id, metadata: new { provider = info.LoginProvider });
            }

            var addLoginResult = await _userManager.AddLoginAsync(user, info);
            if (!addLoginResult.Succeeded)
            {
                var errors = string.Join(", ", addLoginResult.Errors.Select(e => e.Description));
                _logger.LogError("Failed to link {Provider} login: {Errors}", info.LoginProvider, errors);
                return Redirect($"{errorRedirectBase}?error=link_failed");
            }

            try
            {
                await _emailService.SendOAuthAccountLinkedEmailAsync(email, info.LoginProvider);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send OAuth account linked notification to {Email}", email);
            }
        }

        if (user == null)
        {
            return Redirect($"{errorRedirectBase}?error=user_not_found");
        }

        if (user.IsDeleted)
        {
            _logger.LogWarning("Soft-deleted user {Email} attempted OAuth login via {Provider}", user.Email, info.LoginProvider);
            return Redirect($"{errorRedirectBase}?error=account_deleted");
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("User {Email} authenticated via {Provider}", user.Email, info.LoginProvider);

        var separator = redirectTarget.Contains('?') ? "&" : "?";

        // Legacy escape hatch — tokens straight in the URL. Off by default; see AuthOptions.
        if (_authOptions.Value.AllowTokensInOAuthRedirect)
        {
            var tokenResponse = await _tokenService.GenerateTokensAsync(user);
            var legacyUrl = $"{redirectTarget}{separator}accessToken={Uri.EscapeDataString(tokenResponse.AccessToken)}" +
                            $"&refreshToken={Uri.EscapeDataString(tokenResponse.RefreshToken)}" +
                            $"&expiresIn={tokenResponse.ExpiresIn}";

            return Redirect(legacyUrl);
        }

        // A URL is not a confidential channel: it lands in browser history and its cloud
        // sync, the Referer of anything the callback page loads, and every access log on the
        // path. So the redirect carries a code that is single-use, expires in a minute, and
        // is worthless without a POST from the frontend.
        var exchangeCode = await _exchangeCodes.IssueAsync(user.Id, info.LoginProvider, HttpContext.RequestAborted);

        return Redirect($"{redirectTarget}{separator}code={Uri.EscapeDataString(exchangeCode)}");
    }

    /// <summary>
    /// Exchanges the single-use code from the OAuth callback redirect for tokens.
    /// Returns a two-factor challenge instead when the account has 2FA enabled.
    /// </summary>
    [HttpPost("exchange")]
    [EnableRateLimiting("auth")]
    // Returns TwoFactorRequiredResponse at this same 200 for a 2FA-enabled account.
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Exchange([FromBody] OAuthExchangeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Code))
            return BadRequest(new { error = "Code is required." });

        var userId = await _exchangeCodes.RedeemAsync(request.Code, HttpContext.RequestAborted);
        if (userId == null)
            return Unauthorized(new { error = "Invalid, expired, or already-used code." });

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null || user.IsDeleted)
            return Unauthorized(new { error = "Account is not available." });

        if (await _userManager.IsLockedOutAsync(user))
            return Unauthorized(new { error = "Account is temporarily locked." });

        // The OAuth callback deliberately bypasses Identity's own two-factor step so that the
        // second factor is applied here, on the API call, rather than mid-redirect.
        if (user.TwoFactorEnabled)
        {
            return Ok(new TwoFactorRequiredResponse(
                RequiresTwoFactor: true,
                ChallengeToken: _tokenService.GenerateTwoFactorChallengeToken(user),
                ExpiresIn: 300));
        }

        await _audit.LogAsync(AuditAction.LoginSucceeded, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id, metadata: new { method = "oauth_exchange" });

        return Ok(await _tokenService.GenerateTokensAsync(user));
    }

    /// <summary>
    /// Returns the list of OAuth providers configured and enabled.
    /// The frontend uses this to render the correct social login buttons.
    /// </summary>
    [HttpGet("providers")]
    public IActionResult GetProviders()
    {
        var configured = new List<object>();

        if (!string.IsNullOrWhiteSpace(_configuration["OAuth:Google:ClientId"]))
            configured.Add(new { provider = "Google", displayName = "Google" });

        if (!string.IsNullOrWhiteSpace(_configuration["OAuth:GitHub:ClientId"]))
            configured.Add(new { provider = "GitHub", displayName = "GitHub" });

        return Ok(new { providers = configured });
    }

    /// <summary>
    /// Returns true only when <paramref name="returnUrl"/> belongs to one of the
    /// <paramref name="allowedBaseUrls"/> origins and one of the known OAuth callback paths.
    /// Prevents open-redirect attacks where an attacker supplies a crafted returnUrl so
    /// that the exchange code is forwarded to their own server after a successful OAuth flow.
    /// </summary>
    private static bool IsAllowedReturnUrl(string returnUrl, string[] allowedBaseUrls)
    {
        if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var candidate))
            return false;

        var allowedPaths = new[] { "/oauth/callback" };
        var pathAllowed = allowedPaths.Any(p =>
            candidate.AbsolutePath.Equals(p, StringComparison.OrdinalIgnoreCase)
            || candidate.AbsolutePath.StartsWith(p + "/", StringComparison.OrdinalIgnoreCase));

        if (!pathAllowed)
            return false;

        return allowedBaseUrls.Any(baseUrl =>
        {
            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var allowed))
                return false;

            return string.Equals(candidate.Scheme, allowed.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(candidate.Host, allowed.Host, StringComparison.OrdinalIgnoreCase)
                && candidate.Port == allowed.Port;
        });
    }

    private static string GenerateUserNameFromEmail(string email)
    {
        var parts = email.Split('@');
        var localPart = parts[0].Replace(".", "").Replace("+", "");
        var sanitized = Regex.Replace(localPart, @"[^a-zA-Z0-9_-]", "");

        if (parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1]))
        {
            var domain = Regex.Replace(parts[1].Split('.')[0], @"[^a-zA-Z0-9_-]", "");
            sanitized = string.IsNullOrWhiteSpace(domain) ? sanitized : $"{sanitized}_{domain}";
        }

        if (sanitized.Length > 50)
            sanitized = sanitized[..50];

        return string.IsNullOrWhiteSpace(sanitized) ? "user" : sanitized;
    }

    /// <summary>
    /// Normalizes a Google (lh3.googleusercontent.com) profile picture URL so that
    /// it requests a 96 px image regardless of what size the OAuth provider originally
    /// returned. Non-Google URLs are returned unchanged.
    /// </summary>
    private static string? NormalizeProfilePictureUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return url;

        var normalized = Regex.Replace(url, @"=s\d+-c$", "=s96-c");

        if (normalized == url &&
            url.Contains("googleusercontent.com", StringComparison.OrdinalIgnoreCase) &&
            !url.Contains("=s", StringComparison.OrdinalIgnoreCase))
        {
            normalized = url + "=s96-c";
        }

        return normalized;
    }
}
