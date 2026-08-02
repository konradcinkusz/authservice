using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using System.Text.RegularExpressions;
using AuthService.Models;
using AuthService.Services;

namespace AuthService.Controllers;

/// <summary>
/// Handles external OAuth provider authentication (Google, GitHub, etc.)
/// </summary>
[ApiController]
[Route("api/external-auth")]
public class ExternalAuthController(
    UserManager<ApplicationUser> _userManager,
    SignInManager<ApplicationUser> _signInManager,
    ITokenService _tokenService,
    IConfiguration _configuration,
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
        // where a crafted returnUrl could cause JWT tokens to be sent to an attacker's server.
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
    /// Finds or creates the user, generates JWT tokens, and redirects to the frontend.
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

        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

        ApplicationUser? user;

        if (signInResult.Succeeded)
        {
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

        var tokenResponse = await _tokenService.GenerateTokensAsync(user);

        // Redirect to the frontend callback page with tokens in the query string; the
        // callback page is expected to move them into storage/cookies and strip the URL.
        var separator = redirectTarget.Contains('?') ? "&" : "?";
        var redirectUrl = $"{redirectTarget}{separator}accessToken={Uri.EscapeDataString(tokenResponse.AccessToken)}" +
                          $"&refreshToken={Uri.EscapeDataString(tokenResponse.RefreshToken)}" +
                          $"&expiresIn={tokenResponse.ExpiresIn}";

        return Redirect(redirectUrl);
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
    /// that JWT tokens are forwarded to their own server after a successful OAuth flow.
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
