using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthService.Extensions;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AuthService.Pages.Connect;

/// <summary>
/// Where an external-provider sign-in started on <see cref="SignInModel"/> lands, in Hosted mode.
/// <c>ExternalAuthController</c> is unchanged: it redirects here, to a return URL on its allow
/// list, with its usual single-use exchange code, and this page redeems the code server-side
/// instead of a frontend doing it. The second factor, bypassed at the provider callback by
/// design, is applied here, exactly as the exchange endpoint applies it.
/// </summary>
public class ExternalReturnModel(
    SignInFlow _signInFlow,
    ITokenService _tokenService,
    IOAuthExchangeCodeService _exchangeCodes,
    UserManager<ApplicationUser> _userManager,
    IAuditService _audit,
    IDataProtectionProvider _dataProtection,
    IOptionsSnapshot<AuthorizationServerOptions> _options,
    IConfiguration _configuration
) : PageModel
{
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(string? resume, string? code)
    {
        if (_options.Value.Interaction.Mode != AuthorizationServerInteractionMode.Hosted)
            return NotFound();

        var cookie = Request.Cookies[AuthorizationServerDefaults.ExternalResumeCookieName];
        Response.Cookies.Delete(AuthorizationServerDefaults.ExternalResumeCookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = AuthorizationServerDefaults.ExternalReturnPage
        });

        // Bound to the browser that started it: someone else's exchange code, in a link, does
        // not carry this browser's nonce. Refused before the code is even looked at.
        if (!TryReadResume(cookie, out var state) || string.IsNullOrEmpty(resume) || !FixedTimeEquals(resume, state.Nonce))
        {
            Error = "This sign-in was not started in this browser, or took too long. Start again from the application.";
            return Page();
        }

        if (string.IsNullOrEmpty(code))
        {
            // Also what the legacy Auth:AllowTokensInOAuthRedirect switch produces: tokens in the
            // URL instead of a code, which this page does not accept.
            Error = "The sign-in provider did not complete the sign-in. Start again from the application.";
            return Page();
        }

        var userId = await _exchangeCodes.RedeemAsync(code, HttpContext.RequestAborted);
        var user = userId is null ? null : await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            Error = "The sign-in has expired. Start again from the application.";
            return Page();
        }

        var ineligible = await _signInFlow.CheckEligibilityAsync(user);
        if (ineligible != SignInIneligibility.None)
        {
            Error = SignInModel.DescribeIneligibility(ineligible, _configuration["App:Name"] ?? "Auth Service");
            return Page();
        }

        if (user.TwoFactorEnabled)
        {
            SignInModel.SetTwoFactorChallenge(Response, _tokenService.GenerateTwoFactorChallengeToken(user));
            return LocalRedirect($"{AuthorizationServerDefaults.TwoFactorPage}?returnUrl={Uri.EscapeDataString(state.ReturnUrl)}");
        }

        // The provider callback already recorded the last-login time, as for the exchange endpoint.
        await _audit.LogAsync(AuditAction.LoginSucceeded, actorUserId: user.Id, actorEmail: user.Email,
            targetUserId: user.Id, metadata: new { method = "oauth_exchange", surface = "authorization_server" });

        await _signInFlow.SignInToAuthorizationServerAsync(HttpContext, user);

        return LocalRedirect(state.ReturnUrl);
    }

    private bool TryReadResume(string? cookie, out ExternalResume state)
    {
        state = null!;
        if (string.IsNullOrEmpty(cookie))
            return false;

        try
        {
            var protector = _dataProtection.CreateProtector(ExternalResume.Purpose).ToTimeLimitedDataProtector();
            var candidate = JsonSerializer.Deserialize<ExternalResume>(protector.Unprotect(cookie));
            if (candidate is null ||
                !Url.IsLocalUrl(candidate.ReturnUrl) ||
                !candidate.ReturnUrl.StartsWith(AuthorizationServerDefaults.AuthorizationEndpoint + "?", StringComparison.Ordinal))
            {
                return false;
            }

            state = candidate;
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            return false;
        }
    }

    private static bool FixedTimeEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
}
