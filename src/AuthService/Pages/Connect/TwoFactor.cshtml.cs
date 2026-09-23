using AuthService.Extensions;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AuthService.Pages.Connect;

/// <summary>
/// The second factor, after a password or an external provider, in Hosted mode. The first factor
/// leaves the existing two-factor challenge token in an HttpOnly cookie; this page redeems it with
/// the same rules as <c>POST /api/v1/auth/2fa/login</c>, where every wrong code counts toward lockout.
/// </summary>
public class TwoFactorModel(
    SignInFlow _signInFlow,
    ITokenService _tokenService,
    UserManager<ApplicationUser> _userManager,
    IOptionsSnapshot<AuthorizationServerOptions> _options,
    IConfiguration _configuration
) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    public string? Code { get; set; }

    [BindProperty]
    public string? RecoveryCode { get; set; }

    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        if (_options.Value.Interaction.Mode != AuthorizationServerInteractionMode.Hosted)
            return NotFound();
        if (!IsAuthorizationRequest(ReturnUrl))
            return BadRequest("This page is reached from an application's sign-in request.");

        return await GetChallengedUserAsync() is null ? RestartSignIn() : Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (_options.Value.Interaction.Mode != AuthorizationServerInteractionMode.Hosted)
            return NotFound();
        if (!IsAuthorizationRequest(ReturnUrl))
            return BadRequest("This page is reached from an application's sign-in request.");

        var user = await GetChallengedUserAsync();
        if (user is null)
            return RestartSignIn();

        switch (await _signInFlow.VerifySecondFactorAsync(user, Code, RecoveryCode))
        {
            case SecondFactorStatus.Missing:
                Error = "Enter the code from your authenticator app, or a recovery code.";
                return Page();

            case SecondFactorStatus.Invalid:
                Error = "That code is not valid.";
                return Page();

            case SecondFactorStatus.LockedOut:
                Error = "This account is temporarily locked after too many failed attempts. Try again later.";
                return Page();
        }

        var ineligible = await _signInFlow.CheckEligibilityAsync(user);
        if (ineligible != SignInIneligibility.None)
        {
            Error = SignInModel.DescribeIneligibility(ineligible, _configuration["App:Name"] ?? "Auth Service");
            return Page();
        }

        DeleteChallenge();

        await _signInFlow.CompleteSignInAsync(user, new
        {
            surface = "authorization_server",
            secondFactor = string.IsNullOrWhiteSpace(Code) ? "recovery_code" : "totp"
        });
        await _signInFlow.SignInToAuthorizationServerAsync(HttpContext, user);

        return LocalRedirect(ReturnUrl!);
    }

    private async Task<ApplicationUser?> GetChallengedUserAsync()
    {
        var challenge = Request.Cookies[AuthorizationServerDefaults.TwoFactorCookieName];
        var userId = string.IsNullOrEmpty(challenge) ? null : _tokenService.GetUserIdFromTwoFactorChallengeToken(challenge);
        if (userId is null)
            return null;

        var user = await _userManager.FindByIdAsync(userId);
        return user is { IsDeleted: false, TwoFactorEnabled: true } ? user : null;
    }

    private IActionResult RestartSignIn()
    {
        DeleteChallenge();
        return LocalRedirect($"{AuthorizationServerDefaults.SignInPage}?returnUrl={Uri.EscapeDataString(ReturnUrl!)}");
    }

    private void DeleteChallenge() =>
        Response.Cookies.Delete(AuthorizationServerDefaults.TwoFactorCookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = AuthorizationServerDefaults.CookiePath
        });

    private bool IsAuthorizationRequest(string? returnUrl) => SignInModel.IsAuthorizationRequest(Url, returnUrl);
}
