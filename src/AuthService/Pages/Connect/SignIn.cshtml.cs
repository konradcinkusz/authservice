using System.Text.Json;
using AuthService.Extensions;
using AuthService.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AuthService.Pages.Connect;

/// <summary>
/// The authorization server's sign-in page, in Hosted mode (A11). Password sign-in runs the same
/// decision as <c>POST /api/v1/auth/login</c> (<see cref="SignInFlow"/>); external providers go
/// through the existing <c>ExternalAuthController</c> and come back to
/// <see cref="ExternalReturnModel"/>. The session it starts is the authorization server's own
/// cookie, never Identity's.
/// </summary>
public class SignInModel(
    SignInFlow _signInFlow,
    ITokenService _tokenService,
    IOptionsSnapshot<AuthorizationServerOptions> _options,
    IConfiguration _configuration,
    IDataProtectionProvider _dataProtection,
    AuthorizationServerIssuer _issuer
) : PageModel
{
    /// <summary>The authorization request to resume. Only ever this server's own authorization endpoint.</summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public string? Error { get; private set; }

    public string? ClientName { get; private set; }

    public IReadOnlyList<string> Providers { get; private set; } = [];

    /// <summary>Where registration and password reset live (N7): the product, not these pages.</summary>
    public string? ProductUrl => Uri.TryCreate(_configuration["FrontendBaseUrl"], UriKind.Absolute, out var uri) ? uri.ToString() : null;

    public string AppName => _configuration["App:Name"] ?? "Auth Service";

    public IActionResult OnGet()
    {
        if (!IsHosted)
            return NotFound();
        if (!IsAuthorizationRequest(ReturnUrl))
            return BadRequest("This page is reached from an application's sign-in request.");

        Describe();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!IsHosted)
            return NotFound();
        if (!IsAuthorizationRequest(ReturnUrl))
            return BadRequest("This page is reached from an application's sign-in request.");

        Describe();

        if (string.IsNullOrWhiteSpace(Email) || string.IsNullOrEmpty(Password))
        {
            Error = "Enter your email address and password.";
            return Page();
        }

        var outcome = await _signInFlow.CheckPasswordAsync(Email.Trim(), Password);

        switch (outcome.Status)
        {
            case PasswordSignInStatus.Failed:
                Error = "Invalid email or password.";
                return Page();

            case PasswordSignInStatus.LockedOut:
                Error = "This account is temporarily locked after too many failed sign-in attempts. Try again later.";
                return Page();

            case PasswordSignInStatus.EmailNotConfirmed:
                Error = "Verify your email address before signing in.";
                return Page();
        }

        var user = outcome.User!;

        var ineligible = await _signInFlow.CheckEligibilityAsync(user);
        if (ineligible != SignInIneligibility.None)
        {
            Error = DescribeIneligibility(ineligible, AppName);
            return Page();
        }

        if (outcome.Status == PasswordSignInStatus.RequiresTwoFactor)
        {
            SetTwoFactorChallenge(Response, _tokenService.GenerateTwoFactorChallengeToken(user));
            return LocalRedirect($"{AuthorizationServerDefaults.TwoFactorPage}?returnUrl={Uri.EscapeDataString(ReturnUrl!)}");
        }

        await _signInFlow.CompleteSignInAsync(user, new { surface = "authorization_server" });
        await _signInFlow.SignInToAuthorizationServerAsync(HttpContext, user);

        return LocalRedirect(ReturnUrl!);
    }

    /// <summary>
    /// Starts an external-provider sign-in through the existing flow, unchanged. The round trip
    /// is bound to this browser: a nonce rides in the return URL and in a cookie, and the landing
    /// page refuses a code whose nonce does not match, so nobody can finish this request with an
    /// exchange code of their own (login CSRF).
    /// </summary>
    public IActionResult OnGetExternal(string? provider)
    {
        if (!IsHosted)
            return NotFound();
        if (!IsAuthorizationRequest(ReturnUrl))
            return BadRequest("This page is reached from an application's sign-in request.");

        Describe();
        if (provider is null || !Providers.Contains(provider, StringComparer.Ordinal))
        {
            Error = "That sign-in provider is not available.";
            return Page();
        }

        var nonce = TokenHasher.GenerateUrlSafeToken(32);
        var protector = _dataProtection.CreateProtector(ExternalResume.Purpose).ToTimeLimitedDataProtector();
        var payload = protector.Protect(JsonSerializer.Serialize(new ExternalResume(nonce, ReturnUrl!)), ExternalResume.Lifetime);

        Response.Cookies.Append(AuthorizationServerDefaults.ExternalResumeCookieName, payload, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = AuthorizationServerDefaults.ExternalReturnPage,
            MaxAge = ExternalResume.Lifetime,
            IsEssential = true
        });

        var returnTo = $"{_issuer.Value}{AuthorizationServerDefaults.ExternalReturnPage}?resume={nonce}";
        return Redirect($"/api/v1/external-auth/login?provider={Uri.EscapeDataString(provider)}&returnUrl={Uri.EscapeDataString(returnTo)}");
    }

    private bool IsHosted => _options.Value.Interaction.Mode == AuthorizationServerInteractionMode.Hosted;

    private void Describe()
    {
        // Only providers whose credentials are configured, as the provider discovery endpoint does.
        var providers = new List<string>();
        if (!string.IsNullOrWhiteSpace(_configuration["OAuth:Google:ClientId"]))
            providers.Add("Google");
        if (!string.IsNullOrWhiteSpace(_configuration["OAuth:GitHub:ClientId"]))
            providers.Add("GitHub");
        Providers = providers;

        ClientName = ClientNameFor(ReturnUrl, _options.Value);
    }

    private bool IsAuthorizationRequest(string? returnUrl) => IsAuthorizationRequest(Url, returnUrl);

    /// <summary>A local URL for this server's authorization endpoint, and nothing else: never an open redirect.</summary>
    internal static bool IsAuthorizationRequest(IUrlHelper url, string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl)
        && url.IsLocalUrl(returnUrl)
        && returnUrl.StartsWith(AuthorizationServerDefaults.AuthorizationEndpoint + "?", StringComparison.Ordinal);

    internal static string? ClientNameFor(string? returnUrl, AuthorizationServerOptions options)
    {
        var query = returnUrl?.IndexOf('?') is int i and >= 0 ? returnUrl[i..] : null;
        if (query is null)
            return null;

        var clientId = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(query).TryGetValue("client_id", out var value)
            ? value.ToString()
            : null;

        return options.FindClient(clientId)?.DisplayName;
    }

    internal static void SetTwoFactorChallenge(HttpResponse response, string challengeToken) =>
        response.Cookies.Append(AuthorizationServerDefaults.TwoFactorCookieName, challengeToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = AuthorizationServerDefaults.CookiePath,
            MaxAge = TimeSpan.FromMinutes(5),
            IsEssential = true
        });

    internal static string DescribeIneligibility(SignInIneligibility reason, string appName) => reason switch
    {
        SignInIneligibility.LockedOut => "This account is temporarily locked. Try again later.",
        SignInIneligibility.EmailNotConfirmed => "Verify your email address before signing in.",
        SignInIneligibility.ConsentRequired =>
            $"The terms have changed since you last accepted them. Sign in to {appName} to accept the new version, then try again.",
        _ => "This account cannot be used to sign in."
    };
}

/// <summary>What the external sign-in round trip carries in its cookie: the nonce, and the request to resume.</summary>
public sealed record ExternalResume(string Nonce, string ReturnUrl)
{
    public const string Purpose = "AuthService.AuthorizationServer.ExternalResume";

    /// <summary>Long enough for a provider's sign-in page; the exchange code itself lives a minute.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
}
