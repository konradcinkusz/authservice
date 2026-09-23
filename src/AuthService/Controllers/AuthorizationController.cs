using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using AuthService.Data;
using AuthService.Extensions;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthService.Controllers;

/// <summary>
/// The authorization server's authorization and token endpoints (ADR 0005). OpenIddict parses
/// and validates each request first — client, exact redirect URI, PKCE, scopes and resource
/// permissions — and passes it through here only once it is valid; this controller decides who
/// the user is, whether they consented, and what the token says.
///
/// Who renders sign-in and consent is chosen per deployment and read at request time (A11):
/// the pages under <c>Pages/Connect</c> in Hosted mode, a consumer's frontend through the
/// interaction API in External mode.
/// </summary>
[AuthorizationServerSurface]
[ApiExplorerSettings(IgnoreApi = true)]
[IgnoreAntiforgeryToken] // A posted consent decision is validated explicitly; see Authorize.
public class AuthorizationController(
    IOptionsSnapshot<AuthorizationServerOptions> _options,
    UserManager<ApplicationUser> _userManager,
    SignInFlow _signInFlow,
    ITokenService _tokenService,
    IOpenIddictApplicationManager _applications,
    IOpenIddictAuthorizationManager _authorizations,
    IOpenIddictTokenManager _tokens,
    ApplicationDbContext _db,
    IAntiforgery _antiforgery,
    IAuditService _audit,
    AuthorizationServerTokenLimiter _tokenLimiter
) : Controller
{
    private const int MaxRequestQueryLength = 4000;

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The authorization request could not be retrieved.");

        // N10: every token is bound to exactly one resource, which becomes its audience.
        var resources = request.GetResources();
        if (resources.Length != 1)
            return ForbidWith(Errors.InvalidTarget, "Exactly one resource parameter is required.");

        return _options.Value.Interaction.Mode == AuthorizationServerInteractionMode.External
            ? await AuthorizeExternalAsync(request, resources[0])
            : await AuthorizeHostedAsync(request, resources[0]);
    }

    [HttpPost("~/connect/token")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The token request could not be retrieved.");

        // N4: the client authenticated before this ran, so the limit is its own, not its IP's.
        using var lease = _tokenLimiter.Acquire(request.ClientId!);
        if (!lease.IsAcquired)
        {
            var retryAfter = lease.TryGetMetadata(MetadataName.RetryAfter, out var value) ? (double?)value.TotalSeconds : null;
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                error = "Too many requests. Please try again later.",
                retryAfter
            });
        }

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The library admits only the authorization code and refresh token grants.");

        // The code or refresh token, already validated by the library: single use, PKCE
        // verified, issued to this client, and its authorization still valid.
        var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
            ?? throw new InvalidOperationException("The validated grant could not be retrieved.");

        // RFC 8707: a resource named here must be the one the grant was issued for.
        var granted = principal.GetResources();
        if (request.GetResources().Any(r => !granted.Any(g => SameResource(g, r))))
            return ForbidWith(Errors.InvalidTarget, "The resource was not granted to this authorization.");

        // A10: every exchange re-checks the account and rebuilds the claims from its current
        // state, so a role or membership change reaches the next token, and a deleted or
        // locked-out account gets no more — as the existing refresh does.
        var user = await _userManager.FindByIdAsync(principal.GetClaim(Claims.Subject)!);
        if (user is null || user.IsDeleted || await _userManager.IsLockedOutAsync(user))
        {
            if (principal.GetAuthorizationId() is { } authorizationId)
                await _tokens.RevokeByAuthorizationIdAsync(authorizationId);

            return ForbidWith(Errors.InvalidGrant, "The account is no longer allowed to sign in.");
        }

        var identity = await CreateIdentityAsync(user, principal.GetScopes(), granted);
        identity.SetAuthorizationId(principal.GetAuthorizationId());

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> AuthorizeHostedAsync(OpenIddictRequest request, string resource)
    {
        var user = await _signInFlow.GetAuthorizationServerUserAsync(HttpContext);

        if (user is null || request.HasPromptValue(PromptValues.Login))
        {
            if (request.HasPromptValue(PromptValues.None))
                return ForbidWith(Errors.LoginRequired, "The user is not signed in.");

            // Back here after signing in, without the prompt that sent the user there.
            return Challenge(
                new AuthenticationProperties { RedirectUri = AuthorizationServerDefaults.AuthorizationEndpoint + ParametersWithout(Parameters.Prompt) },
                AuthorizationServerDefaults.CookieScheme);
        }

        // The session outlived the account's good standing: sign in again, where the page says why not.
        if (await _signInFlow.CheckEligibilityAsync(user) != SignInIneligibility.None)
        {
            await HttpContext.SignOutAsync(AuthorizationServerDefaults.CookieScheme);
            return Challenge(
                new AuthenticationProperties { RedirectUri = AuthorizationServerDefaults.AuthorizationEndpoint + ParametersWithout(Parameters.Prompt) },
                AuthorizationServerDefaults.CookieScheme);
        }

        var applicationId = await GetApplicationIdAsync(request.ClientId!);
        var scopes = request.GetScopes();

        // The consent page posts the decision back here, so the library validates the whole
        // request again before a code is issued on the strength of it.
        if (HttpMethods.IsPost(Request.Method) && Request.HasFormContentType &&
            Request.Form.TryGetValue(AuthorizationServerDefaults.ConsentParameter, out var decision))
        {
            if (!await _antiforgery.IsRequestValidAsync(HttpContext))
                return BadRequest("The consent form has expired. Start again from the application.");

            var accepted = decision == "accept";

            await _audit.LogAsync(
                accepted ? AuditAction.OAuthConsentGranted : AuditAction.OAuthConsentDenied,
                actorUserId: user.Id, actorEmail: user.Email, targetUserId: user.Id,
                metadata: new { clientId = request.ClientId, scopes, resource, mode = "hosted" });

            return accepted
                ? await IssueCodeAsync(user, applicationId, scopes, resource)
                : ForbidWith(Errors.AccessDenied, "The user declined the request.");
        }

        // N2: consent is remembered per user and client, and asked again for new scopes.
        if (!request.HasPromptValue(PromptValues.Consent) &&
            await FindRememberedConsentAsync(user.Id, applicationId, scopes) is { } remembered)
        {
            return await IssueCodeAsync(user, applicationId, scopes, resource, remembered);
        }

        if (request.HasPromptValue(PromptValues.None))
            return ForbidWith(Errors.ConsentRequired, "The user has not consented to this client.");

        return LocalRedirect(AuthorizationServerDefaults.ConsentPage + ParametersWithout(Parameters.Prompt));
    }

    /// <summary>
    /// External mode (A12): park the request, bind it to this browser, and send the browser to
    /// the consumer's frontend — or, when it comes back with a ticket, finish the request.
    /// </summary>
    private async Task<IActionResult> AuthorizeExternalAsync(OpenIddictRequest request, string resource)
    {
        var parameters = ParametersWithout(Parameters.Prompt, AuthorizationServerDefaults.InteractionTicketParameter);

        var ticket = RequestValue(AuthorizationServerDefaults.InteractionTicketParameter);
        if (!string.IsNullOrEmpty(ticket))
            return await CompleteExternalAsync(ticket, parameters);

        if (parameters.Value!.Length > MaxRequestQueryLength)
            return ForbidWith(Errors.InvalidRequest, "The authorization request is too long.");

        // One binding value per browser, reused across its interactions.
        var binding = Request.Cookies[AuthorizationServerDefaults.BrowserBindingCookieName];
        if (string.IsNullOrEmpty(binding) || binding.Length > 64)
            binding = TokenHasher.GenerateUrlSafeToken(32);

        var handle = TokenHasher.GenerateUrlSafeToken(32);
        var now = DateTime.UtcNow;

        _db.AuthorizationInteractions.Add(new AuthorizationInteraction
        {
            HandleHash = TokenHasher.Hash(handle),
            BrowserBindingHash = TokenHasher.Hash(binding),
            ClientId = request.ClientId!,
            RequestQuery = parameters.Value,
            Scopes = string.Join(' ', request.GetScopes()),
            Resource = resource,
            CreatedAt = now,
            ExpiresAt = now.Add(AuthorizationInteraction.DefaultLifetime)
        });
        await _db.SaveChangesAsync();

        Response.Cookies.Append(AuthorizationServerDefaults.BrowserBindingCookieName, binding, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = AuthorizationServerDefaults.CookiePath,
            MaxAge = AuthorizationInteraction.DefaultLifetime,
            IsEssential = true
        });

        // A11: always the configured page, never anything taken from the request.
        return Redirect(QueryHelpers.AddQueryString(_options.Value.Interaction.ExternalUrl!, "interaction", handle));
    }

    private async Task<IActionResult> CompleteExternalAsync(string ticket, QueryString parameters)
    {
        var now = DateTime.UtcNow;
        var ticketHash = TokenHasher.Hash(ticket);

        // Single use, atomically: the conditional UPDATE is the redemption, so two requests
        // racing with one ticket cannot both succeed.
        var redeemed = await _db.AuthorizationInteractions
            .Where(i => i.TicketHash == ticketHash && i.CompletedAt == null && i.TicketExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(i => i.CompletedAt, now));

        if (redeemed != 1)
            return ForbidWith(Errors.AccessDenied, "The interaction ticket is invalid, expired or already used.");

        var interaction = await _db.AuthorizationInteractions.AsNoTracking().SingleAsync(i => i.TicketHash == ticketHash);

        // Only the browser that started the interaction may finish it. Without this, a ticket
        // issued to an attacker's own account could complete a victim's request, connecting the
        // victim's client to the attacker's data (login CSRF).
        var binding = Request.Cookies[AuthorizationServerDefaults.BrowserBindingCookieName];
        if (string.IsNullOrEmpty(binding) || !FixedTimeEquals(TokenHasher.Hash(binding), interaction.BrowserBindingHash))
            return ForbidWith(Errors.AccessDenied, "The request was started in a different browser.");

        if (!SameParameters(interaction.RequestQuery, parameters.Value!))
            return ForbidWith(Errors.InvalidRequest, "The request does not match the interaction it resumes.");

        if (interaction.Decision != AuthorizationInteractionDecision.Accepted)
            return ForbidWith(Errors.AccessDenied, "The user declined the request.");

        var user = interaction.UserId is null ? null : await _userManager.FindByIdAsync(interaction.UserId);
        if (user is null || await _signInFlow.CheckEligibilityAsync(user) != SignInIneligibility.None)
            return ForbidWith(Errors.AccessDenied, "The account cannot be used to authorize this client.");

        var applicationId = await GetApplicationIdAsync(interaction.ClientId);
        var scopes = interaction.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToImmutableArray();

        return await IssueCodeAsync(user, applicationId, scopes, interaction.Resource);
    }

    /// <summary>
    /// Issues the authorization code. The permanent authorization it hangs off is what remembers
    /// consent (N2) and what revocation ends (AC6).
    /// </summary>
    private async Task<IActionResult> IssueCodeAsync(
        ApplicationUser user, string applicationId, ImmutableArray<string> scopes, string resource, object? authorization = null)
    {
        var identity = await CreateIdentityAsync(user, scopes, [resource]);

        authorization ??= await FindRememberedConsentAsync(user.Id, applicationId, scopes)
            ?? await _authorizations.CreateAsync(identity, user.Id, applicationId, AuthorizationTypes.Permanent, identity.GetScopes());

        identity.SetAuthorizationId(await _authorizations.GetIdAsync(authorization));

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// The access token's contents (A9): the claims existing tokens carry, from the same builder
    /// and under the same names (AC4, AC7), plus the granted scopes and the resource as audience.
    /// The library supplies <c>jti</c>, <c>iat</c>, <c>exp</c>, <c>client_id</c> and <c>scope</c> itself.
    /// </summary>
    private async Task<ClaimsIdentity> CreateIdentityAsync(ApplicationUser user, IEnumerable<string> scopes, IEnumerable<string> resources)
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

        identity.AddClaims((await _tokenService.BuildClaimsAsync(user)).Where(claim => claim.Type != JwtRegisteredClaimNames.Jti));

        identity.SetScopes(scopes);
        identity.SetResources(resources);
        identity.SetDestinations(static _ => [Destinations.AccessToken]);

        return identity;
    }

    private async Task<object?> FindRememberedConsentAsync(string userId, string applicationId, ImmutableArray<string> scopes)
    {
        await foreach (var authorization in _authorizations.FindAsync(
            subject: userId, client: applicationId, status: Statuses.Valid, type: AuthorizationTypes.Permanent, scopes: scopes))
        {
            return authorization;
        }

        return null;
    }

    private async Task<string> GetApplicationIdAsync(string clientId)
    {
        var application = await _applications.FindByClientIdAsync(clientId)
            ?? throw new InvalidOperationException("The client is not registered.");

        return (await _applications.GetIdAsync(application))!;
    }

    private ForbidResult ForbidWith(string error, string description) =>
        Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    private string? RequestValue(string name)
    {
        if (Request.HasFormContentType && Request.Form.TryGetValue(name, out var posted))
            return posted.ToString();

        return Request.Query.TryGetValue(name, out var value) ? value.ToString() : null;
    }

    /// <summary>The authorization request's own parameters, as a query string, minus the ones named.</summary>
    private QueryString ParametersWithout(params string[] excluded)
    {
        IEnumerable<KeyValuePair<string, StringValues>> source = Request.HasFormContentType ? Request.Form : Request.Query;

        return QueryString.Create(source.Where(p =>
            !excluded.Contains(p.Key, StringComparer.Ordinal) &&
            p.Key != AuthorizationServerDefaults.ConsentParameter &&
            p.Key != "__RequestVerificationToken"));
    }

    private static bool SameParameters(string stored, string current)
    {
        var left = QueryHelpers.ParseQuery(stored);
        var right = QueryHelpers.ParseQuery(current);

        return left.Count == right.Count && left.All(pair =>
            right.TryGetValue(pair.Key, out var other) &&
            pair.Value.OrderBy(v => v, StringComparer.Ordinal).SequenceEqual(other.OrderBy(v => v, StringComparer.Ordinal), StringComparer.Ordinal));
    }

    /// <summary>Equal, or the same origin root with and without its trailing slash (N10).</summary>
    private static bool SameResource(string granted, string requested) =>
        string.Equals(granted, requested, StringComparison.Ordinal) ||
        AuthorizationClientSync.ResourceForms(granted).Contains(requested, StringComparer.Ordinal);

    private static bool FixedTimeEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
}
