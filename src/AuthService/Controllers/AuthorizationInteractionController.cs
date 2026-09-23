using AuthService.Data;
using AuthService.Extensions;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthService.Controllers;

/// <summary>
/// The interaction API a consumer's frontend calls, through its BFF, in the authorization
/// server's External mode (A11, A12). The frontend signs the user in with the flows it already
/// has and asks for consent in its own pages; these endpoints tell it what is being asked, and
/// take the decision back.
///
/// Authenticated with the user's bearer token, on the authenticated trust level
/// (SERVICE-API-PATTERNS.md §2), and called server-side, so it needs no CORS (FRONTEND-BFF.md §1).
/// The frontend decides nothing about what is granted (A13): accepting confirms what was
/// requested and is allowed for the client, and no more.
/// </summary>
[ApiController]
[Authorize]
[AuthorizationServerSurface]
[EnableRateLimiting("api")]
[Route("api/v1/oauth/interactions")]
[Route("api/oauth/interactions")] // Unversioned alias. Prefer /api/v1.
public class AuthorizationInteractionController(
    ApplicationDbContext _db,
    IOptionsSnapshot<AuthorizationServerOptions> _options,
    UserManager<ApplicationUser> _userManager,
    SignInFlow _signInFlow,
    IAuditService _audit,
    AuthorizationServerIssuer _issuer
) : AuthControllerBase
{
    /// <summary>What a pending interaction asks for: which client, where it returns, and which scopes.</summary>
    [HttpGet("{handle}")]
    [ProducesResponseType(typeof(AuthorizationInteractionResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get(string handle)
    {
        if (!IsExternal)
            return NotFound();

        var interaction = await FindPendingAsync(handle);
        var client = interaction is null ? null : _options.Value.FindClient(interaction.ClientId);
        if (interaction is null || client is null)
            return NotFound(new { error = "No pending interaction matches this handle. It may have expired." });

        var redirectUri = QueryHelpers.ParseQuery(interaction.RequestQuery).TryGetValue("redirect_uri", out var value)
            ? value.ToString()
            : string.Empty;

        return Ok(new AuthorizationInteractionResponse(
            client.ClientId,
            client.DisplayName,
            Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri) ? uri.Host : string.Empty,
            SplitScopes(interaction.Scopes)
                .Select(s => new AuthorizationInteractionScope(s, _options.Value.DescribeScope(s)))
                .ToList(),
            interaction.Resource,
            interaction.ExpiresAt));
    }

    /// <summary>
    /// Records the signed-in user's consent and returns where to send the browser: authservice's
    /// own authorization endpoint, with a single-use ticket that only this browser can redeem.
    /// </summary>
    [HttpPost("{handle}/accept")]
    [ProducesResponseType(typeof(AuthorizationInteractionDecisionResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public Task<IActionResult> Accept(string handle, [FromBody] AcceptAuthorizationInteractionRequest? request) =>
        DecideAsync(handle, AuthorizationInteractionDecision.Accepted, request);

    /// <summary>Records a refusal. The browser still goes back through authservice, which tells the client.</summary>
    [HttpPost("{handle}/deny")]
    [ProducesResponseType(typeof(AuthorizationInteractionDecisionResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public Task<IActionResult> Deny(string handle) =>
        DecideAsync(handle, AuthorizationInteractionDecision.Denied, request: null);

    private async Task<IActionResult> DecideAsync(string handle, string decision, AcceptAuthorizationInteractionRequest? request)
    {
        if (!IsExternal)
            return NotFound();

        var userId = GetCurrentUserId();
        var user = userId is null ? null : await _userManager.FindByIdAsync(userId);
        if (user is null)
            return Unauthorized();

        var interaction = await FindPendingAsync(handle);
        if (interaction is null)
            return NotFound(new { error = "No pending interaction matches this handle. It may have expired." });

        if (decision == AuthorizationInteractionDecision.Accepted)
        {
            // A13: the frontend confirms what was asked; it cannot add a scope or a resource.
            if (request?.Scopes is { } scopes && !SplitScopes(interaction.Scopes).ToHashSet(StringComparer.Ordinal).SetEquals(scopes))
                return BadRequest(new { error = "invalid_scope", errorDescription = "Only the requested scopes can be accepted." });

            if (request?.Resource is { } resource && !string.Equals(resource, interaction.Resource, StringComparison.Ordinal))
                return BadRequest(new { error = "invalid_target", errorDescription = "Only the requested resource can be accepted." });

            // The frontend vouches that the user signed in; whether the account may be given
            // access is still this service's decision (N6, N7).
            var ineligible = await _signInFlow.CheckEligibilityAsync(user);
            if (ineligible != SignInIneligibility.None)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    error = "account_not_eligible",
                    reason = ineligible switch
                    {
                        SignInIneligibility.ConsentRequired => "consent_required",
                        SignInIneligibility.EmailNotConfirmed => "email_not_confirmed",
                        SignInIneligibility.LockedOut => "locked_out",
                        _ => "account_unavailable"
                    }
                });
            }
        }

        var ticket = TokenHasher.GenerateUrlSafeToken(32);
        var ticketHash = TokenHasher.Hash(ticket);
        var now = DateTime.UtcNow;
        var ticketExpiresAt = now.Add(AuthorizationInteraction.TicketLifetime);

        // First decision wins, atomically: whoever decides binds the interaction to themselves,
        // and nobody can decide it again.
        var decided = await _db.AuthorizationInteractions
            .Where(i => i.Id == interaction.Id && i.Decision == null && i.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set
                .SetProperty(i => i.UserId, user.Id)
                .SetProperty(i => i.Decision, decision)
                .SetProperty(i => i.DecidedAt, now)
                .SetProperty(i => i.TicketHash, ticketHash)
                .SetProperty(i => i.TicketExpiresAt, ticketExpiresAt));

        if (decided != 1)
            return Conflict(new { error = "This interaction has already been decided, or has expired." });

        await _audit.LogAsync(
            decision == AuthorizationInteractionDecision.Accepted ? AuditAction.OAuthConsentGranted : AuditAction.OAuthConsentDenied,
            actorUserId: user.Id, actorEmail: user.Email, targetUserId: user.Id,
            metadata: new { clientId = interaction.ClientId, scopes = interaction.Scopes, resource = interaction.Resource, mode = "external" });

        var redirectTo = QueryHelpers.AddQueryString(
            _issuer.Value + AuthorizationServerDefaults.AuthorizationEndpoint + interaction.RequestQuery,
            AuthorizationServerDefaults.InteractionTicketParameter,
            ticket);

        return Ok(new AuthorizationInteractionDecisionResponse(redirectTo));
    }

    private bool IsExternal => _options.Value.Interaction.Mode == AuthorizationServerInteractionMode.External;

    private async Task<AuthorizationInteraction?> FindPendingAsync(string handle)
    {
        if (string.IsNullOrWhiteSpace(handle) || handle.Length > 64)
            return null;

        var hash = TokenHasher.Hash(handle);
        var now = DateTime.UtcNow;

        return await _db.AuthorizationInteractions.AsNoTracking()
            .FirstOrDefaultAsync(i => i.HandleHash == hash && i.Decision == null && i.ExpiresAt > now);
    }

    private static string[] SplitScopes(string scopes) => scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
}

public record AuthorizationInteractionScope(string Name, string Description);

public record AuthorizationInteractionResponse(
    string ClientId,
    string ClientName,
    string RedirectHost,
    IReadOnlyList<AuthorizationInteractionScope> Scopes,
    string Resource,
    DateTime ExpiresAt);

/// <summary>
/// Optional confirmation of what the user saw. When present it must match the request exactly:
/// the frontend confirms, it does not choose.
/// </summary>
public record AcceptAuthorizationInteractionRequest(IReadOnlyList<string>? Scopes, string? Resource);

/// <summary>Where the frontend sends the browser next.</summary>
public record AuthorizationInteractionDecisionResponse(string RedirectTo);
