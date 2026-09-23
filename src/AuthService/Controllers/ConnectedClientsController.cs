using AuthService.Extensions;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using OpenIddict.Abstractions;

namespace AuthService.Controllers;

/// <summary>
/// Lets a user disconnect one MCP client from their account (AC6). The global operation —
/// logout, password reset, deletion — ends every connection at once; this ends one.
/// </summary>
[ApiController]
[Authorize]
[AuthorizationServerSurface]
[EnableRateLimiting("api")]
[Route("api/v1/auth/connected-clients")]
[Route("api/auth/connected-clients")] // Unversioned alias. Prefer /api/v1.
public class ConnectedClientsController(
    IOpenIddictApplicationManager _applications,
    IOpenIddictAuthorizationManager _authorizations,
    IOpenIddictTokenManager _tokens,
    UserManager<ApplicationUser> _userManager,
    IAuditService _audit
) : AuthControllerBase
{
    /// <summary>
    /// Revokes the signed-in user's authorizations for the client — which also forgets their
    /// consent — and every token issued under them. Access tokens already issued run out on their
    /// own, within minutes. Touches nobody else's authorizations.
    /// </summary>
    [HttpDelete("{clientId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Revoke(string clientId)
    {
        var userId = GetCurrentUserId();
        if (userId is null)
            return Unauthorized();

        var application = await _applications.FindByClientIdAsync(clientId);
        if (application is null)
            return NotFound(new { error = "No client is registered with that id." });

        var applicationId = await _applications.GetIdAsync(application);

        var authorizations = await _authorizations.RevokeAsync(subject: userId, client: applicationId, status: null, type: null);
        var tokens = await _tokens.RevokeAsync(subject: userId, client: applicationId, status: null, type: null);

        var user = await _userManager.FindByIdAsync(userId);
        await _audit.LogAsync(AuditAction.OAuthClientRevoked, actorUserId: userId, actorEmail: user?.Email,
            targetUserId: userId, metadata: new { clientId, revokedAuthorizations = authorizations, revokedTokens = tokens });

        return NoContent();
    }
}
