using System.Security.Claims;
using AuthService.Models;
using AuthService.DTOs;

namespace AuthService.Services;

public interface ITokenService
{
    /// <summary>Issues an access token plus a new refresh-token rotation family for the user.</summary>
    Task<TokenResponse> GenerateTokensAsync(ApplicationUser user);

    /// <summary>
    /// Rotates a refresh token. Returns null when the token is unknown, expired, replayed,
    /// or when the user is no longer eligible to hold a session (deleted or locked out).
    /// </summary>
    Task<TokenResponse?> RefreshTokenAsync(string refreshToken);

    /// <summary>
    /// Revokes every live refresh token for the user, recording why — and the user's MCP client
    /// authorizations and tokens with them.
    /// </summary>
    Task RevokeRefreshTokensAsync(string userId, string reason = RefreshTokenRevocationReason.Logout);

    /// <summary>
    /// Whether the session an access token from this service belongs to is still alive: its
    /// refresh-token family still holds a live token. The access token itself keeps working until
    /// it expires, as every JWT does, but a session that was revoked since it was issued must not
    /// be able to start anything that outlives it, such as an MCP connection (AUTH-MCP-01, I16).
    /// </summary>
    Task<bool> IsSessionAliveAsync(ClaimsPrincipal accessToken);

    /// <summary>
    /// Whether any of the user's sessions has been revoked, for any reason but rotation, at or
    /// after <paramref name="since"/>.
    /// </summary>
    Task<bool> SessionsRevokedSinceAsync(string userId, DateTime since);

    /// <summary>
    /// The claims an access token for the user carries: identity, roles and organization
    /// memberships, stamped at issuance so no consumer has to call back (IDENTITY-AND-ACCOUNTS.md §1).
    /// The authorization server builds MCP tokens from the same list, so both carry the same names.
    /// </summary>
    Task<List<Claim>> BuildClaimsAsync(ApplicationUser user);

    /// <summary>
    /// Issues a short-lived token that proves "this user passed the first factor". It is
    /// scoped to a dedicated audience so the normal bearer pipeline will not accept it as
    /// an access token.
    /// </summary>
    string GenerateTwoFactorChallengeToken(ApplicationUser user);

    /// <summary>Validates a two-factor challenge token and returns the user id it was issued for.</summary>
    string? GetUserIdFromTwoFactorChallengeToken(string challengeToken);
}
