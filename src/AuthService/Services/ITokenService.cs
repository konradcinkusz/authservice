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

    /// <summary>Revokes every live refresh token for the user, recording why.</summary>
    Task RevokeRefreshTokensAsync(string userId, string reason = RefreshTokenRevocationReason.Logout);

    /// <summary>
    /// Issues a short-lived token that proves "this user passed the first factor". It is
    /// scoped to a dedicated audience so the normal bearer pipeline will not accept it as
    /// an access token.
    /// </summary>
    string GenerateTwoFactorChallengeToken(ApplicationUser user);

    /// <summary>Validates a two-factor challenge token and returns the user id it was issued for.</summary>
    string? GetUserIdFromTwoFactorChallengeToken(string challengeToken);
}
