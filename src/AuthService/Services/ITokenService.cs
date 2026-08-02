using AuthService.Models;
using AuthService.DTOs;

namespace AuthService.Services;

public interface ITokenService
{
    Task<TokenResponse> GenerateTokensAsync(ApplicationUser user);
    Task<TokenResponse?> RefreshTokenAsync(string refreshToken);
    Task RevokeRefreshTokensAsync(string userId);
}
