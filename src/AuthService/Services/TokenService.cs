using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using AuthService.Models;
using AuthService.DTOs;
using AuthService.Data;

namespace AuthService.Services;

public class TokenService(
    IConfiguration _configuration,
    UserManager<ApplicationUser> _userManager,
    ApplicationDbContext _context,
    ILogger<TokenService> _logger
) : ITokenService
{
    public async Task<TokenResponse> GenerateTokensAsync(ApplicationUser user)
    {
        var claims = await BuildClaimsAsync(user);

        var accessToken = GenerateAccessToken(claims);
        var refreshToken = GenerateRefreshToken();

        await StoreRefreshTokenAsync(user.Id, refreshToken);

        var expiresIn = int.Parse(_configuration["Jwt:ExpirationMinutes"] ?? "60") * 60;

        return new TokenResponse(accessToken, refreshToken, expiresIn);
    }

    public async Task<TokenResponse?> RefreshTokenAsync(string refreshToken)
    {
        var storedToken = await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken && !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow);

        if (storedToken == null)
            return null;

        var user = storedToken.User;

        // Revoke old token
        storedToken.IsRevoked = true;
        await _context.SaveChangesAsync();

        // Generate new tokens
        return await GenerateTokensAsync(user);
    }

    public async Task RevokeRefreshTokensAsync(string userId)
    {
        var tokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.IsRevoked)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.IsRevoked = true;
        }

        await _context.SaveChangesAsync();
    }

    private async Task<List<Claim>> BuildClaimsAsync(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? user.Email!)
        };

        // Add roles
        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        // Add organization membership claims so downstream services can authorize
        // per-organization actions without an extra call back to AuthService.
        var memberships = await _context.OrganizationMemberships
            .Where(om => om.UserId == user.Id)
            .ToListAsync();

        foreach (var membership in memberships)
        {
            claims.Add(new Claim("organization", membership.OrganizationId));
            claims.Add(new Claim($"organization:{membership.OrganizationId}:role", membership.Role.ToString()));
        }

        return claims;
    }

    private string GenerateAccessToken(List<Claim> claims)
    {
        var secretKey = _configuration["Jwt:SecretKey"];
        if (string.IsNullOrEmpty(secretKey))
            throw new InvalidOperationException(
                "JWT SecretKey is not configured. Set 'Jwt:SecretKey' via environment variables or dotnet user-secrets.");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expirationMinutes = int.Parse(_configuration["Jwt:ExpirationMinutes"] ?? "60");
        var expiration = DateTime.UtcNow.AddMinutes(expirationMinutes);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: expiration,
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private async Task StoreRefreshTokenAsync(string userId, string token)
    {
        var refreshToken = new RefreshToken
        {
            UserId = userId,
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
    }
}
