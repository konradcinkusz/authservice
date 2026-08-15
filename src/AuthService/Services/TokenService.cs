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
    JwtSigningKeys _signingKeys,
    UserManager<ApplicationUser> _userManager,
    ApplicationDbContext _context,
    IAuditService _audit,
    ILogger<TokenService> _logger
) : ITokenService
{
    private const int DefaultRefreshTokenDays = 7;
    private const int TwoFactorChallengeMinutes = 5;

    /// <summary>Audience suffix that keeps two-factor challenge tokens out of the bearer pipeline.</summary>
    public const string TwoFactorAudienceSuffix = ":2fa";

    public Task<TokenResponse> GenerateTokensAsync(ApplicationUser user)
        => IssueAsync(user, Guid.NewGuid().ToString(), rotatedFrom: null);

    public async Task<TokenResponse?> RefreshTokenAsync(string refreshToken)
    {
        var tokenHash = TokenHasher.Hash(refreshToken);

        var storedToken = await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);

        if (storedToken == null)
            return null;

        // Replay: a token that was already rotated (or explicitly revoked) is being presented
        // again. Either the client is confused or someone stole a token; both mean the whole
        // rotation family is suspect, so it dies.
        if (storedToken.IsRevoked)
        {
            var revoked = await RevokeFamilyAsync(storedToken.FamilyId, RefreshTokenRevocationReason.ReuseDetected);

            _logger.LogWarning(
                "Refresh token reuse detected for user {UserId}. Revoked {Count} token(s) in family {FamilyId}.",
                storedToken.UserId, revoked, storedToken.FamilyId);

            await _audit.LogAsync(
                AuditAction.RefreshTokenReuseDetected,
                targetUserId: storedToken.UserId,
                succeeded: false,
                metadata: new
                {
                    familyId = storedToken.FamilyId,
                    revokedTokens = revoked,
                    presentedTokenRevokedReason = storedToken.RevokedReason
                });

            return null;
        }

        if (storedToken.ExpiresAt <= DateTime.UtcNow)
            return null;

        var user = storedToken.User;

        // The token being valid says nothing about the user still being allowed to hold a
        // session. Lockout and soft-delete are enforced here, not only on the login path.
        if (user.IsDeleted || await _userManager.IsLockedOutAsync(user))
        {
            await RevokeFamilyAsync(storedToken.FamilyId, RefreshTokenRevocationReason.UserNotEligible);

            _logger.LogWarning(
                "Refresh refused for user {UserId} (deleted={IsDeleted}, lockoutEnd={LockoutEnd}). Family {FamilyId} revoked.",
                user.Id, user.IsDeleted, user.LockoutEnd, storedToken.FamilyId);

            return null;
        }

        storedToken.IsRevoked = true;
        storedToken.RevokedAt = DateTime.UtcNow;
        storedToken.RevokedReason = RefreshTokenRevocationReason.Rotated;

        return await IssueAsync(user, storedToken.FamilyId, storedToken);
    }

    public async Task RevokeRefreshTokensAsync(string userId, string reason = RefreshTokenRevocationReason.Logout)
    {
        var tokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.IsRevoked)
            .ToListAsync();

        if (tokens.Count == 0)
            return;

        var now = DateTime.UtcNow;
        foreach (var token in tokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = now;
            token.RevokedReason = reason;
        }

        await _context.SaveChangesAsync();
    }

    public string GenerateTwoFactorChallengeToken(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("purpose", "two_factor_challenge")
        };

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: TwoFactorAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(TwoFactorChallengeMinutes),
            signingCredentials: _signingKeys.SigningCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string? GetUserIdFromTwoFactorChallengeToken(string challengeToken)
    {
        if (string.IsNullOrWhiteSpace(challengeToken))
            return null;

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration["Jwt:Issuer"] ?? "AuthService",
            ValidAudience = TwoFactorAudience,
            IssuerSigningKeys = _signingKeys.ValidationKeys,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            var principal = new JwtSecurityTokenHandler().ValidateToken(challengeToken, parameters, out _);

            if (principal.FindFirstValue("purpose") != "two_factor_challenge")
                return null;

            return principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
                ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "Rejected an invalid two-factor challenge token");
            return null;
        }
    }

    /// <summary>
    /// Issues a token pair. The raw refresh token is returned to the caller and immediately
    /// forgotten — only its hash reaches the database.
    /// </summary>
    private async Task<TokenResponse> IssueAsync(ApplicationUser user, string familyId, RefreshToken? rotatedFrom)
    {
        var claims = await BuildClaimsAsync(user);
        var accessToken = GenerateAccessToken(claims);
        var refreshToken = GenerateRefreshToken();

        var entity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = TokenHasher.Hash(refreshToken),
            FamilyId = familyId,
            ExpiresAt = DateTime.UtcNow.AddDays(RefreshTokenDays)
        };

        _context.RefreshTokens.Add(entity);

        if (rotatedFrom != null)
            rotatedFrom.ReplacedByTokenId = entity.Id;

        await _context.SaveChangesAsync();

        var expiresIn = AccessTokenMinutes * 60;

        return new TokenResponse(accessToken, refreshToken, expiresIn);
    }

    /// <summary>Revokes every non-revoked token in a rotation family. Returns how many were revoked.</summary>
    private async Task<int> RevokeFamilyAsync(string familyId, string reason)
    {
        var family = await _context.RefreshTokens
            .Where(rt => rt.FamilyId == familyId && !rt.IsRevoked)
            .ToListAsync();

        var now = DateTime.UtcNow;
        foreach (var token in family)
        {
            token.IsRevoked = true;
            token.RevokedAt = now;
            token.RevokedReason = reason;
        }

        await _context.SaveChangesAsync();
        return family.Count;
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
        var expiration = DateTime.UtcNow.AddMinutes(AccessTokenMinutes);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: expiration,
            signingCredentials: _signingKeys.SigningCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(randomNumber);
    }

    private SymmetricSecurityKey SigningKey
    {
        get
        {
            var secretKey = _configuration["Jwt:SecretKey"];
            if (string.IsNullOrWhiteSpace(secretKey))
                throw new InvalidOperationException(
                    "Jwt:SecretKey is not configured. Set it via the Jwt__SecretKey environment variable or dotnet user-secrets.");

            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        }
    }

    private string TwoFactorAudience =>
        (_configuration["Jwt:Audience"] ?? "AuthService") + TwoFactorAudienceSuffix;

    private int AccessTokenMinutes =>
        int.TryParse(_configuration["Jwt:ExpirationMinutes"], out var minutes) && minutes > 0 ? minutes : 60;

    private int RefreshTokenDays =>
        int.TryParse(_configuration["Jwt:RefreshTokenDays"], out var days) && days > 0 ? days : DefaultRefreshTokenDays;
}
