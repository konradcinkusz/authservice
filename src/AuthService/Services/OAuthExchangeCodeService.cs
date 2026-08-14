using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthService.Services;

/// <summary>
/// Issues and redeems the single-use codes that replace tokens-in-the-query-string at the
/// end of the OAuth flow. This is the same shape as the authorization code in OAuth itself,
/// for the same reason: a URL is not a confidential channel.
/// </summary>
public interface IOAuthExchangeCodeService
{
    /// <summary>Creates a code for the user and returns the raw value to put in the redirect.</summary>
    Task<string> IssueAsync(string userId, string provider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Redeems a code exactly once. Returns the user id, or null when the code is unknown,
    /// expired, or already used.
    /// </summary>
    Task<string?> RedeemAsync(string code, CancellationToken cancellationToken = default);
}

public class OAuthExchangeCodeService(
    ApplicationDbContext _context,
    ILogger<OAuthExchangeCodeService> _logger
) : IOAuthExchangeCodeService
{
    public async Task<string> IssueAsync(string userId, string provider, CancellationToken cancellationToken = default)
    {
        var code = TokenHasher.GenerateUrlSafeToken(32);

        _context.OAuthExchangeCodes.Add(new OAuthExchangeCode
        {
            CodeHash = TokenHasher.Hash(code),
            UserId = userId,
            Provider = provider,
            ExpiresAt = DateTime.UtcNow.Add(OAuthExchangeCode.DefaultLifetime)
        });

        // Opportunistic cleanup: codes live for a minute, so anything an hour old is litter.
        var cutoff = DateTime.UtcNow.AddHours(-1);
        await _context.OAuthExchangeCodes
            .Where(c => c.ExpiresAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);

        await _context.SaveChangesAsync(cancellationToken);

        return code;
    }

    public async Task<string?> RedeemAsync(string code, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(code))
            return null;

        var hash = TokenHasher.Hash(code);

        var entry = await _context.OAuthExchangeCodes
            .FirstOrDefaultAsync(c => c.CodeHash == hash, cancellationToken);

        if (entry == null)
            return null;

        if (entry.ConsumedAt != null)
        {
            _logger.LogWarning("OAuth exchange code replayed for user {UserId} (issued {CreatedAt})",
                entry.UserId, entry.CreatedAt);
            return null;
        }

        if (entry.ExpiresAt <= DateTime.UtcNow)
            return null;

        entry.ConsumedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync(cancellationToken);

        return entry.UserId;
    }
}
