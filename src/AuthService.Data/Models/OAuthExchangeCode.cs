namespace AuthService.Models;

/// <summary>
/// A short-lived, single-use code handed to the frontend after a successful OAuth
/// callback. The frontend POSTs it to <c>/api/auth/external/exchange</c> and receives
/// the token pair in the response body, so no credential ever travels in a URL
/// (browser history, Referer headers, proxy and CDN logs).
///
/// Only the hash of the code is stored, for the same reason refresh tokens are hashed.
/// </summary>
public class OAuthExchangeCode
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>Base64-encoded SHA-256 hash of the exchange code.</summary>
    public string CodeHash { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    /// <summary>Provider the code was issued for, recorded for auditing.</summary>
    public string Provider { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }

    /// <summary>Set the first time the code is redeemed. A second redemption is refused.</summary>
    public DateTime? ConsumedAt { get; set; }

    /// <summary>Default lifetime of an exchange code.</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromSeconds(60);

    public ApplicationUser User { get; set; } = null!;
}
