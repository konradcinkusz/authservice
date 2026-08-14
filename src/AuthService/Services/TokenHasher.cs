using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services;

/// <summary>
/// Hashing for opaque, high-entropy bearer secrets (refresh tokens, OAuth exchange codes).
///
/// A plain unsalted SHA-256 is deliberate and sufficient here: these values are 32–64 bytes
/// of CSPRNG output, so there is no dictionary to attack and nothing for a slow KDF to buy.
/// Password hashing is a different problem and stays with ASP.NET Core Identity.
/// </summary>
public static class TokenHasher
{
    /// <summary>Returns the Base64-encoded SHA-256 hash of <paramref name="token"/>.</summary>
    public static string Hash(string token)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>Generates a URL-safe token with <paramref name="byteLength"/> bytes of entropy.</summary>
    public static string GenerateUrlSafeToken(int byteLength = 32)
    {
        var bytes = RandomNumberGenerator.GetBytes(byteLength);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }
}
