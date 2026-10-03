using System.Security.Cryptography;

namespace AuthService.Tests.Infrastructure;

/// <summary>
/// The six-digit code an authenticator app would show (RFC 6238: HMAC-SHA1, 30-second steps).
/// Identity validates these but cannot generate them, so a test that completes a second factor
/// has to compute one from the shared key the way the user's device would.
/// </summary>
public static class Totp
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <param name="sharedKey">The key as enrolment returns it: base32, possibly grouped with spaces.</param>
    public static string Code(string sharedKey, DateTimeOffset? at = null)
    {
        var key = DecodeBase32(sharedKey);
        var step = (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / 30;

        var counter = BitConverter.GetBytes(step);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counter);

        var hash = HMACSHA1.HashData(key, counter);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                     | (hash[offset + 1] << 16)
                     | (hash[offset + 2] << 8)
                     | hash[offset + 3];

        return (binary % 1_000_000).ToString("D6");
    }

    private static byte[] DecodeBase32(string value)
    {
        var bits = 0;
        var buffer = 0;
        var bytes = new List<byte>();

        foreach (var c in value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant))
        {
            buffer = (buffer << 5) | Base32Alphabet.IndexOf(c);
            bits += 5;

            if (bits >= 8)
            {
                bits -= 8;
                bytes.Add((byte)(buffer >> bits));
                buffer &= (1 << bits) - 1;
            }
        }

        return [.. bytes];
    }
}
