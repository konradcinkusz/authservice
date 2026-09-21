using System.Security.Cryptography;

namespace AuthService.Mcp;

public static class SigningKeyGenerator
{
    // README.md ("API overview") is explicit that a signing key must never be reused across
    // two projects' instances — generating a fresh RS256 pair here makes that the only path.
    public static (string PrivateKeyPem, string PublicKeyPem) GenerateRsaKeyPair()
    {
        using var rsa = RSA.Create(2048);
        return (rsa.ExportRSAPrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }
}
