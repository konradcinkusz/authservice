using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Services;

/// <summary>Algorithm used to sign access tokens.</summary>
public enum JwtSigningAlgorithm
{
    /// <summary>
    /// Symmetric HMAC-SHA256. Signing and verifying are the same capability, so every service
    /// given the key can mint tokens for any user. Only correct when AuthService is the sole
    /// validator, or every validator is trusted to issue.
    /// </summary>
    HS256,

    /// <summary>
    /// Asymmetric RSA-SHA256. AuthService holds the private key and is the only thing that can
    /// issue; consumers fetch the public key from <c>/.well-known/jwks.json</c> and can only
    /// verify. Required once a second service validates tokens (ADR 0002).
    /// </summary>
    RS256
}

/// <summary>
/// Resolves the key material tokens are signed with, and the set of keys offered for
/// validation.
///
/// The two are deliberately not the same list. Signing uses exactly one key; validation
/// accepts the signing key <b>and</b> any configured previous public key, which is what makes
/// rotation a rolling change rather than a flag day: publish the new key alongside the old,
/// sign with the new, and retire the old once every outstanding token has expired. The
/// <c>kid</c> header tells consumers which one to reach for.
///
/// Under HS256 the JWKS is empty by construction. A symmetric key is a credential, and the one
/// thing this class must never do is publish it.
/// </summary>
public sealed class JwtSigningKeys : IDisposable
{
    /// <summary>HMAC-SHA256 is only defined for keys of at least 256 bits.</summary>
    public const int MinimumSecretKeyBytes = 32;

    /// <summary>Below this an RSA signature is not worth the ceremony of having one.</summary>
    public const int MinimumRsaKeySizeBits = 2048;

    private readonly RSA? _rsa;
    private readonly List<RSA> _retired = [];
    private readonly List<JsonWebKey> _publicKeys = [];

    public JwtSigningKeys(IConfiguration configuration)
    {
        Algorithm = ResolveAlgorithm(configuration);

        if (Algorithm == JwtSigningAlgorithm.HS256)
        {
            var secret = configuration["Jwt:SecretKey"];

            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new InvalidOperationException(
                    "Jwt:SecretKey is not configured. Set it via the Jwt__SecretKey environment " +
                    "variable, appsettings.json, or dotnet user-secrets — or switch to asymmetric " +
                    "signing with Jwt__Algorithm=RS256 and Jwt__PrivateKeyPem.");
            }

            var bytes = Encoding.UTF8.GetByteCount(secret);
            if (bytes < MinimumSecretKeyBytes)
            {
                throw new InvalidOperationException(
                    $"Jwt:SecretKey must be at least {MinimumSecretKeyBytes} bytes " +
                    $"({MinimumSecretKeyBytes} ASCII characters) for HMAC-SHA256; the configured " +
                    $"value is {bytes} bytes. Generate one with: openssl rand -base64 48");
            }

            SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256);
            ValidationKeys = [SigningKey];
            return;
        }

        var privateKeyPem = ReadPem(configuration, "Jwt:PrivateKeyPem", "Jwt:PrivateKeyPath");

        if (string.IsNullOrWhiteSpace(privateKeyPem))
        {
            throw new InvalidOperationException(
                "Jwt:Algorithm is RS256 but no private key is configured. Set Jwt__PrivateKeyPem " +
                "to a PKCS#8 PEM private key, or Jwt__PrivateKeyPath to a file holding one. " +
                "Generate a keypair with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048");
        }

        _rsa = RSA.Create();
        try
        {
            _rsa.ImportFromPem(privateKeyPem);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidOperationException(
                "Jwt:PrivateKeyPem is not a readable PEM private key. Expected a PKCS#8 block " +
                "beginning '-----BEGIN PRIVATE KEY-----'.", ex);
        }

        if (_rsa.KeySize < MinimumRsaKeySizeBits)
        {
            throw new InvalidOperationException(
                $"Jwt:PrivateKeyPem is a {_rsa.KeySize}-bit RSA key; at least " +
                $"{MinimumRsaKeySizeBits} bits are required.");
        }

        var parameters = _rsa.ExportParameters(includePrivateParameters: false);
        var keyId = ComputeThumbprint(parameters);

        var rsaKey = new RsaSecurityKey(_rsa) { KeyId = keyId };
        SigningKey = rsaKey;
        SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);
        _publicKeys.Add(BuildJsonWebKey(parameters, keyId));

        var validation = new List<SecurityKey> { rsaKey };

        // Previous keys are validation-only: a token minted before the last rotation must keep
        // working until it expires, but nothing signs with them again.
        foreach (var pem in ReadPreviousPublicKeys(configuration))
        {
            var retired = RSA.Create();
            try
            {
                retired.ImportFromPem(pem);
            }
            catch (ArgumentException ex)
            {
                retired.Dispose();
                throw new InvalidOperationException(
                    "Jwt:PreviousPublicKeyPem contains a value that is not a readable PEM public key.", ex);
            }

            _retired.Add(retired);

            var retiredParameters = retired.ExportParameters(includePrivateParameters: false);
            var retiredKeyId = ComputeThumbprint(retiredParameters);

            validation.Add(new RsaSecurityKey(retired) { KeyId = retiredKeyId });
            _publicKeys.Add(BuildJsonWebKey(retiredParameters, retiredKeyId));
        }

        ValidationKeys = validation;
    }

    public JwtSigningAlgorithm Algorithm { get; }

    /// <summary>The single key tokens are signed with.</summary>
    public SecurityKey SigningKey { get; }

    public SigningCredentials SigningCredentials { get; }

    /// <summary>
    /// Every key a token may legitimately be signed with — the current key plus any retired
    /// public keys still inside their token lifetime.
    /// </summary>
    public IReadOnlyList<SecurityKey> ValidationKeys { get; }

    /// <summary>
    /// True when consumers can verify tokens without holding the ability to issue them. This is
    /// the property the architecture standard's "exactly one service holds a signing key"
    /// checklist item is actually about.
    /// </summary>
    public bool SupportsPublicVerification => Algorithm == JwtSigningAlgorithm.RS256;

    /// <summary>
    /// The JWKS document served at <c>/.well-known/jwks.json</c>. Empty under HS256 — there is
    /// no public half of a symmetric key, and serving the secret would hand out issuance.
    /// </summary>
    public object BuildJwks() => new
    {
        keys = _publicKeys.Select(key => new
        {
            kty = key.Kty,
            use = key.Use,
            alg = key.Alg,
            kid = key.Kid,
            n = key.N,
            e = key.E
        }).ToArray()
    };

    private static JwtSigningAlgorithm ResolveAlgorithm(IConfiguration configuration)
    {
        var configured = configuration["Jwt:Algorithm"];

        if (!string.IsNullOrWhiteSpace(configured))
        {
            if (Enum.TryParse<JwtSigningAlgorithm>(configured, ignoreCase: true, out var parsed))
                return parsed;

            throw new InvalidOperationException(
                $"Jwt:Algorithm '{configured}' is not supported. Use HS256 or RS256.");
        }

        // Unset: infer from what was supplied. Configuring a private key and still signing
        // symmetrically would be a silent downgrade, which is the failure worth avoiding here.
        var hasPrivateKey =
            !string.IsNullOrWhiteSpace(configuration["Jwt:PrivateKeyPem"]) ||
            !string.IsNullOrWhiteSpace(configuration["Jwt:PrivateKeyPath"]);

        return hasPrivateKey ? JwtSigningAlgorithm.RS256 : JwtSigningAlgorithm.HS256;
    }

    private static string? ReadPem(IConfiguration configuration, string inlineKey, string pathKey)
    {
        var inline = configuration[inlineKey];
        if (!string.IsNullOrWhiteSpace(inline))
            return NormalizePem(inline);

        var path = configuration[pathKey];
        if (string.IsNullOrWhiteSpace(path))
            return null;

        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"{pathKey} points at '{path}', which does not exist.");
        }

        return File.ReadAllText(path);
    }

    private static IEnumerable<string> ReadPreviousPublicKeys(IConfiguration configuration)
    {
        var single = ReadPem(configuration, "Jwt:PreviousPublicKeyPem", "Jwt:PreviousPublicKeyPath");
        if (!string.IsNullOrWhiteSpace(single))
            yield return single;

        // Jwt:PreviousPublicKeys:0, :1, … for the (rare) case of more than one live rotation.
        foreach (var child in configuration.GetSection("Jwt:PreviousPublicKeys").GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(child.Value))
                yield return NormalizePem(child.Value);
        }
    }

    /// <summary>
    /// Environment variables and Fly secrets routinely arrive with the PEM's newlines escaped as
    /// the two characters <c>\n</c>. Importing that fails with an unhelpful parse error, so it
    /// is repaired here rather than in every deployment's shell quoting.
    /// </summary>
    private static string NormalizePem(string pem) =>
        pem.Contains("\\n", StringComparison.Ordinal)
            ? pem.Replace("\\n", "\n", StringComparison.Ordinal)
            : pem;

    /// <summary>
    /// RFC 7638 JWK thumbprint. Deriving the <c>kid</c> from the key itself rather than
    /// configuring it means a rotated key cannot accidentally reuse its predecessor's id, which
    /// would make the JWKS ambiguous exactly when it matters most.
    /// </summary>
    private static string ComputeThumbprint(RSAParameters parameters)
    {
        var e = Base64UrlEncoder.Encode(parameters.Exponent!);
        var n = Base64UrlEncoder.Encode(parameters.Modulus!);

        // Members in lexicographic order, no whitespace — the thumbprint is defined over the
        // exact bytes, so the serialization is part of the specification.
        var canonical = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(digest);
    }

    private static JsonWebKey BuildJsonWebKey(RSAParameters parameters, string keyId) => new()
    {
        Kty = "RSA",
        Use = "sig",
        Alg = SecurityAlgorithms.RsaSha256,
        Kid = keyId,
        N = Base64UrlEncoder.Encode(parameters.Modulus!),
        E = Base64UrlEncoder.Encode(parameters.Exponent!)
    };

    public void Dispose()
    {
        _rsa?.Dispose();
        foreach (var key in _retired)
            key.Dispose();
    }
}
