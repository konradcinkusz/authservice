using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthService.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Covers the key-material half of ADR 0002. The assertions that matter most are the negative
/// ones: a symmetric secret must never reach the JWKS, and a downgrade to HS256 must never
/// happen silently while a private key is configured.
/// </summary>
public class JwtSigningKeysTests
{
    private static string Secret => Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));

    private static JwtSigningKeys Build(params (string Key, string Value)[] settings)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings.Select(s => new KeyValuePair<string, string?>(s.Key, s.Value)))
            .Build();

        return new JwtSigningKeys(configuration);
    }

    private static string GeneratePrivateKeyPem(int keySizeBits = 2048)
    {
        using var rsa = RSA.Create(keySizeBits);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    private static string PublicKeyPemOf(string privateKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    // ── Algorithm selection ────────────────────────────────────────────────────

    [Fact]
    public void Defaults_to_HS256_when_only_a_secret_is_configured()
    {
        using var keys = Build(("Jwt:SecretKey", Secret));

        Assert.Equal(JwtSigningAlgorithm.HS256, keys.Algorithm);
        Assert.False(keys.SupportsPublicVerification);
    }

    [Fact]
    public void Infers_RS256_when_a_private_key_is_configured()
    {
        // The silent-downgrade case: a deployment that supplies a private key but forgets
        // Jwt:Algorithm must not keep signing symmetrically.
        using var keys = Build(("Jwt:PrivateKeyPem", GeneratePrivateKeyPem()));

        Assert.Equal(JwtSigningAlgorithm.RS256, keys.Algorithm);
        Assert.True(keys.SupportsPublicVerification);
    }

    [Fact]
    public void Rejects_an_unknown_algorithm()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => Build(("Jwt:Algorithm", "ES512"), ("Jwt:SecretKey", Secret)));

        Assert.Contains("HS256 or RS256", exception.Message);
    }

    // ── HS256 ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Rejects_a_secret_shorter_than_the_HMAC_floor()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => Build(("Jwt:SecretKey", "too-short")));

        Assert.Contains("at least 32 bytes", exception.Message);
    }

    [Fact]
    public void Rejects_a_missing_secret()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => Build(("Jwt:Issuer", "AuthService")));

        Assert.Contains("Jwt:SecretKey is not configured", exception.Message);
    }

    [Fact]
    public void Never_publishes_the_symmetric_secret()
    {
        // The single most important assertion in this file. Publishing a symmetric key hands
        // every reader the ability to mint tokens as any user.
        var secret = Secret;
        using var keys = Build(("Jwt:SecretKey", secret));

        var json = JsonSerializer.Serialize(keys.BuildJwks());

        Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
        Assert.DoesNotContain(
            Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(secret)), json, StringComparison.Ordinal);
        Assert.Equal("{\"keys\":[]}", json);
    }

    [Fact]
    public void Signs_with_HMAC_under_HS256()
    {
        using var keys = Build(("Jwt:SecretKey", Secret));

        Assert.Equal(SecurityAlgorithms.HmacSha256, keys.SigningCredentials.Algorithm);
        Assert.Single(keys.ValidationKeys);
    }

    // ── RS256 ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Signs_with_RSA_under_RS256()
    {
        using var keys = Build(("Jwt:Algorithm", "RS256"), ("Jwt:PrivateKeyPem", GeneratePrivateKeyPem()));

        Assert.Equal(SecurityAlgorithms.RsaSha256, keys.SigningCredentials.Algorithm);
        Assert.NotNull(keys.SigningKey.KeyId);
    }

    [Fact]
    public void Publishes_exactly_the_public_half()
    {
        var privateKeyPem = GeneratePrivateKeyPem();
        using var keys = Build(("Jwt:PrivateKeyPem", privateKeyPem));

        var json = JsonSerializer.Serialize(keys.BuildJwks());
        using var document = JsonDocument.Parse(json);
        var published = document.RootElement.GetProperty("keys");

        Assert.Equal(1, published.GetArrayLength());

        var key = published[0];
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.Equal(keys.SigningKey.KeyId, key.GetProperty("kid").GetString());

        // The modulus and exponent are the public half; nothing from the private key
        // (d, p, q, dp, dq, qi) may appear.
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var parameters = rsa.ExportParameters(includePrivateParameters: true);

        Assert.Equal(Base64UrlEncoder.Encode(parameters.Modulus!), key.GetProperty("n").GetString());
        Assert.Equal(Base64UrlEncoder.Encode(parameters.Exponent!), key.GetProperty("e").GetString());
        Assert.DoesNotContain(Base64UrlEncoder.Encode(parameters.D!), json, StringComparison.Ordinal);
        Assert.DoesNotContain(Base64UrlEncoder.Encode(parameters.P!), json, StringComparison.Ordinal);
    }

    [Fact]
    public void Derives_a_stable_key_id_from_the_key_itself()
    {
        var privateKeyPem = GeneratePrivateKeyPem();

        using var first = Build(("Jwt:PrivateKeyPem", privateKeyPem));
        using var second = Build(("Jwt:PrivateKeyPem", privateKeyPem));

        Assert.Equal(first.SigningKey.KeyId, second.SigningKey.KeyId);

        using var other = Build(("Jwt:PrivateKeyPem", GeneratePrivateKeyPem()));
        Assert.NotEqual(first.SigningKey.KeyId, other.SigningKey.KeyId);
    }

    [Fact]
    public void Accepts_a_PEM_whose_newlines_survived_as_backslash_n()
    {
        // How a PEM routinely arrives from `fly secrets set` and from CI environment blocks.
        var escaped = GeneratePrivateKeyPem().Replace("\n", "\\n");

        using var keys = Build(("Jwt:PrivateKeyPem", escaped));

        Assert.Equal(JwtSigningAlgorithm.RS256, keys.Algorithm);
    }

    [Fact]
    public void Rejects_an_undersized_RSA_key()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => Build(("Jwt:PrivateKeyPem", GeneratePrivateKeyPem(1024))));

        Assert.Contains("2048", exception.Message);
    }

    [Fact]
    public void Rejects_a_private_key_that_is_not_a_PEM()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => Build(("Jwt:Algorithm", "RS256"), ("Jwt:PrivateKeyPem", "not a key")));

        Assert.Contains("readable PEM private key", exception.Message);
    }

    [Fact]
    public void Rejects_RS256_with_no_private_key()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => Build(("Jwt:Algorithm", "RS256")));

        Assert.Contains("no private key is configured", exception.Message);
    }

    // ── Rotation ───────────────────────────────────────────────────────────────

    [Fact]
    public void Keeps_a_retired_key_for_validation_but_not_for_signing()
    {
        var current = GeneratePrivateKeyPem();
        var retired = GeneratePrivateKeyPem();

        using var keys = Build(
            ("Jwt:PrivateKeyPem", current),
            ("Jwt:PreviousPublicKeyPem", PublicKeyPemOf(retired)));

        // Both are offered for validation…
        Assert.Equal(2, keys.ValidationKeys.Count);

        // …and both are published, so a consumer can select on `kid`…
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(keys.BuildJwks()));
        Assert.Equal(2, document.RootElement.GetProperty("keys").GetArrayLength());

        // …but only the current key signs.
        Assert.Equal(keys.ValidationKeys[0].KeyId, keys.SigningKey.KeyId);
        Assert.NotEqual(keys.ValidationKeys[1].KeyId, keys.SigningKey.KeyId);
    }
}
