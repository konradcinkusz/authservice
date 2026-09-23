using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace AuthService.AuthorizationServer.Tests.Infrastructure;

/// <summary>Tokens as returned by the existing register/login/refresh endpoints.</summary>
public record ApiTokens(string AccessToken, string RefreshToken, int ExpiresIn, string TokenType = "Bearer");

/// <summary>Accounts, JSON Web Token decoding and the other small helpers every test class needs.</summary>
public static class TestAccounts
{
    /// <summary>Satisfies the configured Identity password policy (8+, upper, lower, digit, symbol).</summary>
    public const string Password = "Passw0rd!23";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string NewEmail(string prefix = "user") => $"{prefix}-{Guid.NewGuid():N}@example.test";

    /// <summary>Registers an account through the existing API and returns its tokens.</summary>
    public static async Task<(string Email, ApiTokens Tokens)> RegisterAsync(this HttpClient client, string? email = null)
    {
        email ??= NewEmail();

        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = Password,
            acceptedTermsVersion = AuthorizationServerFactory.TermsVersion,
            acceptedPrivacyVersion = AuthorizationServerFactory.PrivacyVersion
        });
        response.EnsureSuccessStatusCode();

        return (email, (await response.Content.ReadFromJsonAsync<ApiTokens>(Json))!);
    }

    public static async Task<ApiTokens> LoginAsync(this HttpClient client, string email)
    {
        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = Password });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ApiTokens>(Json))!;
    }

    public static HttpRequestMessage WithBearer(this HttpRequestMessage request, string accessToken)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return request;
    }

    /// <summary>Decodes one segment of a compact JWS (0 = header, 1 = payload) without validating it.</summary>
    public static JsonDocument DecodeSegment(string jwt, int index)
    {
        var segments = jwt.Split('.');
        Assert.Equal(3, segments.Length);

        var segment = segments[index].Replace('-', '+').Replace('_', '/');
        segment = segment.PadRight(segment.Length + (4 - segment.Length % 4) % 4, '=');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(segment)));
    }

    public static string[] PropertyNames(this JsonElement element) =>
        element.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).ToArray();

    public static string Sha256Base64Url(string value) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    public static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
