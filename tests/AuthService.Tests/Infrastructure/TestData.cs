using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace AuthService.Tests.Infrastructure;

/// <summary>Shared constants and small helpers for the integration tests.</summary>
public static class TestData
{
    public const string TermsVersion = "2026-01-01";
    public const string PrivacyVersion = "2026-01-01";
    public const string CookiesVersion = "2026-01-01";

    /// <summary>Satisfies the configured Identity password policy (8+, upper, lower, digit, symbol).</summary>
    public const string ValidPassword = "Passw0rd!23";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>A fresh address per call, so tests never collide on the unique-email constraint.</summary>
    public static string NewEmail(string prefix = "user") =>
        $"{prefix}-{Guid.NewGuid():N}@example.test";
}

/// <summary>Tokens as returned by register/login/refresh.</summary>
public record TestTokens(string AccessToken, string RefreshToken, int ExpiresIn, string TokenType = "Bearer");

public static class HttpClientExtensions
{
    /// <summary>Registers a new account and returns its tokens.</summary>
    public static async Task<(string Email, TestTokens Tokens)> RegisterAsync(
        this HttpClient client, string? email = null)
    {
        email ??= TestData.NewEmail();

        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = TestData.ValidPassword,
            acceptedTermsVersion = TestData.TermsVersion,
            acceptedPrivacyVersion = TestData.PrivacyVersion
        });

        response.EnsureSuccessStatusCode();

        var tokens = await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json);
        return (email, tokens!);
    }

    public static void Authenticate(this HttpClient client, TestTokens tokens) =>
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

    public static void ClearAuthentication(this HttpClient client) =>
        client.DefaultRequestHeaders.Authorization = null;
}
