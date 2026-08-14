using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace AuthService.Services;

/// <summary>Outcome of asking an OAuth provider whether it verified an email address.</summary>
/// <param name="IsVerified">True only when the provider positively asserts the address is verified.</param>
/// <param name="Reason">Machine-readable reason when it is not, for logs and audit metadata.</param>
public record ProviderEmailVerification(bool IsVerified, string? Reason = null)
{
    public static ProviderEmailVerification Verified { get; } = new(true);
}

/// <summary>
/// Establishes whether the email address an OAuth provider handed back is one the provider
/// has actually verified.
///
/// This matters because the callback uses the address to find an existing local account. If
/// an unverified address is enough, anyone can add a victim's address to their own provider
/// account and sign straight into the victim's account here.
/// </summary>
public interface IProviderEmailVerifier
{
    Task<ProviderEmailVerification> VerifyAsync(
        ExternalLoginInfo info,
        string email,
        CancellationToken cancellationToken = default);
}

public class ProviderEmailVerifier(
    IHttpClientFactory _httpClientFactory,
    ILogger<ProviderEmailVerifier> _logger
) : IProviderEmailVerifier
{
    private const string GitHubEmailsEndpoint = "https://api.github.com/user/emails";

    public async Task<ProviderEmailVerification> VerifyAsync(
        ExternalLoginInfo info,
        string email,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
            return new ProviderEmailVerification(false, "no_email");

        return info.LoginProvider switch
        {
            "Google" => VerifyGoogle(info),
            "GitHub" => await VerifyGitHubAsync(info, email, cancellationToken),

            // Unknown providers are not trusted by default. Adding a provider means adding
            // its verification rule here, deliberately, rather than inheriting a free pass.
            _ => new ProviderEmailVerification(false, "provider_not_supported")
        };
    }

    /// <summary>
    /// Google states verification in the <c>email_verified</c> claim. It is mapped explicitly
    /// in the Google handler configuration — without that mapping the claim never arrives and
    /// this correctly refuses to link.
    /// </summary>
    private ProviderEmailVerification VerifyGoogle(ExternalLoginInfo info)
    {
        var claim = info.Principal.FindFirstValue("email_verified");

        if (string.IsNullOrWhiteSpace(claim))
        {
            _logger.LogWarning("Google did not return an email_verified claim for provider key {ProviderKey}", info.ProviderKey);
            return new ProviderEmailVerification(false, "email_verified_claim_missing");
        }

        return bool.TryParse(claim, out var verified) && verified
            ? ProviderEmailVerification.Verified
            : new ProviderEmailVerification(false, "email_not_verified");
    }

    /// <summary>
    /// GitHub's profile email is not proof of anything on its own, so this asks the
    /// <c>/user/emails</c> endpoint (requires the <c>user:email</c> scope) and accepts the
    /// address only when GitHub reports it as verified.
    /// </summary>
    private async Task<ProviderEmailVerification> VerifyGitHubAsync(
        ExternalLoginInfo info,
        string email,
        CancellationToken cancellationToken)
    {
        var accessToken = info.AuthenticationTokens?
            .FirstOrDefault(t => t.Name == "access_token")?.Value;

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            _logger.LogWarning(
                "No GitHub access token available to verify {Email}. SaveTokens must be enabled on the GitHub handler.",
                email);
            return new ProviderEmailVerification(false, "no_access_token");
        }

        try
        {
            var client = _httpClientFactory.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, GitHubEmailsEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("AuthService", "1.0"));

            using var response = await client.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GitHub /user/emails returned {Status} while verifying {Email}",
                    response.StatusCode, email);
                return new ProviderEmailVerification(false, "emails_endpoint_failed");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var emails = await JsonSerializer.DeserializeAsync<List<GitHubEmail>>(
                stream,
                new JsonSerializerOptions(JsonSerializerDefaults.Web),
                cancellationToken);

            var match = emails?.FirstOrDefault(e =>
                string.Equals(e.Email, email, StringComparison.OrdinalIgnoreCase));

            if (match == null)
                return new ProviderEmailVerification(false, "email_not_on_account");

            if (!match.Verified)
                return new ProviderEmailVerification(false, "email_not_verified");

            // Verified but non-primary addresses are genuinely owned by the user, so they are
            // accepted; primary is preferred but not required.
            return ProviderEmailVerification.Verified;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify GitHub email {Email}", email);
            return new ProviderEmailVerification(false, "verification_error");
        }
    }

    private sealed record GitHubEmail(string Email, bool Verified, bool Primary);
}
