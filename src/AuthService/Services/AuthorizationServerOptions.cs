using System.Net;
using System.Text;

namespace AuthService.Services;

/// <summary>
/// The OAuth 2.1 authorization server for MCP connector clients (ADR 0005), bound from the
/// <c>AuthorizationServer</c> configuration section. The section is empty by default, and a
/// deployment with no client configured has no authorization-server endpoint, page or metadata
/// at all (P8).
///
/// Named <c>AuthorizationServer</c> rather than anything under <c>OAuth</c>: that section holds
/// the Google and GitHub settings, where this service is the client, not the server.
/// </summary>
public class AuthorizationServerOptions
{
    public const string SectionName = "AuthorizationServer";

    /// <summary>The scope a client needs to be issued a refresh token. Always advertised and allowed.</summary>
    public const string OfflineAccessScope = "offline_access";

    /// <summary>Pre-registered confidential clients. Configuration is authoritative for them (A8).</summary>
    public List<AuthorizationServerClient> Clients { get; set; } = [];

    /// <summary>
    /// What each scope means, shown on the consent step. A list rather than a map keyed by name:
    /// <c>:</c> is the configuration key delimiter, so a scope named <c>notes:read</c> cannot be a key.
    /// </summary>
    public List<AuthorizationServerScope> Scopes { get; set; } = [];

    /// <summary>
    /// Base64 encoding of the 256-bit key the library encrypts the codes and refresh tokens it
    /// issues with. A platform secret, never a generated or ephemeral one: a key that changes at
    /// restart invalidates every connection (A4).
    /// </summary>
    public string? EncryptionKey { get; set; }

    /// <summary>
    /// Retired encryption keys, still accepted for decryption so a rotation is rolling. Drop one
    /// once a refresh-token lifetime has passed since it was replaced.
    /// </summary>
    public List<string> PreviousEncryptionKeys { get; set; } = [];

    /// <summary>An authorization code's lifetime. Single-use, and redeemed within seconds in practice.</summary>
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 60;

    /// <summary>
    /// An MCP access token's lifetime. Short, because an issued JWT cannot be recalled (D4): its
    /// lifetime is the containment. Claude refreshes on a 401 and ahead of expiry.
    /// </summary>
    public int AccessTokenLifetimeMinutes { get; set; } = 15;

    /// <summary>A refresh token's lifetime, restarted by every refresh (sliding).</summary>
    public int RefreshTokenLifetimeDays { get; set; } = 30;

    public AuthorizationServerInteractionOptions Interaction { get; set; } = new();

    /// <summary>True when at least one client is configured, which is what turns the server on.</summary>
    public bool IsEnabled => Clients.Count > 0;

    /// <summary>The consent-step description of <paramref name="scope"/>, or the scope itself when none is configured.</summary>
    public string DescribeScope(string scope)
    {
        var configured = Scopes.FirstOrDefault(s => string.Equals(s.Name, scope, StringComparison.Ordinal));
        if (!string.IsNullOrWhiteSpace(configured?.Description))
            return configured.Description;

        return scope == OfflineAccessScope ? "Stay connected when you are not using it" : scope;
    }

    public AuthorizationServerClient? FindClient(string? clientId) =>
        Clients.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));

    /// <summary>
    /// Checks everything a deployment can get wrong in configuration, so a mistake is a startup
    /// failure naming the setting rather than a failed connection somewhere in Claude
    /// (the posture ADR 0002 set for key material). Returns every problem at once.
    /// </summary>
    public IReadOnlyList<string> Validate(
        JwtSigningAlgorithm signingAlgorithm, string? publicBaseUrl, string? apiIssuer = null, string? apiAudience = null)
    {
        var errors = new List<string>();
        if (!IsEnabled)
            return errors;

        if (signingAlgorithm != JwtSigningAlgorithm.RS256)
        {
            errors.Add(
                "The authorization server needs asymmetric signing, so resource servers can verify its tokens " +
                "without being able to mint them. Set Jwt:Algorithm=RS256 and Jwt:PrivateKeyPem (ADR 0002).");
        }

        if (!TryNormalizeIssuer(publicBaseUrl, out var issuer))
        {
            errors.Add(
                "Jwt:PublicBaseUrl must be set to this service's public https origin (for example " +
                "https://auth.example.com) when AuthorizationServer:Clients is configured. It is the issuer " +
                "of MCP tokens and is never derived from the request.");
        }

        if (!TryDecodeKey(EncryptionKey, out _))
        {
            errors.Add(
                "AuthorizationServer:EncryptionKey must be the base64 encoding of 32 random bytes, supplied as a " +
                "platform secret. See \"Registering an MCP client\" in docs/DEPLOYMENT.md for how to generate one.");
        }

        for (var i = 0; i < PreviousEncryptionKeys.Count; i++)
        {
            if (!TryDecodeKey(PreviousEncryptionKeys[i], out _))
                errors.Add($"AuthorizationServer:PreviousEncryptionKeys:{i} must be the base64 encoding of 32 bytes.");
        }

        if (AuthorizationCodeLifetimeSeconds is < 1 or > 600)
            errors.Add("AuthorizationServer:AuthorizationCodeLifetimeSeconds must be between 1 and 600.");
        if (AccessTokenLifetimeMinutes is < 1 or > 60)
            errors.Add("AuthorizationServer:AccessTokenLifetimeMinutes must be between 1 and 60.");
        if (RefreshTokenLifetimeDays is < 1 or > 365)
            errors.Add("AuthorizationServer:RefreshTokenLifetimeDays must be between 1 and 365.");

        if (Interaction.Mode == AuthorizationServerInteractionMode.External &&
            !IsHttpsUrl(Interaction.ExternalUrl, allowQuery: false))
        {
            errors.Add(
                "AuthorizationServer:Interaction:ExternalUrl must be the absolute https URL of the consumer's " +
                "page that signs the user in and asks for consent, when Interaction:Mode is External.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < Clients.Count; i++)
        {
            var client = Clients[i];
            var prefix = $"AuthorizationServer:Clients:{i}";

            if (string.IsNullOrWhiteSpace(client.ClientId))
                errors.Add($"{prefix}:ClientId is required.");
            else if (!seen.Add(client.ClientId))
                errors.Add($"{prefix}:ClientId '{client.ClientId}' is configured more than once.");

            if (string.IsNullOrWhiteSpace(client.DisplayName))
                errors.Add($"{prefix}:DisplayName is required; it is what the consent step shows.");

            // A present-but-short secret is refused as firmly as a missing one: the client is
            // confidential (AC5), and its secret is the only thing standing in for the user here.
            if (string.IsNullOrEmpty(client.ClientSecret) || Encoding.UTF8.GetByteCount(client.ClientSecret) < 32)
            {
                errors.Add(
                    $"{prefix}:ClientSecret must be at least 256 bits (32 bytes), supplied as a platform secret " +
                    $"({prefix.Replace(":", "__")}__ClientSecret).");
            }

            if (client.RedirectUris.Count == 0)
                errors.Add($"{prefix}:RedirectUris needs at least one entry.");
            for (var j = 0; j < client.RedirectUris.Count; j++)
            {
                if (!IsAllowedRedirectUri(client.RedirectUris[j]))
                {
                    errors.Add(
                        $"{prefix}:RedirectUris:{j} must be an absolute https URI, or http on a loopback address, " +
                        "with no fragment.");
                }
            }

            if (!client.AllowedScopes.Contains(OfflineAccessScope, StringComparer.Ordinal))
            {
                errors.Add(
                    $"{prefix}:AllowedScopes must include {OfflineAccessScope}: without it the client is never issued " +
                    "a refresh token, and Claude asks for it only when it is allowed.");
            }

            foreach (var scope in client.AllowedScopes)
            {
                if (string.IsNullOrWhiteSpace(scope) || scope.Any(char.IsWhiteSpace) || scope.Contains('"') || scope.Contains('\\'))
                    errors.Add($"{prefix}:AllowedScopes contains '{scope}', which is not a valid scope token.");
                if (scope == "openid")
                    errors.Add($"{prefix}:AllowedScopes contains openid; this server does not implement OpenID Connect.");
            }

            if (client.AllowedResources.Count == 0)
                errors.Add($"{prefix}:AllowedResources needs at least one entry: every token is bound to one resource.");
            for (var j = 0; j < client.AllowedResources.Count; j++)
            {
                if (!IsHttpsUrl(client.AllowedResources[j], allowQuery: true))
                    errors.Add($"{prefix}:AllowedResources:{j} must be an absolute https URI with no fragment.");
            }

            if (client.TokenRequestsPerMinute < 1)
                errors.Add($"{prefix}:TokenRequestsPerMinute must be at least 1.");
            if (client.TokenRequestsPerUserPerMinute < 1)
                errors.Add($"{prefix}:TokenRequestsPerUserPerMinute must be at least 1.");
        }

        for (var i = 0; i < Scopes.Count; i++)
        {
            if (string.IsNullOrWhiteSpace(Scopes[i].Name))
                errors.Add($"AuthorizationServer:Scopes:{i}:Name is required.");
        }

        // MCP tokens are kept out of authservice's own API by their issuer and audience (A1, A9).
        // Were both the ones the API validates, it would take an MCP token for its own (I20).
        // Checked last, once the issuer and every resource are known to be well formed.
        if (errors.Count == 0 &&
            string.Equals(apiIssuer?.Trim().TrimEnd('/'), issuer, StringComparison.Ordinal) &&
            Clients.Any(c => c.AllowedResources.SelectMany(AuthorizationClientSync.ResourceForms).Contains(apiAudience, StringComparer.Ordinal)))
        {
            errors.Add(
                "Jwt:Issuer is Jwt:PublicBaseUrl and Jwt:Audience is one of AuthorizationServer:Clients' AllowedResources, " +
                "so authservice's own API would accept MCP tokens as its own. Change Jwt:Issuer or Jwt:Audience.");
        }

        return errors;
    }

    /// <summary>
    /// The issuer is the configured public origin, with the trailing slash trimmed (A1). The
    /// library's own representation adds one; the discovery document, the authorization
    /// response and the token carry this form instead.
    /// </summary>
    public static bool TryNormalizeIssuer(string? publicBaseUrl, out string issuer)
    {
        issuer = string.Empty;
        if (!IsHttpsUrl(publicBaseUrl, allowQuery: false))
            return false;

        issuer = publicBaseUrl!.Trim().TrimEnd('/');
        return true;
    }

    public static bool TryDecodeKey(string? value, out byte[] key)
    {
        key = [];
        if (string.IsNullOrWhiteSpace(value))
            return false;

        try
        {
            key = Convert.FromBase64String(value.Trim());
        }
        catch (FormatException)
        {
            return false;
        }

        return key.Length == 32;
    }

    private static bool IsHttpsUrl(string? value, bool allowQuery) =>
        Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && string.IsNullOrEmpty(uri.Fragment)
        && (allowQuery || string.IsNullOrEmpty(uri.Query));

    private static bool IsAllowedRedirectUri(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
            return false;

        if (uri.Scheme == Uri.UriSchemeHttps)
            return true;

        // http only on the loopback interface (MCP-SEC "Communication Security").
        return uri.Scheme == Uri.UriSchemeHttp
            && (uri.IsLoopback || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address)));
    }
}

/// <summary>One pre-registered confidential client.</summary>
public class AuthorizationServerClient
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>What the consent step calls the client.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>A platform secret. Stored by the library as a PBKDF2 hash.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Matched exactly; Claude's is taken from Anthropic's connector documentation.</summary>
    public List<string> RedirectUris { get; set; } = [];

    public List<string> AllowedScopes { get; set; } = [];

    /// <summary>The MCP servers this client may ask for a token to, by canonical URI.</summary>
    public List<string> AllowedResources { get; set; } = [];

    /// <summary>
    /// This client's token-endpoint limit, applied after the client has authenticated (N4). Every
    /// Claude user's token and refresh calls come from Anthropic's small egress range, so a per-IP
    /// bucket would lump them together; size this to the client's users instead.
    /// </summary>
    public int TokenRequestsPerMinute { get; set; } = 1200;

    /// <summary>
    /// One user's share of <see cref="TokenRequestsPerMinute"/>, so that a user who holds the
    /// client's secret, as Claude's individual plans require, cannot spend the budget every other
    /// user of the client depends on (I18). A connection refreshes a few times an hour.
    /// </summary>
    public int TokenRequestsPerUserPerMinute { get; set; } = 30;
}

public class AuthorizationServerScope
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}

public class AuthorizationServerInteractionOptions
{
    /// <summary>Who renders sign-in and consent (A11). Read at request time.</summary>
    public AuthorizationServerInteractionMode Mode { get; set; } = AuthorizationServerInteractionMode.Hosted;

    /// <summary>
    /// External mode only: the consumer's page the browser is sent to, with <c>?interaction=</c>
    /// appended. Always taken from here, never from the request.
    /// </summary>
    public string? ExternalUrl { get; set; }
}

public enum AuthorizationServerInteractionMode
{
    /// <summary>authservice renders sign-in, the second factor and consent itself. The default.</summary>
    Hosted,

    /// <summary>A consumer's frontend renders them, through the interaction API.</summary>
    External
}
