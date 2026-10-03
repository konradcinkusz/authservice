using System.Text;
using System.Text.Json;

namespace AuthService.Tests.Infrastructure;

public static class AccessTokenClaims
{
    /// <summary>
    /// The payload of an access token as the service wrote it. Nothing is validated: a test that
    /// calls this is reading what was put in the token, not deciding whether to trust it.
    /// </summary>
    public static JsonDocument Payload(this TestTokens tokens)
    {
        var segment = tokens.AccessToken.Split('.')[1].Replace('-', '+').Replace('_', '/');
        segment = segment.PadRight(segment.Length + (4 - segment.Length % 4) % 4, '=');

        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(segment)));
    }

    /// <summary>The role the token carries for one organization, or null when it carries none.</summary>
    public static string? OrganizationRole(this TestTokens tokens, string organizationId)
    {
        using var payload = tokens.Payload();

        return payload.RootElement.TryGetProperty($"organization:{organizationId}:role", out var role)
            ? role.GetString()
            : null;
    }
}
