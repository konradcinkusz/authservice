using Microsoft.AspNetCore.Http;

namespace AuthService.Services;

/// <summary>
/// How this deployment sits behind proxies. Bound from the <c>Network</c> configuration section.
///
/// The defaults are the safe ones: nothing is trusted beyond the framework default (loopback),
/// so <c>X-Forwarded-For</c> from an arbitrary caller cannot rewrite the client IP that rate
/// limiting and audit records are keyed on. Each deployment declares its own trusted hops.
/// </summary>
public class NetworkOptions
{
    public const string SectionName = "Network";

    /// <summary>
    /// Header carrying the real client IP, set by a platform that also strips any client-supplied
    /// copy — for example <c>Fly-Client-IP</c> on Fly.io or <c>CF-Connecting-IP</c> behind Cloudflare.
    /// Preferred over <c>X-Forwarded-For</c> because it is single-valued and not client-appendable.
    /// Leave empty when there is no such header.
    /// </summary>
    public string? ClientIpHeader { get; set; }

    /// <summary>Individual proxy IPs whose <c>X-Forwarded-*</c> headers are trusted.</summary>
    public string[] KnownProxies { get; set; } = [];

    /// <summary>Proxy networks in CIDR form (e.g. <c>10.0.0.0/8</c>) whose forwarded headers are trusted.</summary>
    public string[] KnownNetworks { get; set; } = [];

    /// <summary>How many proxy hops to walk back through. Must match the real topology.</summary>
    public int ForwardLimit { get; set; } = 1;

    /// <summary>
    /// Accept <c>X-Forwarded-*</c> from any caller. This is only safe when the app is
    /// genuinely unreachable except through a trusted proxy, because any client that can
    /// reach it directly can then forge its own IP. Off by default.
    /// </summary>
    public bool TrustAllProxies { get; set; }
}

public static class ClientIpExtensions
{
    /// <summary>
    /// Resolves the client IP for rate limiting and audit records: the platform header when one
    /// is configured, otherwise the connection's remote address (which reflects
    /// <c>X-Forwarded-For</c> only for hops the forwarded-headers middleware was told to trust).
    /// </summary>
    public static string ResolveClientIp(this HttpContext context, string? clientIpHeader)
    {
        if (!string.IsNullOrWhiteSpace(clientIpHeader) &&
            context.Request.Headers.TryGetValue(clientIpHeader, out var header))
        {
            var value = header.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                // Take the first entry in case the platform ever emits a list.
                var first = value.Split(',')[0].Trim();
                if (first.Length > 0)
                    return first;
            }
        }

        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}
