namespace AuthService.Models;

/// <summary>
/// An authorization request waiting on a consumer's frontend, in the authorization server's
/// External interaction mode (ADR 0005). The frontend signs the user in and asks for consent
/// with the flows it already has; authservice keeps the request here in the meantime, and
/// completes it itself once the frontend reports the decision.
///
/// Three values a caller could present are involved, and only their hashes are stored, for the
/// same reason refresh tokens are hashed: the handle the frontend receives, the value of the
/// cookie binding the interaction to the browser that started it, and the single-use ticket
/// that carries the decision back to authservice's own origin.
/// </summary>
public class AuthorizationInteraction
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>SHA-256 of the handle given to the frontend in the redirect.</summary>
    public string HandleHash { get; set; } = string.Empty;

    /// <summary>SHA-256 of the browser-binding cookie's value when the interaction started.</summary>
    public string BrowserBindingHash { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// The authorization request's query string, replayed at the authorization endpoint to
    /// resume it. It carries nothing secret: the PKCE value is a challenge, not the verifier.
    /// </summary>
    public string RequestQuery { get; set; } = string.Empty;

    /// <summary>The scopes that were requested and are allowed for the client, space-delimited.</summary>
    public string Scopes { get; set; } = string.Empty;

    /// <summary>The single resource the request named.</summary>
    public string Resource { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }

    /// <summary>The user who decided, bound when the frontend accepts or denies.</summary>
    public string? UserId { get; set; }

    /// <summary><see cref="AuthorizationInteractionDecision"/>, or null while pending.</summary>
    public string? Decision { get; set; }

    public DateTime? DecidedAt { get; set; }

    /// <summary>SHA-256 of the single-use ticket issued with the decision.</summary>
    public string? TicketHash { get; set; }

    public DateTime? TicketExpiresAt { get; set; }

    /// <summary>Set, exactly once, when the ticket is redeemed.</summary>
    public DateTime? CompletedAt { get; set; }

    /// <summary>How long a frontend has to sign the user in and report the decision.</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(10);

    /// <summary>How long the ticket carrying the decision back is valid; the same as an exchange code.</summary>
    public static readonly TimeSpan TicketLifetime = TimeSpan.FromSeconds(60);

    public ApplicationUser? User { get; set; }
}

/// <summary>The decisions a frontend can report. Constants rather than an enum, as with audit actions.</summary>
public static class AuthorizationInteractionDecision
{
    public const string Accepted = "accepted";
    public const string Denied = "denied";
}
