namespace AuthService.Services;

/// <summary>
/// Behavioural switches for the authentication surface, bound from the <c>Auth</c>
/// configuration section. Every one of these exists because the safe default and the
/// zero-configuration-demo default are not the same thing, and a deployment should be
/// able to say which it wants rather than inherit whichever the code happened to pick.
/// </summary>
public class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>
    /// Whether an unverified email address may sign in and accept organization invitations.
    /// Null (the default) means "auto": verification is enforced exactly when this deployment
    /// can actually send email, so the docker-compose quick start is not locked out of itself.
    /// Set explicitly to true or false to override.
    /// </summary>
    public bool? RequireConfirmedEmail { get; set; }

    /// <summary>
    /// Revoke every refresh token when the user changes their password. Changing a password
    /// is the universal "kick everyone else out" gesture; leaving it off means a stolen
    /// refresh token survives the response to the theft.
    /// </summary>
    public bool RevokeSessionsOnPasswordChange { get; set; } = true;

    /// <summary>
    /// When sessions are revoked on password change, hand the caller a fresh token pair in the
    /// response so the session that just changed the password keeps working. Turn this off to
    /// force a re-login everywhere including the current device.
    /// </summary>
    public bool ReissueTokensOnPasswordChange { get; set; } = true;

    /// <summary>
    /// Require the OAuth provider to assert that it verified the email address before that
    /// address is used to match — or create — a local account. Turning this off restores the
    /// pre-fix behaviour and reopens the account-takeover path; it exists only as an escape
    /// hatch for deployments that must keep working while they migrate.
    /// </summary>
    public bool RequireVerifiedProviderEmail { get; set; } = true;

    /// <summary>
    /// Legacy OAuth callback behaviour: put the access and refresh tokens directly in the
    /// redirect query string. Off by default — the callback now returns a single-use exchange
    /// code instead. Enable only while a frontend is being migrated, and expect the tokens to
    /// end up in browser history, Referer headers and every proxy log on the path.
    /// </summary>
    public bool AllowTokensInOAuthRedirect { get; set; }
}
