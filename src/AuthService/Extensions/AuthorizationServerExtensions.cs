using System.Security.Cryptography;
using System.Threading.RateLimiting;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace AuthService.Extensions;

/// <summary>Names and paths the authorization server's pieces share.</summary>
public static class AuthorizationServerDefaults
{
    /// <summary>
    /// The authorization server's own sign-in session. Never <c>Identity.Application</c>: the
    /// external-login callback signs into that scheme with the second factor bypassed.
    /// </summary>
    public const string CookieScheme = "AuthService.AuthorizationServer";

    public const string CookieName = "__Secure-authservice-as";
    public const string TwoFactorCookieName = "__Secure-authservice-as-2fa";
    public const string ExternalResumeCookieName = "__Secure-authservice-as-resume";
    public const string BrowserBindingCookieName = "__Secure-authservice-as-binding";
    public const string AntiforgeryCookieName = "__Secure-authservice-as-af";

    /// <summary>Every cookie above is scoped here, except the external-resume one, which the callback page reads.</summary>
    public const string CookiePath = "/connect";

    public const string AuthorizationEndpoint = "/connect/authorize";
    public const string TokenEndpoint = "/connect/token";
    public const string MetadataEndpoint = "/.well-known/oauth-authorization-server";
    public const string JwksEndpoint = "/.well-known/jwks.json";

    public const string SignInPage = "/connect/signin";
    public const string TwoFactorPage = "/connect/2fa";
    public const string ConsentPage = "/connect/consent";

    /// <summary>The path <c>ExternalAuthController</c> already accepts as a return URL.</summary>
    public const string ExternalReturnPage = "/oauth/callback";

    /// <summary>External mode: the parameter carrying the single-use ticket back to the authorization endpoint.</summary>
    public const string InteractionTicketParameter = "interaction_ticket";

    /// <summary>The consent decision a Hosted consent page posts back to the authorization endpoint.</summary>
    public const string ConsentParameter = "consent";

    public const string CspNonceItem = "AuthService.AuthorizationServer.CspNonce";

    /// <summary>How long a sign-in on the authorization server's pages lasts. Long enough to connect a client.</summary>
    public static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(20);
}

/// <summary>What the startup banner prints about the authorization server.</summary>
public sealed record AuthorizationServerPosture(bool Enabled, int ClientCount, AuthorizationServerInteractionMode Mode, string? Issuer)
{
    public override string ToString() => Enabled
        ? $"enabled ({ClientCount} client(s), {Mode} interaction, issuer {Issuer})"
        : "disabled (no client configured)";
}

/// <summary>The issuer MCP tokens carry: <c>Jwt:PublicBaseUrl</c>, trailing slash trimmed (A1).</summary>
public sealed record AuthorizationServerIssuer(string Value);

/// <summary>Marks a controller that exists only while the authorization server is enabled (A5).</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class AuthorizationServerSurfaceAttribute : Attribute;

/// <summary>
/// The OAuth 2.1 authorization server for MCP connector clients (ADR 0005): OpenIddict, with
/// the overrides its defaults need here (analysis §4.5), the authorization server's cookie
/// session and pages, and the parts of the existing pipeline it has to fit into. All of it
/// lives here so that Program.cs gains two calls rather than another screen of wiring (P9).
/// </summary>
public static class AuthorizationServerExtensions
{
    /// <summary>
    /// Registers the authorization server. The library's stores are registered whether or not a
    /// client is configured, because revocation and pruning use them; the endpoints, pages and
    /// metadata exist only when one is (P8).
    /// </summary>
    public static AuthorizationServerPosture AddAuthorizationServer(this WebApplicationBuilder builder, JwtSigningKeys signingKeys)
    {
        var services = builder.Services;
        var section = builder.Configuration.GetSection(AuthorizationServerOptions.SectionName);
        var options = section.Get<AuthorizationServerOptions>() ?? new AuthorizationServerOptions();
        services.Configure<AuthorizationServerOptions>(section);

        var publicBaseUrl = builder.Configuration["Jwt:PublicBaseUrl"];
        var errors = options.Validate(signingKeys.Algorithm, publicBaseUrl);
        if (errors.Count > 0)
        {
            throw new InvalidOperationException(
                "The authorization server is misconfigured:" + Environment.NewLine +
                string.Join(Environment.NewLine, errors.Select(e => " - " + e)));
        }

        services.AddOpenIddict()
            .AddCore(core => core.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>());

        services.AddHostedService<AuthorizationClientSync>();

        // At Trace the library writes every token it issues into the log, and its request
        // logging redacts neither codes' verifiers nor everything else a caller sends. Applied
        // after configuration, per logging provider, so no setting can lower it (N5).
        services.PostConfigure<LoggerFilterOptions>(CapLibraryLogging);

        services.Configure<MvcOptions>(mvc => mvc.Conventions.Add(new AuthorizationServerSurfaceConvention(options.IsEnabled)));

        if (!options.IsEnabled)
            return new AuthorizationServerPosture(false, 0, options.Interaction.Mode, null);

        AuthorizationServerOptions.TryNormalizeIssuer(publicBaseUrl, out var issuer);
        services.AddSingleton(new AuthorizationServerIssuer(issuer));
        services.AddSingleton<AuthorizationServerTokenLimiter>();

        services.AddOpenIddict().AddServer(server =>
        {
            // A1: the issuer comes from configuration, never from the request. The library adds a
            // trailing slash to it; the handlers below write the configured form where it is public.
            server.SetIssuer(new Uri(issuer));

            server.SetAuthorizationEndpointUris(AuthorizationServerDefaults.AuthorizationEndpoint.TrimStart('/'))
                  .SetTokenEndpointUris(AuthorizationServerDefaults.TokenEndpoint.TrimStart('/'));

            // A2: the library's discovery endpoints would take over the existing OIDC document
            // and publish a second JWKS. Both are off; authservice serves the RFC 8414 document
            // itself, from these options, and points jwks_uri at the existing key set.
            server.SetConfigurationEndpointUris(Array.Empty<Uri>());
            server.SetJsonWebKeySetEndpointUris(Array.Empty<Uri>());

            server.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow();

            // AC2: PKCE required, S256 only. By default the library accepts plain and makes PKCE optional.
            server.RequireProofKeyForCodeExchange();
            server.Configure(o =>
            {
                o.CodeChallengeMethods.Clear();
                o.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);

                // OpenID Connect is out of scope: no identity tokens, so no openid scope.
                o.Scopes.Remove(Scopes.OpenId);

                // N9: client_secret_basic (added by the ASP.NET Core host) and client_secret_post.
                o.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.PrivateKeyJwt);
            });

            server.RegisterScopes(options.Clients.SelectMany(c => c.AllowedScopes).Distinct(StringComparer.Ordinal).ToArray());

            // N10: the library's resource registry compares against Uri.AbsoluteUri, which always
            // ends an origin in "/", so it can never match an origin-root resource as Claude sends
            // it. Each client's resource permissions carry both forms instead (AuthorizationClientSync),
            // and the authorization endpoint requires exactly one resource.
            server.DisableResourceValidation();

            // A3, F8: the existing key signs; retired public keys follow it and only validate.
            // The library signs with the first credential and sorts symmetric keys first, so no
            // symmetric key may ever be registered here — MapAuthorizationServer asserts both.
            server.AddSigningCredentials(signingKeys.SigningCredentials);
            foreach (var retired in signingKeys.ValidationKeys.Skip(1))
                server.AddSigningCredentials(new SigningCredentials(retired, SecurityAlgorithms.RsaSha256));

            // A4: a durable key from a platform secret, never an ephemeral or development one.
            // The first encrypts; the rest only decrypt, so a rotation is rolling.
            foreach (var value in new[] { options.EncryptionKey! }.Concat(options.PreviousEncryptionKeys))
            {
                AuthorizationServerOptions.TryDecodeKey(value, out var key);
                server.AddEncryptionKey(new SymmetricSecurityKey(key));
            }

            // AC4: access tokens are signed JWTs that resource servers read, not JWEs.
            server.DisableAccessTokenEncryption();

            server.SetAuthorizationCodeLifetime(TimeSpan.FromSeconds(options.AuthorizationCodeLifetimeSeconds));
            server.SetAccessTokenLifetime(TimeSpan.FromMinutes(options.AccessTokenLifetimeMinutes));
            server.SetRefreshTokenLifetime(TimeSpan.FromDays(options.RefreshTokenLifetimeDays));

            // N3: single-use means single-use. The library allows 30 seconds of reuse by default.
            server.SetRefreshTokenReuseLeeway(TimeSpan.Zero);

            server.UseAspNetCore()
                  .EnableAuthorizationEndpointPassthrough()
                  .EnableTokenEndpointPassthrough();

            server.AddEventHandler(AttachIssuerToAuthorizationResponse.Descriptor);
            server.AddEventHandler(ShapeAccessToken.Descriptor);
            server.AddEventHandler(AuditRefreshTokenReuse.Descriptor);
        });

        services.AddAuthentication().AddCookie(AuthorizationServerDefaults.CookieScheme, cookie =>
        {
            cookie.Cookie.Name = AuthorizationServerDefaults.CookieName;
            cookie.Cookie.Path = AuthorizationServerDefaults.CookiePath;
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            cookie.Cookie.SameSite = SameSiteMode.Lax;
            cookie.ExpireTimeSpan = AuthorizationServerDefaults.SessionLifetime;
            cookie.SlidingExpiration = false;
            cookie.LoginPath = AuthorizationServerDefaults.SignInPage;
            cookie.ReturnUrlParameter = "returnUrl";
        });

        services.AddRazorPages(pages =>
        {
            pages.Conventions.AddFolderApplicationModelConvention("/Connect", model =>
            {
                model.Filters.Add(new AuthorizationServerPageHeaders());

                // Browsers, one per person: the per-IP policy fits (N4).
                model.EndpointMetadata.Add(new EnableRateLimitingAttribute("auth"));
            });
        });

        services.AddAntiforgery(antiforgery =>
        {
            antiforgery.Cookie.Name = AuthorizationServerDefaults.AntiforgeryCookieName;
            antiforgery.Cookie.Path = AuthorizationServerDefaults.CookiePath;
            antiforgery.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            antiforgery.Cookie.SameSite = SameSiteMode.Strict;
        });

        // N4, F10: every Claude user's token calls come from Anthropic's small egress range, so
        // the global per-IP bucket would lump them together. The token endpoint is limited per
        // authenticated client instead, in the endpoint itself (AuthorizationServerTokenLimiter).
        services.PostConfigure<RateLimiterOptions>(limiter =>
        {
            if (limiter.GlobalLimiter is { } global)
                limiter.GlobalLimiter = new TokenEndpointExemptLimiter(global);
        });

        return new AuthorizationServerPosture(true, options.Clients.Count, options.Interaction.Mode, issuer);
    }

    /// <summary>Maps the RFC 8414 metadata and the pages, when the authorization server is enabled.</summary>
    public static WebApplication MapAuthorizationServer(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;
        if (!options.IsEnabled)
            return app;

        AssertSigningCredentials(app.Services);

        app.MapGet(AuthorizationServerDefaults.MetadataEndpoint, (AuthorizationServerIssuer issuer, HttpContext http) =>
        {
            http.Response.Headers.CacheControl = "public, max-age=300";
            return Results.Json(BuildMetadata(options, issuer.Value));
        }).AllowAnonymous();

        app.MapRazorPages();

        return app;
    }

    /// <summary>
    /// RFC 8414 authorization server metadata (AC1), generated from the same options the
    /// library is configured with. It advertises nothing this server does not do: no
    /// registration or introspection endpoint, no client ID metadata documents, and no "none"
    /// authentication method, which would invite Claude to try CIMD (N9).
    /// </summary>
    public static object BuildMetadata(AuthorizationServerOptions options, string issuer) => new Dictionary<string, object>
    {
        ["issuer"] = issuer,
        ["authorization_endpoint"] = issuer + AuthorizationServerDefaults.AuthorizationEndpoint,
        ["token_endpoint"] = issuer + AuthorizationServerDefaults.TokenEndpoint,
        ["jwks_uri"] = issuer + AuthorizationServerDefaults.JwksEndpoint,
        ["scopes_supported"] = options.Clients.SelectMany(c => c.AllowedScopes)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
        ["response_types_supported"] = new[] { ResponseTypes.Code },
        ["grant_types_supported"] = new[] { GrantTypes.AuthorizationCode, GrantTypes.RefreshToken },
        ["code_challenge_methods_supported"] = new[] { CodeChallengeMethods.Sha256 },
        ["token_endpoint_auth_methods_supported"] = new[]
        {
            ClientAuthenticationMethods.ClientSecretBasic,
            ClientAuthenticationMethods.ClientSecretPost
        },
        ["authorization_response_iss_parameter_supported"] = true
    };

    /// <summary>
    /// A3 and F8, checked against what the library will actually do rather than what was
    /// registered: it signs with its first signing credential after sorting, so that must be
    /// the current key, and no symmetric key may be in the list at all.
    /// </summary>
    private static void AssertSigningCredentials(IServiceProvider services)
    {
        var server = services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        var keys = services.GetRequiredService<JwtSigningKeys>();

        if (server.SigningCredentials.Count == 0 ||
            !ReferenceEquals(server.SigningCredentials[0].Key, keys.SigningKey) ||
            server.SigningCredentials.Exists(c => c.Key is SymmetricSecurityKey))
        {
            throw new InvalidOperationException(
                "The authorization server would not sign with Jwt:PrivateKeyPem. Its first signing credential " +
                "must be the configured RS256 key, and no symmetric key may be registered.");
        }
    }

    private static void CapLibraryLogging(LoggerFilterOptions options)
    {
        const string category = "OpenIddict";

        for (var i = 0; i < options.Rules.Count; i++)
        {
            var rule = options.Rules[i];
            if (rule.CategoryName?.StartsWith(category, StringComparison.OrdinalIgnoreCase) == true &&
                (rule.LogLevel is null || rule.LogLevel < LogLevel.Warning))
            {
                options.Rules[i] = new LoggerFilterRule(rule.ProviderName, rule.CategoryName, LogLevel.Warning, rule.Filter);
            }
        }

        // A provider-specific rule beats every provider-agnostic one, so the cap is repeated per provider.
        foreach (var provider in options.Rules.Select(r => r.ProviderName).Append(null).Distinct().ToList())
            options.Rules.Add(new LoggerFilterRule(provider, category, LogLevel.Warning, null));
    }
}

/// <summary>Removes the authorization server's controllers when no client is configured (A5).</summary>
internal sealed class AuthorizationServerSurfaceConvention(bool enabled) : IApplicationModelConvention
{
    public void Apply(ApplicationModel application)
    {
        if (enabled)
            return;

        foreach (var controller in application.Controllers
                     .Where(c => c.Attributes.OfType<AuthorizationServerSurfaceAttribute>().Any())
                     .ToList())
        {
            application.Controllers.Remove(controller);
        }
    }
}

/// <summary>
/// SECURITY-REVIEW.md §4's header set on every authorization-server page, with
/// <c>frame-ancestors 'none'</c> so the consent step cannot be clickjacked. There is no script at
/// all; the one style block carries a per-request nonce. <c>form-action</c> is deliberately
/// absent: browsers apply it to the redirects that follow a form post, and the consent post
/// ends in a redirect to the client.
/// </summary>
internal sealed class AuthorizationServerPageHeaders : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var http = context.HttpContext;
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        http.Items[AuthorizationServerDefaults.CspNonceItem] = nonce;

        var headers = http.Response.Headers;
        headers.ContentSecurityPolicy =
            $"default-src 'none'; style-src 'nonce-{nonce}'; frame-ancestors 'none'; base-uri 'none'";
        headers.XFrameOptions = "DENY";
        headers.XContentTypeOptions = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
        // What antiforgery sets itself; anything else makes it log a warning on every page.
        headers.CacheControl = "no-cache, no-store";
        headers.Pragma = "no-cache";

        return next();
    }
}

/// <summary>
/// The token endpoint's limit, partitioned by the client the library has just authenticated
/// (N4) — which is why it is applied in the endpoint rather than by the rate-limiting
/// middleware, which runs before authentication. Rejections are not queued.
/// </summary>
public sealed class AuthorizationServerTokenLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter;

    public AuthorizationServerTokenLimiter(IOptions<AuthorizationServerOptions> options)
    {
        var limits = options.Value.Clients.ToDictionary(c => c.ClientId, c => c.TokenRequestsPerMinute, StringComparer.Ordinal);

        _limiter = PartitionedRateLimiter.Create<string, string>(clientId =>
            RateLimitPartition.GetFixedWindowLimiter(clientId, id => new FixedWindowRateLimiterOptions
            {
                PermitLimit = limits.GetValueOrDefault(id, 1),
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
    }

    public RateLimitLease Acquire(string clientId) => _limiter.AttemptAcquire(clientId);

    public void Dispose() => _limiter.Dispose();
}

/// <summary>The global limiter, with the token endpoint taken out of it (N4).</summary>
internal sealed class TokenEndpointExemptLimiter(PartitionedRateLimiter<HttpContext> inner) : PartitionedRateLimiter<HttpContext>
{
    private readonly PartitionedRateLimiter<HttpContext> _exempt =
        PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("authorization-server-token"));

    private static bool IsExempt(HttpContext context) =>
        context.Request.Path.Equals(AuthorizationServerDefaults.TokenEndpoint, StringComparison.OrdinalIgnoreCase);

    public override RateLimiterStatistics? GetStatistics(HttpContext resource) =>
        IsExempt(resource) ? _exempt.GetStatistics(resource) : inner.GetStatistics(resource);

    protected override RateLimitLease AttemptAcquireCore(HttpContext resource, int permitCount) =>
        IsExempt(resource) ? _exempt.AttemptAcquire(resource, permitCount) : inner.AttemptAcquire(resource, permitCount);

    protected override ValueTask<RateLimitLease> AcquireAsyncCore(HttpContext resource, int permitCount, CancellationToken cancellationToken) =>
        IsExempt(resource)
            ? _exempt.AcquireAsync(resource, permitCount, cancellationToken)
            : inner.AcquireAsync(resource, permitCount, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
            _exempt.Dispose();
        }
    }

    protected override async ValueTask DisposeAsyncCore()
    {
        await inner.DisposeAsync();
        await _exempt.DisposeAsync();
    }
}

/// <summary>Writes A1's issuer into the authorization response's <c>iss</c> (RFC 9207), in place of the library's slashed form.</summary>
internal sealed class AttachIssuerToAuthorizationResponse(AuthorizationServerIssuer issuer)
    : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<AttachIssuerToAuthorizationResponse>()
            .SetOrder(OpenIddictServerHandlers.Authentication.AttachIssuer.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        if (!string.IsNullOrEmpty(context.Response.Iss))
            context.Response.Iss = issuer.Value;

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Makes an access token exactly the contract resource servers validate against (A9): A1's
/// issuer in <c>iss</c>, and none of the library's private <c>oi_*</c> claims (the internal ids of
/// the authorization, the presenter and the token entry), which it otherwise leaves in the JWT.
/// The library accepts both issuer forms on the codes and refresh tokens it reads back itself.
/// </summary>
internal sealed class ShapeAccessToken(AuthorizationServerIssuer issuer) : IOpenIddictServerHandler<GenerateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
            .UseSingletonHandler<ShapeAccessToken>()
            .SetOrder(OpenIddictServerHandlers.Protection.AttachTokenMetadata.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(GenerateTokenContext context)
    {
        if (context.TokenType != TokenTypeIdentifiers.AccessToken)
            return ValueTask.CompletedTask;

        context.SecurityTokenDescriptor.Issuer = issuer.Value;

        if (context.SecurityTokenDescriptor.Subject is { } subject)
        {
            foreach (var claim in subject.Claims.Where(c => c.Type.StartsWith(Claims.Prefixes.Private, StringComparison.Ordinal)).ToList())
                subject.RemoveClaim(claim);
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Records a replayed refresh token (N5), just before the library rejects it and revokes the
/// rest of its chain. With a reuse leeway of zero (N3), any redeemed refresh token presented
/// again is a replay: the audit row is what shows whether that is theft or Claude refreshing
/// twice concurrently.
/// </summary>
internal sealed class AuditRefreshTokenReuse(IOpenIddictTokenManager tokens, IAuditService audit)
    : IOpenIddictServerHandler<ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .AddFilter<OpenIddictServerHandlerFilters.RequireDegradedModeDisabled>()
            .AddFilter<OpenIddictServerHandlerFilters.RequireTokenStorageEnabled>()
            .AddFilter<OpenIddictServerHandlerFilters.RequireTokenIdResolved>()
            .UseScopedHandler<AuditRefreshTokenReuse>()
            .SetOrder(OpenIddictServerHandlers.Protection.ValidateTokenEntry.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenContext context)
    {
        if (context.Principal is null || !context.Principal.HasTokenType(TokenTypeIdentifiers.RefreshToken))
            return;

        var token = await tokens.FindByIdAsync(context.TokenId!);
        if (token is null || !await tokens.HasStatusAsync(token, Statuses.Redeemed))
            return;

        await audit.LogAsync(
            AuditAction.OAuthRefreshTokenReuseDetected,
            targetUserId: context.Principal.GetClaim(Claims.Subject),
            succeeded: false,
            metadata: new
            {
                clientId = context.Principal.GetPresenters().FirstOrDefault(),
                authorizationId = context.AuthorizationId
            });
    }
}
