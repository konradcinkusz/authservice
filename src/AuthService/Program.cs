using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Google;
using AspNet.Security.OAuth.GitHub;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Text;
using System.Threading.RateLimiting;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using AuthService.Extensions;
using static AuthService.Extensions.DatabaseProviderExtensions;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddProblemDetails();
builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase);

// Log model validation errors before returning 400 (helps debug [ApiController] auto-validation)
builder.Services.Configure<Microsoft.AspNetCore.Mvc.ApiBehaviorOptions>(options =>
{
    options.InvalidModelStateResponseFactory = context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        var errors = context.ModelState
            .Where(e => e.Value?.Errors.Count > 0)
            .ToDictionary(
                e => e.Key,
                e => e.Value!.Errors.Select(err => err.ErrorMessage).ToArray()
            );
        logger.LogWarning("Model validation failed for {Path}: {Errors}",
            context.HttpContext.Request.Path,
            System.Text.Json.JsonSerializer.Serialize(errors));
        return new Microsoft.AspNetCore.Mvc.BadRequestObjectResult(
            new Microsoft.AspNetCore.Mvc.ValidationProblemDetails(context.ModelState));
    };
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Auth Service API",
        Version = "v1",
        Description = "A standalone authentication and authorization service: user identity, JWT tokens, " +
                      "OAuth social login, and multi-tenant organizations with role-based membership."
    });

    // Every route is served both as /api/v1/... (canonical) and /api/... (unversioned alias).
    // Only the canonical form is documented, so the generated spec describes one contract.
    c.DocInclusionPredicate((_, apiDescription) =>
        apiDescription.RelativePath?.StartsWith("api/v1/", StringComparison.OrdinalIgnoreCase) == true);

    var securityScheme = new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "Enter JWT Bearer token: Bearer {your token}",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        Reference = new Microsoft.OpenApi.Models.OpenApiReference
        {
            Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
            Id = "Bearer"
        }
    };

    c.AddSecurityDefinition("Bearer", securityScheme);

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        { securityScheme, Array.Empty<string>() }
    });

    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName()?.Name ?? "AuthService"}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

// ─── Required configuration ────────────────────────────────────────────────────
// Validated here, at startup, with messages naming the setting and how to set it.
// Checking for null alone is not enough: a key present-but-empty (as shipped in
// appsettings.json) sails past `??` and fails much later, somewhere unhelpful.

var dbProvider = builder.Configuration.GetDatabaseProvider();
var schemaMode = builder.Configuration.GetSchemaMode();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException(
        "Connection string 'DefaultConnection' is not configured. Set it via the " +
        "ConnectionStrings__DefaultConnection environment variable, appsettings.json, or dotnet user-secrets.");
}

// Key material is resolved — and validated — here rather than at first login, so a bad key is
// a startup failure with a message naming the setting. Constructing it eagerly also means the
// singleton registered below never throws from inside a request.
var signingKeys = new JwtSigningKeys(builder.Configuration);
builder.Services.AddSingleton(signingKeys);

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "AuthService";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "AuthService";

// Public origin of this service, used to build the `jwks_uri` in the discovery document.
// Optional: without it the request's own scheme/host is used, which is correct as long as
// forwarded headers are trusted (they are, via UseForwardedHeaders below).
var jwtPublicBaseUrl = builder.Configuration["Jwt:PublicBaseUrl"];

// Database — supports PostgreSQL (default) or SQL Server via DatabaseProvider / DATABASE_PROVIDER.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    DatabaseProviderExtensions.ConfigureProvider(
        options,
        connectionString,
        dbProvider,
        builder.Configuration.GetMigrationsAssembly());
});

// ─── Options ───────────────────────────────────────────────────────────────────
builder.Services.Configure<ConsentSettings>(builder.Configuration.GetSection(ConsentSettings.SectionName));
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.SectionName));
builder.Services.Configure<NetworkOptions>(builder.Configuration.GetSection(NetworkOptions.SectionName));

var networkOptions = builder.Configuration.GetSection(NetworkOptions.SectionName).Get<NetworkOptions>()
    ?? new NetworkOptions();
var authOptions = builder.Configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>()
    ?? new AuthOptions();

// Email delivery decides whether email verification can be enforced at all: turning it on
// without a provider configured would lock every new user out of the account they just made.
var sendGridApiKey = builder.Configuration["SendGrid:ApiKey"];
var canSendEmail = !string.IsNullOrWhiteSpace(sendGridApiKey);
var requireConfirmedEmail = authOptions.RequireConfirmedEmail ?? canSendEmail;

builder.Services.AddSingleton(new EmailCapabilities(canSendEmail));

// Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    options.User.RequireUniqueEmail = true;

    // Enforced when this deployment can send verification email (Auth:RequireConfirmedEmail overrides).
    options.SignIn.RequireConfirmedEmail = requireConfirmedEmail;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// JWT Authentication
// SECURITY: These values MUST be set via environment variables in production
// (Jwt__PrivateKeyPem or Jwt__SecretKey, Jwt__Issuer, Jwt__Audience)
var authBuilder = builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    // External login uses cookie scheme to carry state between challenge and callback
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        // Two-factor challenge tokens are issued for "<audience>:2fa" and are therefore
        // rejected here — they can complete a 2FA login and nothing else.
        ValidAudience = jwtAudience,
        // The whole set, not just the signing key: a token minted before a key rotation stays
        // valid until it expires (see JwtSigningKeys).
        IssuerSigningKeys = signingKeys.ValidationKeys,
        ClockSkew = TimeSpan.Zero
    };
});

// OAuth providers — only registered when credentials are present in configuration
// so the app still starts cleanly in environments without OAuth keys configured.
var googleClientId = builder.Configuration["OAuth:Google:ClientId"];
var googleClientSecret = builder.Configuration["OAuth:Google:ClientSecret"];
if (!string.IsNullOrWhiteSpace(googleClientId) && !string.IsNullOrWhiteSpace(googleClientSecret))
{
    authBuilder.AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
    {
        options.ClientId = googleClientId;
        options.ClientSecret = googleClientSecret;
        options.Scope.Add("profile");
        options.ClaimActions.MapJsonKey("picture", "picture");
        // Required by the account-linking check — without this claim the callback cannot
        // tell a verified address from one the account merely lists.
        options.ClaimActions.MapJsonKey("email_verified", "email_verified");
        options.SaveTokens = false; // We issue our own JWT tokens
    });
}

var githubClientId = builder.Configuration["OAuth:GitHub:ClientId"];
var githubClientSecret = builder.Configuration["OAuth:GitHub:ClientSecret"];
if (!string.IsNullOrWhiteSpace(githubClientId) && !string.IsNullOrWhiteSpace(githubClientSecret))
{
    authBuilder.AddGitHub(GitHubAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.ClientId = githubClientId;
        options.ClientSecret = githubClientSecret;
        options.Scope.Add("user:email");
        options.ClaimActions.MapJsonKey("avatar_url", "avatar_url");
        // GitHub exposes verification status only via GET /user/emails, which needs the
        // provider access token — hence SaveTokens. The token is held in the external
        // login cookie for the duration of the callback and is never persisted.
        options.SaveTokens = true;
    });
}

builder.Services.AddAuthorization();

// SECURITY: Which forwarded headers to believe, and from whom.
//
// Trusting X-Forwarded-For from any caller lets a client pick its own IP, which makes
// per-IP rate limiting decorative: a fresh header value buys a fresh bucket. Trust is
// therefore declared per deployment rather than assumed.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor
        | ForwardedHeaders.XForwardedProto
        | ForwardedHeaders.XForwardedHost;

    if (networkOptions.TrustAllProxies)
    {
        // Opt-in only. Safe exclusively when the app cannot be reached except through a
        // trusted proxy, because anything that reaches it directly can now forge its IP.
        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();
        options.ForwardLimit = null;
        return;
    }

    options.ForwardLimit = networkOptions.ForwardLimit;

    foreach (var proxy in networkOptions.KnownProxies)
    {
        if (IPAddress.TryParse(proxy, out var address))
            options.KnownProxies.Add(address);
    }

    foreach (var network in networkOptions.KnownNetworks)
    {
        var parts = network.Split('/');
        if (parts.Length == 2 &&
            IPAddress.TryParse(parts[0], out var prefix) &&
            int.TryParse(parts[1], out var prefixLength))
        {
            options.KnownNetworks.Add(new(prefix, prefixLength));
        }
    }
});

builder.Services.AddHttpClient();
builder.Services.AddMemoryCache();
builder.Services.AddHttpContextAccessor();

// Register custom services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IProviderEmailVerifier, ProviderEmailVerifier>();
builder.Services.AddScoped<IOAuthExchangeCodeService, OAuthExchangeCodeService>();

// Register email service - uses SendGrid when SENDGRID_API_KEY / SendGrid:ApiKey is set,
// otherwise falls back to a no-op that logs warnings so the app starts without email configured.
if (canSendEmail)
{
    builder.Services.AddScoped<IEmailService, SendGridEmailService>();
}
else
{
    builder.Services.AddScoped<IEmailService, NoOpEmailService>();
}
builder.Services.AddScoped<InvitationService>();

// Background services
builder.Services.AddSingleton<IMigrationCompletionSignal, MigrationCompletionSignal>();
builder.Services.AddHostedService<MigrationBackgroundService>();
builder.Services.AddHostedService<OrganizationCleanupService>();
builder.Services.AddHostedService<UserCleanupService>();

// Health checks — liveness is static, readiness depends on the schema being ready.
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseReadyHealthCheck>("database", tags: ["ready"]);

// CORS
builder.Services.AddConfiguredCors(builder.Configuration, CorsExtensions.FrontendPolicy);

// SECURITY: Rate Limiting - Protect against brute force and abuse
builder.Services.AddRateLimiter(options =>
{
    // Strict rate limiting for authentication endpoints (login, register, refresh),
    // partitioned per client IP as resolved from the configured trust boundary.
    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.ResolveClientIp(networkOptions.ClientIpHeader),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 5
            }));

    // Standard rate limiting for general API endpoints, partitioned per authenticated
    // user (or IP for unauthenticated requests).
    options.AddPolicy("api", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name
                ?? httpContext.ResolveClientIp(networkOptions.ClientIpHeader),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 200,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 20
            }));

    // Global fallback rate limiter — per authenticated user or per client IP.
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name
                ?? httpContext.ResolveClientIp(networkOptions.ClientIpHeader),
            factory: partition => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 500,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 50
            }));

    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

        var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfterValue)
            ? (double?)retryAfterValue.TotalSeconds
            : null;

        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "Too many requests. Please try again later.",
            retryAfter
        }, cancellationToken: token);
    };
});

var app = builder.Build();

// Startup summary of the security-relevant choices, so an operator can see from the logs
// which posture the service actually came up in rather than inferring it.
app.Logger.LogInformation(
    "AuthService starting. Provider={Provider}, SchemaMode={SchemaMode}, SigningAlgorithm={SigningAlgorithm}, " +
    "RequireConfirmedEmail={RequireConfirmedEmail}, EmailDelivery={EmailDelivery}, " +
    "TrustAllProxies={TrustAllProxies}, ClientIpHeader={ClientIpHeader}",
    dbProvider, schemaMode, signingKeys.Algorithm, requireConfirmedEmail,
    canSendEmail ? "SendGrid" : "disabled (no-op)",
    networkOptions.TrustAllProxies, networkOptions.ClientIpHeader ?? "(none)");

if (!signingKeys.SupportsPublicVerification)
{
    app.Logger.LogWarning(
        "Tokens are signed with HS256. Any service given Jwt:SecretKey to validate tokens can " +
        "also mint them, for any user and any role. Set Jwt__Algorithm=RS256 with " +
        "Jwt__PrivateKeyPem before a second service validates these tokens (ADR 0002).");
}

if (authOptions.AllowTokensInOAuthRedirect)
{
    app.Logger.LogWarning(
        "Auth:AllowTokensInOAuthRedirect is enabled — OAuth tokens will be placed in the redirect " +
        "query string, where they reach browser history, Referer headers and proxy logs. " +
        "Migrate the frontend to the exchange-code flow and turn this off.");
}

if (!authOptions.RequireVerifiedProviderEmail)
{
    app.Logger.LogWarning(
        "Auth:RequireVerifiedProviderEmail is disabled — OAuth logins will link to existing local " +
        "accounts on an unverified provider email. This reopens a known account-takeover path.");
}

// Configure the HTTP request pipeline
// SECURITY: Global exception handler - prevents stack trace leaks to clients
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler();
}

// SECURITY: Swagger publishes the complete API surface, including the admin routes.
// On in Development, off elsewhere unless a deployment opts in with Swagger:Enabled.
var swaggerEnabled = builder.Configuration.GetValue<bool?>("Swagger:Enabled") ?? app.Environment.IsDevelopment();
if (swaggerEnabled)
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth Service API v1");
        c.RoutePrefix = "swagger";
        c.DocumentTitle = "Auth Service API Documentation";
        c.DefaultModelsExpandDepth(2);
        c.DefaultModelExpandDepth(2);
    });
}

app.UseForwardedHeaders();

app.UseHttpsRedirection();

app.UseCors(CorsExtensions.FrontendPolicy);

// SECURITY: Enable rate limiting middleware
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// ─── Public key distribution ───────────────────────────────────────────────────
// The point of asymmetric signing: consumers verify against this and cannot issue. Anonymous
// by design — a public key is public — and cacheable, since the key only changes on rotation
// and the `kid` header is what actually selects between them.
//
// Under HS256 this serves an empty key set rather than 404, so a consumer configured for JWKS
// gets "no keys I can use" instead of "this service does not do JWKS at all". The symmetric
// key is never published here; that would hand out the ability to mint tokens.
app.MapGet("/.well-known/jwks.json", (JwtSigningKeys keys, HttpContext http) =>
{
    http.Response.Headers.CacheControl = "public, max-age=300";
    return Results.Json(keys.BuildJwks());
}).AllowAnonymous();

// Enough OIDC metadata for ASP.NET Core's JwtBearerOptions.Authority to discover the JWKS on
// its own. This is deliberately not a claim to be an OIDC provider — there is no authorization
// endpoint and no token endpoint here (ADR 0003). It exists so a consumer can write
// `options.Authority = "https://auth.example.com"` and nothing else.
app.MapGet("/.well-known/openid-configuration", (HttpContext http) =>
{
    // `issuer` is the value tokens actually carry in `iss` — not this service's URL. They are
    // allowed to differ (the default issuer is the bare string "AuthService"), and reporting the
    // URL here would hand consumers an issuer that never matches a token they receive.
    //
    // `jwks_uri` must be reachable by the consumer, so it is built from the configured public
    // base URL where one is set, and from the request otherwise. Behind Fly's proxy the request
    // host is correct only because UseForwardedHeaders ran first.
    var baseUrl = (jwtPublicBaseUrl ?? $"{http.Request.Scheme}://{http.Request.Host}").TrimEnd('/');

    http.Response.Headers.CacheControl = "public, max-age=300";
    return Results.Json(new
    {
        issuer = jwtIssuer,
        jwks_uri = $"{baseUrl}/.well-known/jwks.json",
        id_token_signing_alg_values_supported = new[] { signingKeys.Algorithm.ToString() },
        response_types_supported = Array.Empty<string>(),
        subject_types_supported = new[] { "public" }
    });
}).AllowAnonymous();

// Liveness: the process is up and serving. Restart-on-failure hangs off this.
app.MapGet("/health", () => Results.Ok(new { status = "Healthy", service = "AuthService" }));

// The same answer under the name the architecture standard's checklist uses, so a
// platform configured from that checklist finds it. Kept as an alias rather than a
// rename: /health is what every existing deployment and the README already point at.
app.MapGet("/alive", () => Results.Ok(new { status = "Healthy", service = "AuthService" }));

// Readiness: the process can actually serve a request. Load balancers and platform
// health checks belong here, not on /health — see docs/DEPLOYMENT.md.
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new
        {
            status = report.Status.ToString(),
            service = "AuthService",
            checks = report.Entries.Select(e => new
            {
                name = e.Key,
                status = e.Value.Status.ToString(),
                description = e.Value.Description
            })
        });
    }
});

app.Run();

public partial class Program { }
