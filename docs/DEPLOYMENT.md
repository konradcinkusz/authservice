# Deploying your own instance

This repository publishes a container image. It does not deploy itself anywhere and has no
canonical hosted instance — each consuming project runs its own, with its own compute, its own
database and its own signing key (ADR 0001).

That means the `fly.toml`, the secrets and the database live in **the consuming project's**
repository, next to the apps that depend on them. What follows is the reference those
deployments are written against.

## The image

```
ghcr.io/konradcinkusz/authservice:v0.3.4
```

Published by [`.github/workflows/publish-image.yml`](../.github/workflows/publish-image.yml) on
every `v*` tag. Pin a version rather than tracking `latest`: this is `0.x`, and the HTTP
contract may still move. [Releases](https://github.com/konradcinkusz/authservice/releases) lists
every version and what changed in it.

## What the container needs

| Setting | Required | Notes |
| --- | --- | --- |
| `ConnectionStrings__DefaultConnection` | yes | Startup fails naming this setting if it is missing |
| `DATABASE_PROVIDER` | no | `PostgreSQL` (default) or `SqlServer` |
| `Database__SchemaMode` | no | `EnsureCreated` (default), `Migrate`, or `None`. Use `Migrate` for a database you intend to keep, on an image that ships the committed migration sets (any release after v0.3.1); an existing `EnsureCreated` database needs the one-time adoption script first — see [schema/README.md](schema/README.md) |
| `Database__MigrationsAssembly` | with `Migrate` | `AuthService.Migrations.PostgreSQL` or `AuthService.Migrations.SqlServer`, matching `DATABASE_PROVIDER` |
| `Jwt__PrivateKeyPem` | for RS256 | PKCS#8 RSA private key, 2048-bit minimum |
| `Jwt__SecretKey` | for HS256 | 32+ bytes. Only for deployments where this service is the sole validator |
| `Jwt__Issuer` / `Jwt__Audience` | no | Default `AuthService`. Set them per product so a token from one cannot authenticate against another |
| `Jwt__PublicBaseUrl` | with MCP clients | This service's public https origin. The issuer of MCP tokens; see [Registering an MCP client](#registering-an-mcp-client). Without it, `jwks_uri` comes from the request's own origin — from v0.3.4; older images need it set, see [Pointing a service at it](#pointing-a-service-at-it) |
| `AuthorizationServer__Clients__0__…` | no | An MCP connector client. With none, the authorization server does not exist |
| `AuthorizationServer__EncryptionKey` | with MCP clients | 32 random bytes, base64. A platform secret |
| `ASPNETCORE_URLS` | no | Defaults to `http://+:8080` in the image |

Everything else — OAuth credentials, SendGrid, CORS origins, consent versions — is optional and
degrades to a working no-op when absent.

## Health endpoints

| Path | Meaning | Point what at it |
| --- | --- | --- |
| `GET /health` | Liveness. Static; true as soon as the process serves | Restart policies |
| `GET /health/ready` | Readiness. 503 until the schema is initialised and the database answers | **Platform health checks and load balancers** |

Schema initialisation runs in a `BackgroundService` after Kestrel is listening, so the
container answers probes while the schema catches up. Pointing a deploy health check at
`/health/ready` is what makes a slow first boot a slow deploy rather than a failed one.

## A reference `fly.toml`

```toml
app = "yourproduct-authservice"
primary_region = "fra"

[build]
  image = "ghcr.io/konradcinkusz/authservice:v0.3.4"

[env]
  ASPNETCORE_ENVIRONMENT = "Production"
  ASPNETCORE_URLS = "http://+:8080"
  DATABASE_PROVIDER = "PostgreSQL"
  Jwt__Issuer = "YourProduct"
  Jwt__Audience = "YourProduct"
  Jwt__PublicBaseUrl = "https://yourproduct-authservice.fly.dev"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true

  # NOT zero. Every service validating these tokens fetches the JWKS from this app — on its
  # first request and again whenever its cache expires — so this app sits on the synchronous
  # request path of all of them. A scaled-to-zero identity service turns a cache expiry
  # somewhere else into a failed request.
  min_machines_running = 1

  [[http_service.checks]]
    path = "/health/ready"
    interval = "30s"
    timeout = "5s"
    grace_period = "60s"

[[vm]]
  size = "shared-cpu-1x"
  memory = "512mb"
```

Secrets are set out of band, never in `[env]` — everything in `[env]` is visible in
`fly config show`:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-signing.pem

fly secrets set --app yourproduct-authservice \
  "ConnectionStrings__DefaultConnection=Host=yourproduct-postgres.internal;Port=5432;Database=authservice;Username=authservice;Password=..." \
  "Jwt__PrivateKeyPem=$(cat jwt-signing.pem)"
```

With an MCP client configured, two more secrets (generated as
[below](#1-generate-the-two-secrets)):

```bash
fly secrets set --app yourproduct-authservice \
  "AuthorizationServer__Clients__0__ClientSecret=<client secret>" \
  "AuthorizationServer__EncryptionKey=<encryption key>"
```

Keep `jwt-signing.pem` somewhere durable and out of the repository. Losing it signs every user
out; leaking it lets the holder mint tokens as anyone.

## Pointing a service at it

Consumers hold no key material. They need this service's URL and the issuer/audience it was
configured with:

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MetadataAddress =
            "https://yourproduct-authservice.fly.dev/.well-known/openid-configuration";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = "YourProduct",
            ValidAudience = "YourProduct",
            ValidateIssuerSigningKey = true
        };
    });
```

Set `Jwt__Issuer` and `Jwt__Audience` to something product-specific rather than leaving the
`AuthService` default. Two products both on the defaults would accept each other's tokens.

On an image older than v0.3.4, also set `Jwt__PublicBaseUrl` on this service. Those releases
served a relative `jwks_uri` when it was unset, and JwtBearer then finds no keys: every token
fails with IDX10500.

## Registering an MCP client

This is about MCP **connector clients** — Claude's web, desktop and mobile apps connecting,
on a user's behalf, to an MCP server your project runs. authservice is then the OAuth 2.1
authorization server those clients sign users in through ([ADR 0005](decisions/0005-mcp-authorization-server.md)).
It is not about the `integrate` MCP server this repository ships, which
[`src/AuthService.Mcp`](../src/AuthService.Mcp/README.md) covers.

Nothing below is needed unless you configure a client. With `AuthorizationServer:Clients`
empty — the default — the authorization server's endpoints, pages and metadata do not exist.

### What it needs first

- **RS256 signing** (`Jwt__PrivateKeyPem`). The MCP server verifies tokens from the JWKS; under
  HS256 there is nothing to verify with, and startup fails naming `Jwt:Algorithm`.
- **`Jwt__PublicBaseUrl`**, set to this service's public https origin with no path, for example
  `https://yourproduct-authservice.fly.dev`. It is the issuer of MCP tokens, taken from here and
  never from the request.
- **The schema.** The authorization server's tables arrive as the `AddAuthorizationServer`
  migration. A database created by `EnsureCreated` on an earlier release does not get them:
  move it onto migrations first ([schema/README.md](schema/README.md#moving-an-existing-database-onto-migrations)),
  then run with `Database__SchemaMode=Migrate`. Until a client is configured, nothing needs them:
  such a database keeps working after the upgrade, logout and deletion included.
- **Trusted forwarded headers.** The library refuses plain-http requests to its endpoints. Behind
  a TLS-terminating proxy the app sees http unless it trusts `X-Forwarded-Proto` from that proxy:
  configure `Network__KnownProxies` / `Network__KnownNetworks`, or `Network__TrustAllProxies=true`
  where nothing can reach the app except through the proxy.
- **A machine that is up.** Claude waits at most 10 seconds for the discovery and token endpoints
  (30 for a refresh). Keep `min_machines_running = 1`, as the reference `fly.toml` already does,
  or make sure a cold start is well under that.

### 1. Generate the two secrets

A client secret of 32 random bytes as hex, and a 32-byte encryption key as base64, for the
tokens the library keeps to itself. Generate them; never make them up.

macOS or Linux:

```bash
openssl rand -hex 32
```

```bash
openssl rand -base64 32
```

Windows (PowerShell 7):

```powershell
[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower()
```

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

The first command of each pair is the client secret, the second the encryption key. Both are
platform secrets: never in `[env]`, `appsettings.json`, or the repository.

### 2. Configure the client

Placeholders in angle brackets. The secrets go in the platform's secret store; the rest can be
plain environment variables.

```
AuthorizationServer__Clients__0__ClientId=<claude-yourproduct>
AuthorizationServer__Clients__0__DisplayName=Claude
AuthorizationServer__Clients__0__ClientSecret=<client secret>          # secret
AuthorizationServer__Clients__0__RedirectUris__0=https://claude.ai/api/mcp/auth_callback
AuthorizationServer__Clients__0__AllowedScopes__0=<notes:read>
AuthorizationServer__Clients__0__AllowedScopes__1=offline_access
AuthorizationServer__Clients__0__AllowedResources__0=<https://mcp.yourproduct.example/mcp>
AuthorizationServer__Scopes__0__Name=<notes:read>
AuthorizationServer__Scopes__0__Description=<Read your notes>
AuthorizationServer__EncryptionKey=<encryption key>                    # secret
```

| Setting | What it is |
| --- | --- |
| `ClientId`, `DisplayName` | Your choice of id; the name the consent step shows |
| `RedirectUris` | Matched exactly. `https://claude.ai/api/mcp/auth_callback` serves Claude's web, desktop and mobile apps; https only, or http on a loopback address |
| `AllowedScopes` | The scopes the MCP server enforces. Must include `offline_access`: Claude asks for it only when it is advertised, and without it gets no refresh token |
| `AllowedResources` | The MCP server's canonical URI: lowercase scheme and host, no trailing slash, no fragment. Every token is bound to exactly one, in `aud`. Give the MCP endpoint a path such as `/mcp` |
| `Scopes:<n>:Name` / `Description` | What the consent step shows for each scope. A list, because `:` cannot appear in a configuration key |
| `TokenRequestsPerMinute` | Optional, default 1200: this client's token-endpoint limit, across all its users |
| `TokenRequestsPerUserPerMinute` | Optional, default 30: one user's share of it, so that someone who holds the client secret cannot spend everyone else's budget. A connection refreshes a few times an hour |
| `AuthorizationCodeLifetimeSeconds`, `AccessTokenLifetimeMinutes`, `RefreshTokenLifetimeDays` | Optional, under `AuthorizationServer__`; defaults 60, 15 and 30 (sliding) |

Startup refuses anything unsafe — a short or missing secret, an http redirect URI, a resource
with a fragment, no `offline_access`, HS256, no issuer, no encryption key, or a `Jwt__Issuer` and
`Jwt__Audience` equal to the issuer and a resource, which would let authservice's own API accept
MCP tokens — with a message naming the setting. Configuration is authoritative: at every start the client is created or brought up
to date, and a client you remove is deleted together with every authorization and token it held.

Check the result:

```bash
curl https://yourproduct-authservice.fly.dev/.well-known/oauth-authorization-server
```

### 3. Point the MCP server at it

The MCP server serves its own protected-resource metadata (RFC 9728) and lists this service
**first** in `authorization_servers` — Claude uses the first entry and does not fall back:

```json
{
  "resource": "https://mcp.yourproduct.example/mcp",
  "authorization_servers": ["https://yourproduct-authservice.fly.dev"],
  "scopes_supported": ["notes:read"]
}
```

It validates each token offline: the signature from the JWKS the metadata names, `iss` equal to
`Jwt__PublicBaseUrl` exactly, `aud` equal to its own canonical URI, and `exp`; then it enforces
`scope` itself. The claims are the ones existing tokens carry, under the same names, plus
`client_id` and `scope` — ADR 0005 lists them. In ASP.NET Core:

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MetadataAddress =
            "https://yourproduct-authservice.fly.dev/.well-known/oauth-authorization-server";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = "https://yourproduct-authservice.fly.dev",
            ValidAudience = "https://mcp.yourproduct.example/mcp"
        };
    });
```

authservice's own API refuses these tokens, and the MCP server should refuse authservice's
ordinary ones: the audiences differ.

### 4. Add the connector in Claude

Settings → Connectors → **Add custom connector**, with the MCP server's URL. Open **Advanced
settings** and enter the client id and the client secret. The secret is required: left blank,
Claude acts as a public client, and v1 accepts confidential clients only.

### Choosing who renders sign-in and consent

`AuthorizationServer__Interaction__Mode` picks one per deployment, read on every request.

**`Hosted`** (the default). authservice serves its own pages at `/connect/…`: password sign-in with
the same rules as the login API, a second-factor page, a consent page, and the configured external
providers. For a provider to work from these pages, add this service's own origin to
`OAuth__PostLoginRedirectAllowedBaseUrls` — the provider flow returns to `/oauth/callback` on it.
Registration and password reset are not offered there; the pages link to `FrontendBaseUrl`.
They name your product with `App__Name`, which otherwise reads "Auth Service": set it to the name
your users know, since those pages are where they decide whether to let a client in.

**`External`**. The browser goes to your frontend instead, which signs the user in and asks for
consent with the flows it already has. Set `AuthorizationServer__Interaction__ExternalUrl` to that
page's absolute https URL. The contract it works to:

1. The browser arrives at `ExternalUrl?interaction=<handle>`, with ten minutes to finish.
2. Once the user is signed in, your BFF calls `GET /api/v1/oauth/interactions/{handle}` with the
   user's access token. The response names the client, the host it returns to, the scopes with
   their descriptions, and the resource.
3. On the user's decision it calls `POST /api/v1/oauth/interactions/{handle}/accept` or `…/deny`
   with the same token. An accept body may repeat `scopes` and `resource` to confirm them; anything
   other than what was requested is refused. The first decision wins.
4. The response is `{ "redirectTo": "…" }`. Send the browser there — a top-level navigation. It
   returns to authservice with a single-use ticket, and authservice finishes the flow with the client.

The ticket works only in the browser that started the request, which carries an authservice cookie
for it: a link forwarded to anyone else fails, and spends the ticket, so the user starts again from
the client. The API is server-to-server, so it needs no CORS.

Besides success, the API answers:

| Status | `error` | Meaning, and what to do |
| --- | --- | --- |
| `400` | `invalid_scope`, `invalid_target` | An accept named scopes or a resource other than the ones requested. Repeat what `GET` returned, or send neither |
| `401` | `invalid_token`, or no body | No token, or one whose session has ended (below). Refresh the session or sign the user in again, then retry |
| `403` | `account_not_eligible` | The account may not be given access; `reason` says why. On `consent_required`, have the user accept the current Terms and Privacy versions, then accept again. The others are `email_not_confirmed`, `locked_out` and `account_unavailable` |
| `404` | a sentence | The handle is unknown, has expired, or was already decided |
| `409` | a sentence | Another decision landed at the same moment, and it stands |

Two things are the page's to get right:

- **Treat the handle as a secret for its ten minutes.** Whoever holds it can approve the request
  with their own account, and the victim's browser would then connect the client to the attacker's
  data. Serve the page with `Referrer-Policy: no-referrer`, and keep its query string out of logs,
  analytics and error reports.
- **Call the API with a token from a live session.** A token whose session has since been revoked
  (logout, password change, an admin's revocation) still authenticates elsewhere until it expires,
  but `accept` and `deny` refuse it with `401` and `invalid_token`. Refresh the session or sign the
  user in again, then retry. An approval also lapses if the user's sessions are revoked before the
  browser comes back with the ticket.

### Revocation and rotation

- Logout, a password reset or change, the admin revocation paths and account deletion end a user's
  MCP connections along with their other sessions. `DELETE /api/v1/auth/connected-clients/{clientId}`,
  with the user's token, disconnects one client and forgets their consent. An access token already
  issued stays valid until it expires, at most `AccessTokenLifetimeMinutes` later.
- The Hosted pages' own sign-in session is not ended by logout or an admin's revocation; it lapses
  within 20 minutes. A password change or reset, a lockout and account deletion do end it.
- **Rotating the signing key** is the usual rolling change, with one difference: the library signs
  its codes and refresh tokens with the same key, so keep the old public key in
  `Jwt__PreviousPublicKeyPem` for a **refresh-token lifetime** (30 days by default), not an
  access-token lifetime. Drop it early and every MCP connection has to be made again.
- **Rotating the encryption key** is the same shape: put the new key in
  `AuthorizationServer__EncryptionKey`, the old one in
  `AuthorizationServer__PreviousEncryptionKeys__0`, and remove it a refresh-token lifetime later.

### Things to know

- The pages' cookies are protected with ASP.NET Core Data Protection, as the external sign-in's
  already are. A restart in the middle of someone's sign-in makes them start again; with more than
  one instance, share the key ring or use sticky sessions.
- A failed external-provider sign-in started on a Hosted page ends on the product's login page
  (`OAuth__ErrorRedirectBaseUrl`), not back on authservice's. And with the legacy
  `Auth__AllowTokensInOAuthRedirect` on, the Hosted pages cannot use external providers at all.
- Every Claude user's token and refresh calls come from Anthropic's egress range (`160.79.104.0/21`),
  so the token endpoint is limited per client, and per user within it, rather than per IP. One
  address may still send only as many token requests a minute as all clients together may, which
  bounds a flood of wrong secrets from one machine; a distributed one is for your edge to stop. A
  firewall in front of this service has to let that range through, to the discovery and token
  endpoints as well as the MCP server.
- A scope or resource you withdraw from a client takes effect on its existing connections at their
  next refresh: a withdrawn scope is left out of the new token, and a connection to a withdrawn
  resource ends.
- Claude calls the metadata and token endpoints from its servers, so it needs no CORS. A client that
  calls them from a web page, such as a browser-based MCP inspector you test with, needs that page's
  origin in `Cors__AllowedOrigins` and a client of its own with the page's redirect URI; `http` on a
  loopback address is accepted. Keep such a client, and its origin, to a test deployment.

## A note on shape

The deployment above assumes the consuming project owns the topology: it declares the app,
holds the secrets, and runs the database. A common arrangement is one Postgres app with a
database per service, with this one reached over the platform's private network — but that is
the consumer's decision to make, not this repository's to prescribe.
