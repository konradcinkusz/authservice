<a name="readme-top"></a>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo.svg" alt="authservice — JWT auth for ASP.NET Core" width="360">
  </picture>
</p>

# authservice

[![Ask me anything](https://flat.badgen.net/static/Ask%20me/anything?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz "Ask me anything")
[![GitHub license](https://flat.badgen.net/github/license/konradcinkusz/authservice?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz/authservice/blob/main/LICENSE "GitHub license")
[![Maintained](https://flat.badgen.net/static/Maintained/yes?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz/authservice/commits/main "Maintained")
[![GitHub branches](https://flat.badgen.net/github/branches/konradcinkusz/authservice?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz/authservice/branches "GitHub branches")
[![GitHub commits](https://flat.badgen.net/github/commits/konradcinkusz/authservice?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz/authservice/commits/main "GitHub commits")
[![GitHub issues](https://flat.badgen.net/github/issues/konradcinkusz/authservice?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz/authservice/issues "GitHub issues")
[![GitHub pull requests](https://flat.badgen.net/github/prs/konradcinkusz/authservice?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz/authservice/pulls "GitHub pull requests")
[![GitHub release](https://flat.badgen.net/github/release/konradcinkusz/authservice?icon=github&color=black&scale=1.01)](https://github.com/konradcinkusz/authservice/releases "GitHub release")

[![CI](https://github.com/konradcinkusz/authservice/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/konradcinkusz/authservice/actions/workflows/ci.yml "CI")
[![CodeQL](https://github.com/konradcinkusz/authservice/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/konradcinkusz/authservice/actions/workflows/codeql.yml "CodeQL")
[![Secret scan](https://github.com/konradcinkusz/authservice/actions/workflows/secret-scan.yml/badge.svg?branch=main)](https://github.com/konradcinkusz/authservice/actions/workflows/secret-scan.yml "Secret scan")

A standalone authentication and authorization service for ASP.NET Core: user identity,
JWT access/refresh tokens, social login (Google/GitHub), and multi-tenant organizations
with role-based membership. Bring it up as its own microservice and point any frontend
or backend at it over HTTP.

This project started as an extraction of the `AuthService` module from a larger private
product. Everything specific to that product — billing/subscriptions, usage quotas,
in-app announcements, and other product features — was intentionally left behind so this
repository stays generically useful. See [`EXTRACTION.md`](EXTRACTION.md) for the
detailed rationale and what was kept vs. dropped.

## Features

- **User accounts**: registration, login, email verification, password reset, change
  password, soft-delete with a retention period.
- **JWT authentication**: short-lived access tokens plus rotating refresh tokens, stored
  as hashes, with replay detection that kills the whole rotation family.
- **Two-factor authentication**: TOTP with recovery codes, on top of ASP.NET Core Identity's
  own primitives.
- **OAuth social login**: Google and GitHub out of the box (only enabled when credentials
  are configured — the service starts fine without them). Linking requires a
  provider-verified email address, and the callback hands back a single-use exchange code
  rather than putting tokens in a URL.
- **Organizations**: multi-tenant grouping with `Owner` / `Admin` / `Member` roles,
  email invitations with retry tracking, ownership transfer, and soft-delete/restore.
  The permission matrix is documented in [`docs/roles.md`](docs/roles.md).
- **Admin API**: paginated user/organization listing, role management, lock/unlock,
  force-logout, soft-delete/restore, protected by `Admin`/`SuperAdmin` roles.
- **Audit log**: a queryable, append-only record of security-relevant actions — who
  granted a role, who locked an account, and when.
- **Consent tracking and data export**: versioned Terms/Privacy/Cookie acceptance records,
  plus a self-service export endpoint (GDPR Art. 15/20) matching the existing erasure flow.
- **Sign-in for MCP connectors** (optional): an OAuth 2.1 authorization server, authorization
  code with PKCE, through which MCP clients such as Claude connect to your MCP server on a
  user's behalf. It is off until a client is configured; see
  [Registering an MCP client](docs/DEPLOYMENT.md#registering-an-mcp-client).
- **Dual database support**: PostgreSQL (default) or SQL Server, selected by configuration.
- **Rate limiting** (with a configurable proxy trust boundary), CORS, and Swagger/OpenAPI
  with JWT bearer auth built in.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## What's intentionally *not* here

This is an auth service, not an application backend. It does not include billing,
subscription tiers, usage quotas, or any product-specific data (notes, messages, etc.).
Build those as separate services that trust JWTs issued here.

It is not a general OAuth or OpenID Connect provider either. The authorization server serves
pre-registered MCP connector clients and nothing else. It has no ID tokens, `userinfo` or
end-session endpoint, no dynamic client registration, no token introspection, and no
client-credentials or device grant. SAML, SCIM and an admin UI are out as well. For those, use
Keycloak, Ory or Zitadel. The boundary is recorded in
[ADR 0003](docs/decisions/0003-scope.md), as amended by
[ADR 0005](docs/decisions/0005-mcp-authorization-server.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Quick start (Docker Compose)

The fastest way to see it working end-to-end — spins up PostgreSQL and the service
together, with a demo JWT secret and a seeded `SuperAdmin` account:

```bash
docker compose up --build
```

Then follow [`DEMO.md`](DEMO.md) for a full `curl` walkthrough (register, login,
create an organization, invite/accept a member, and query the admin API), or open
http://localhost:8080/swagger to explore interactively. The secrets baked into
`docker-compose.yml` are for local experimentation only — replace them for anything
beyond your own machine.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting started

### Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- PostgreSQL (default) or SQL Server
- Docker + Docker Compose (only needed for the quick start above)

### Configuration

Configuration is standard ASP.NET Core (`appsettings.json`, environment variables, or
`dotnet user-secrets`). At minimum, set:

| Key | Description |
| --- | --- |
| `ConnectionStrings:DefaultConnection` | Database connection string |
| `DatabaseProvider` | `PostgreSQL` (default) or `SqlServer` |
| `Jwt:SecretKey` | Symmetric signing key for access tokens (32+ chars). Required only under HS256 |
| `Jwt:Issuer` / `Jwt:Audience` | JWT issuer/audience, defaults to `AuthService` |

The service fails to start, with a message naming the setting, if the connection string is
missing or the configured signing key is missing or too weak.

### Token signing

Two modes, selected by `Jwt:Algorithm`:

| Key | Description |
| --- | --- |
| `Jwt:Algorithm` | `HS256` or `RS256`. Unset, it is inferred: `RS256` when a private key is configured, `HS256` otherwise |
| `Jwt:PrivateKeyPem` / `Jwt:PrivateKeyPath` | PKCS#8 RSA private key (2048-bit minimum). Required under RS256 |
| `Jwt:PreviousPublicKeyPem` / `Jwt:PreviousPublicKeyPath` | A retired public key, kept valid for verification while tokens signed with it are still alive |
| `Jwt:PublicBaseUrl` | Public origin of this service, used to build `jwks_uri`. Defaults to the request's own scheme and host. Required, as an https origin, once an MCP client is configured, because it is then also the issuer of MCP tokens. Releases before v0.3.4 served a relative `jwks_uri` when it was left empty, which JwtBearer cannot fetch keys from, so set it on those |

**HS256** is the zero-ceremony default and is correct while this service is the only thing
validating its own tokens. Verifying and signing are the same capability under a symmetric
key, so any service given `Jwt:SecretKey` can also mint a token for any user with any role,
including `SuperAdmin`.

**RS256 is what you want the moment a second service validates these tokens.** This service
keeps the private key and is the only thing that can issue; consumers fetch the public key and
can only verify.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-signing.pem
fly secrets set "Jwt__PrivateKeyPem=$(cat jwt-signing.pem)" --app your-authservice
```

Two endpoints are then served anonymously:

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/jwks.json` | The public key set. Empty under HS256 — the symmetric key is never published |
| `GET /.well-known/openid-configuration` | Enough metadata for a consumer to point `JwtBearerOptions` at this service and discover the rest |

**Rotating a key** is a rolling change rather than a flag day: generate a new keypair, move the
old public key to `Jwt:PreviousPublicKeyPem`, set the new private key as `Jwt:PrivateKeyPem`,
and deploy. Both keys appear in the JWKS and both verify; only the new one signs. Drop the
previous key once every token issued before the rotation has expired
(`Jwt:ExpirationMinutes`). With an MCP client configured, keep it for a refresh-token lifetime
instead (`AuthorizationServer:RefreshTokenLifetimeDays`, 30 days by default), because the
authorization server signs its refresh tokens with the same key. The `kid` header is derived
from the key itself, so consumers select the right one without configuration.

Optional:

| Key | Description |
| --- | --- |
| `OAuth:Google:ClientId` / `ClientSecret` | Enables Google login when both are set |
| `OAuth:GitHub:ClientId` / `ClientSecret` | Enables GitHub login when both are set |
| `OAuth:CallbackBaseUrl` | Public base URL the OAuth provider redirects back to |
| `OAuth:PostLoginRedirectBaseUrl` | Frontend URL to redirect to after login |
| `SendGrid:ApiKey` / `FromEmail` / `FromName` | Enables real email delivery; otherwise emails are only logged |
| `App:Name` | Product name used in email templates and on the MCP sign-in and consent pages (default: "Auth Service") |
| `InitialAdmin:Email` / `Password` | Seeds a `SuperAdmin` account on first startup |
| `Cors:AllowedOrigins` | Array of allowed frontend origins |
| `ConsentVersions:Terms` / `Privacy` / `Cookies` | Legal document versions users must accept |
| `Jwt:ExpirationMinutes` / `Jwt:RefreshTokenDays` | Token lifetimes (default 60 minutes / 7 days) |
| `Database:SchemaMode` | `EnsureCreated` (default), `Migrate`, or `None` — see [Database schema](#database-schema) |
| `Database:MigrationsAssembly` | `AuthService.Migrations.PostgreSQL` or `AuthService.Migrations.SqlServer`, matching the provider, when `SchemaMode=Migrate` |
| `Swagger:Enabled` | Serve Swagger UI. Defaults to on in Development, off elsewhere |
| `AuthorizationServer:Clients` | MCP connector clients. With none, the default, the authorization server does not exist. Each takes a client id, a secret, redirect URIs, scopes and one or more resources |
| `AuthorizationServer:EncryptionKey` | 32 random bytes, base64, from a platform secret. Required once a client is configured |
| `AuthorizationServer:Scopes` | What the consent step says about each scope |
| `AuthorizationServer:Interaction:Mode` | `Hosted` (default): authservice renders the sign-in and consent pages. `External`: your frontend does, through the interaction API |

The authorization server also needs RS256 signing and `Jwt:PublicBaseUrl`. Startup refuses an
unsafe client configuration with a message naming the setting. The full procedure, including
the Claude connector settings, is in
[Registering an MCP client](docs/DEPLOYMENT.md#registering-an-mcp-client).

### Security-relevant settings

These change what the service allows. All default to the safe value; the service logs the
posture it started with, and warns when one of the escape hatches is enabled.

| Key | Default | Effect |
| --- | --- | --- |
| `Auth:RequireConfirmedEmail` | auto | Whether an unverified address may sign in or accept invitations. "Auto" means on exactly when email delivery is configured, so the zero-config quick start is not locked out of itself. |
| `Auth:RequireVerifiedProviderEmail` | `true` | Require an OAuth provider to assert it verified the address before linking it to a local account. Turning this off reopens a known account-takeover path. |
| `Auth:AllowTokensInOAuthRedirect` | `false` | Put tokens in the OAuth redirect URL instead of returning a single-use exchange code. For frontends mid-migration only. |
| `Auth:RevokeSessionsOnPasswordChange` | `true` | End all sessions when a password changes. |
| `Auth:ReissueTokensOnPasswordChange` | `true` | Return a fresh token pair so the device that changed the password stays signed in. |
| `Network:ClientIpHeader` | *(none)* | Platform header carrying the real client IP (`Fly-Client-IP`, `CF-Connecting-IP`). Preferred over `X-Forwarded-For`, which clients can forge. |
| `Network:KnownProxies` / `KnownNetworks` | *(empty)* | Proxy IPs / CIDRs whose `X-Forwarded-*` headers are trusted. |
| `Network:ForwardLimit` | `1` | Proxy hops to walk back through. |
| `Network:TrustAllProxies` | `false` | Accept `X-Forwarded-For` from anyone. Only safe when the app is unreachable except through a trusted proxy — otherwise per-IP rate limiting can be bypassed by sending a new header value per request. |

Example for local development with `dotnet user-secrets` (run from `src/AuthService`):

```bash
dotnet user-secrets set "Jwt:SecretKey" "some-long-random-development-secret"
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=authservice_dev;Username=postgres;Password=postgres"
```

### Run locally

```bash
dotnet restore
dotnet run --project src/AuthService
```

The service ensures the database schema exists on startup (see **Database schema**
below) and seeds the `SuperAdmin` / `Admin` / `User` roles. Swagger UI is available at
`/swagger`.

### Run with Docker

`docker compose up --build` (see **Quick start** above) is the easiest path if you don't
already have a database. To build and run the image standalone against your own
database instead:

```bash
docker build -f src/AuthService/Dockerfile -t authservice .
docker run -p 8080:8080 \
  -e Jwt__SecretKey=some-long-random-secret \
  -e ConnectionStrings__DefaultConnection="Host=host.docker.internal;Port=5432;Database=authservice;Username=postgres;Password=postgres" \
  authservice
```

### Database schema

`Database:SchemaMode` chooses how the schema is created at startup:

| Mode | Behaviour | Use for |
| --- | --- | --- |
| `EnsureCreated` (default) | Creates the schema when the database is empty; **does nothing at all when it is not**. | Demos, development, tests |
| `Migrate` | Applies EF Core migrations from `Database:MigrationsAssembly`. | Production, and any database you intend to keep |
| `None` | Nothing — schema applied out of band. | DBA- or job-managed deployments |

`EnsureCreated` is a bootstrap, not an upgrade path: against an existing database it will not
add columns introduced since it first ran, and the app then fails at runtime against a stale
schema. The service logs a warning on every startup where this happens.

A migration set is committed for each provider — one set cannot serve both, because the
generated DDL and the filtered-index expressions differ — so running with migrations is two
settings:

```
Database__SchemaMode=Migrate
Database__MigrationsAssembly=AuthService.Migrations.PostgreSQL   # or AuthService.Migrations.SqlServer
```

An existing `EnsureCreated` database moves onto migrations once, with the adoption script in
`docs/schema/upgrade/`. A model change comes with a migration for both providers:

```bash
scripts/generate-migrations.sh AddWidgetTable
```

Full procedure — adopting an existing database, upgrading one from before v0.2, adding a
migration — in [`docs/schema/README.md`](docs/schema/README.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Releasing

The repository publishes two things, each from its own tag namespace, so either can be
released without the other:

| Tag | Workflow | Publishes |
| --- | --- | --- |
| `v*`, e.g. `v0.3.4` | `.github/workflows/publish-image.yml` | The service image, as `ghcr.io/konradcinkusz/authservice:<tag>` and `:latest` |
| `mcp-v*`, e.g. `mcp-v0.1.1` | `.github/workflows/publish-mcp.yml` | The [`integrate` MCP server](#mcp-integration-server) as self-contained binaries, attached to that tag's release |

**Publish a GitHub Release** with a new tag, and the tag push starts the workflow.
`publish-mcp.yml` uploads to the release for its tag, so for `mcp-v*` create the release
rather than pushing the tag alone. Both workflows can also be run by hand from the Actions tab
(`workflow_dispatch`).

When publishing an `mcp-v*` release, untick **Set as the latest release**, so that the
repository page and `releases/latest` keep pointing at the service. The binaries report the
tag's version in the MCP handshake.

**No secrets to configure.** This repo doesn't deploy itself anywhere — the only
credential the workflows use is the automatic `GITHUB_TOKEN`.

One-time step after your first release: the GHCR package is created **private** by
default even though the repo is public — go to the package's own Settings on GitHub and
set visibility to Public, or every consumer will need its own `ghcr.io` pull
credentials.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Deploying your own instance

This service is meant to be reused as-is: each consuming project runs its **own
independent instance** — own compute, own database, own signing key — rather than
sharing one central deployment across products. There's no source-level dependency to
take on and this repo hosts no canonical instance of its own; a consuming project pulls
a released image and runs it as part of *its own* infrastructure.

Example for a project deploying to Fly.io:

```toml
# <consuming-project>/flyio/authservice.fly.toml
app = "<yourproject>-authservice"
primary_region = "fra"

[build]
  image = "ghcr.io/konradcinkusz/authservice:v0.3.4"   # pin a real tag, don't float :latest

[env]
  ASPNETCORE_ENVIRONMENT = "Production"
  ASPNETCORE_URLS = "http://+:8080"
  DatabaseProvider = "PostgreSQL"
  Jwt__Issuer = "<YourProject>"
  Jwt__Audience = "<YourProject>"
  # Fly sets this header itself and strips any client-supplied copy, so unlike
  # X-Forwarded-For it is a trustworthy partition key for per-IP rate limiting.
  Network__ClientIpHeader = "Fly-Client-IP"

# Point platform health checks at readiness, not liveness: /health answers 200 the
# moment Kestrel binds, which would route live traffic at a machine whose schema is
# still being created — or whose initialization failed outright.
[[http_service.checks]]
  interval = "30s"
  timeout = "5s"
  grace_period = "60s"
  method = "GET"
  path = "/health/ready"
```

Deploy it with `flyctl deploy --config flyio/authservice.fly.toml --app
<yourproject>-authservice --image ghcr.io/konradcinkusz/authservice:v0.3.4`, with
`ConnectionStrings__DefaultConnection` and `Jwt__PrivateKeyPem` set as Fly secrets pointing
at *that project's own* database and *that project's own*, independently generated
signing key ([Token signing](#token-signing)). Never reuse a signing key or database across
two projects' instances — each is meant to be a fully independent trust root, not a shared
identity provider.

Not deploying to Fly? The same image runs anywhere that runs containers — plain `docker
run`, Azure Container Apps, Kubernetes, whatever the consuming project already uses.
Only the image reference and how you set the two secrets above change.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## API overview

Endpoints are served at `/api/v1/...`. The unversioned `/api/...` path is kept as an alias
for the pre-v1 contract; prefer `/api/v1`. See `/swagger` for the full, generated reference.

- `POST /api/v1/auth/register`, `/login`, `/refresh`, `/logout`
- `POST /api/v1/auth/verify-email`, `/resend-verification`
- `GET/POST /api/v1/auth/consents`, `PUT /api/v1/auth/profile`, `GET /api/v1/auth/export`
- `POST /api/v1/auth/forgot-password`, `/reset-password`, `/change-password`
- `POST /api/v1/auth/2fa/enable`, `/verify`, `/disable`, `/recovery-codes`, `/login`
- `DELETE /api/v1/auth/account`
- `GET /api/v1/external-auth/login?provider=Google|GitHub`, `/callback`, `/providers`
- `POST /api/v1/external-auth/exchange`
- `GET/POST /api/v1/organizations`, `GET/PUT/DELETE /api/v1/organizations/{id}`
- `POST /api/v1/organizations/{id}/invite`, `/restore`, `/transfer-ownership`
- `POST /api/v1/organizations/invitations/accept`, `GET /api/v1/organizations/invitations`
- `DELETE /api/v1/organizations/{id}/members/{userId}`, `/members/me`
- `PUT /api/v1/organizations/{id}/members/{userId}/role`
- `GET /api/v1/admin/stats`, `/users`, `/users/{userId}`, `/users/deleted`, `/audit-events`
- `POST /api/v1/admin/users/{userId}/roles`, `/lock`, `/unlock`, `/restore`, `/revoke-sessions`
- `DELETE /api/v1/admin/users/{userId}`
- `DELETE /api/v1/auth/connected-clients/{clientId}` (once an MCP client is configured)
- `GET /api/v1/oauth/interactions/{handle}`, `POST .../accept`, `.../deny` (External interaction mode only)

Once an MCP client is configured, the authorization server adds these routes outside `/api`:
`GET /.well-known/oauth-authorization-server` (RFC 8414 metadata), `GET/POST /connect/authorize`
and `POST /connect/token`. In Hosted mode it also adds the sign-in and consent pages under
`/connect/` and `/oauth/callback`. Its access tokens name this service's URL as issuer and the MCP
server as their only audience. This API refuses them. An MCP server that validates its audience,
as the runbook shows, refuses this API's tokens. The token contract is in
[ADR 0005](docs/decisions/0005-mcp-authorization-server.md).

`GET /health` is liveness (static). `GET /health/ready` is readiness and returns 503 until
the schema is initialised and the database is reachable — point platform health checks there.

Downstream services validate the JWTs this service issues without calling back into
AuthService — organization membership and role are embedded as claims (`organization`,
`organization:{id}:role`).

Under RS256 a consumer needs no key material at all, only this service's URL:

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MetadataAddress = "https://your-authservice.fly.dev/.well-known/openid-configuration";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = "AuthService",     // Jwt:Issuer on this service
            ValidAudience = "AuthService",   // Jwt:Audience on this service
            ValidateIssuerSigningKey = true
        };
    });
```

The signing keys are fetched from the JWKS and refreshed on rotation. Nothing downstream can
issue a token.

Under HS256 a consumer validates with the same `Jwt:SecretKey`, `Issuer` and `Audience` — and
thereby also gains the ability to mint tokens for any user with any role, including
`SuperAdmin`. Only give the secret to services you would trust to do that; the reasoning and
the decision to move to RS256 are recorded in
[`docs/decisions/0002-token-signing-algorithm.md`](docs/decisions/0002-token-signing-algorithm.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## MCP integration server

[`src/AuthService.Mcp`](src/AuthService.Mcp/README.md) is an MCP (Model Context Protocol)
server that wires authservice into a consumer project for you. Point an MCP client (Claude
Code, Claude Desktop, ...) at it and call its single `integrate` tool, and it:

- detects the consumer's stack (ASP.NET Core, Node/Express or Python/FastAPI);
- adds authservice to `docker-compose.yml`, pinned to the latest release;
- generates a fresh signing key, mounts it into the container as a compose secret, and keeps it
  out of git;
- gives the project its own token issuer and audience;
- writes the JWT validation code for the stack;
- optionally deploys.

Only the database connection string is left for you to fill in. Self-contained binaries for
Linux, macOS and Windows are attached to each `mcp-v*`
[release](https://github.com/konradcinkusz/authservice/releases); that directory's README has
the client config and the tool's parameters.

This is a different use of MCP from the authorization server above. Here, authservice ships an
MCP server that helps you set authservice up. There, authservice signs users in so that MCP
clients such as Claude can call *your* MCP server for them.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Testing

```bash
dotnet test
```

The suite boots the real application against in-memory SQLite via `WebApplicationFactory` —
no Docker and no network required.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing and security

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — scope, setup, conventions.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability privately, and the project's
  current security posture.
- [`docs/issue-analysis.md`](docs/issue-analysis.md) — the open backlog analysed, with the
  fixes chosen and the alternatives rejected.
- [`docs/decisions/`](docs/decisions) — architecture decision records.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

MIT — see [LICENSE](LICENSE).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Follow

[![GitHub followers](https://img.shields.io/github/followers/konradcinkusz?style=social)](https://github.com/konradcinkusz "GitHub followers")
[![GitHub stars](https://img.shields.io/github/stars/konradcinkusz/authservice?style=social)](https://github.com/konradcinkusz/authservice/stargazers "GitHub stars")

## Star history

<a href="https://star-history.com/#konradcinkusz/authservice&Timeline">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=konradcinkusz/authservice&type=Timeline&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=konradcinkusz/authservice&type=Timeline" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=konradcinkusz/authservice&type=Timeline" />
</picture>
</a>

<p align="right">(<a href="#readme-top">back to top</a>)</p>
