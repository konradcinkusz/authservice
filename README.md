# authservice

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

- **User accounts**: registration, login, password reset, change password, soft-delete
  with a retention period.
- **JWT authentication**: short-lived access tokens plus long-lived, revocable refresh
  tokens stored server-side.
- **OAuth social login**: Google and GitHub out of the box (only enabled when credentials
  are configured — the service starts fine without them).
- **Organizations**: multi-tenant grouping with `Owner` / `Admin` / `Member` roles,
  email invitations with retry tracking, and soft-delete/restore.
- **Admin API**: paginated user/organization listing, role management, account lockout
  and restore, protected by `Admin`/`SuperAdmin` roles.
- **Consent tracking**: versioned Terms/Privacy/Cookie acceptance records for GDPR-style
  accountability.
- **Dual database support**: PostgreSQL (default) or SQL Server, selected by configuration.
- **Rate limiting**, CORS, and Swagger/OpenAPI with JWT bearer auth built in.

## What's intentionally *not* here

This is an auth service, not an application backend. It does not include billing,
subscription tiers, usage quotas, or any product-specific data (notes, messages, etc.).
Build those as separate services that trust JWTs issued here.

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

## Getting started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- PostgreSQL (default) or SQL Server
- Docker + Docker Compose (only needed for the quick start above)

### Configuration

Configuration is standard ASP.NET Core (`appsettings.json`, environment variables, or
`dotnet user-secrets`). At minimum, set:

| Key | Description |
| --- | --- |
| `ConnectionStrings:DefaultConnection` | Database connection string |
| `DatabaseProvider` | `PostgreSQL` (default) or `SqlServer` |
| `Jwt:SecretKey` | Symmetric signing key for access tokens (32+ chars) |
| `Jwt:Issuer` / `Jwt:Audience` | JWT issuer/audience, defaults to `AuthService` |

Optional:

| Key | Description |
| --- | --- |
| `OAuth:Google:ClientId` / `ClientSecret` | Enables Google login when both are set |
| `OAuth:GitHub:ClientId` / `ClientSecret` | Enables GitHub login when both are set |
| `OAuth:CallbackBaseUrl` | Public base URL the OAuth provider redirects back to |
| `OAuth:PostLoginRedirectBaseUrl` | Frontend URL to redirect to after login |
| `SendGrid:ApiKey` / `FromEmail` / `FromName` | Enables real email delivery; otherwise emails are only logged |
| `App:Name` | Product name used in email templates (default: "Auth Service") |
| `InitialAdmin:Email` / `Password` | Seeds a `SuperAdmin` account on first startup |
| `Cors:AllowedOrigins` | Array of allowed frontend origins |
| `ConsentVersions:Terms` / `Privacy` / `Cookies` | Legal document versions users must accept |

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

This repository ships without versioned EF Core migrations so it can bootstrap cleanly
against either supported provider (`EnsureCreated` runs at startup). If you need
migration-based schema evolution for a production deployment:

```bash
cd src/AuthService
dotnet ef migrations add InitialCreate
```

...and switch `DatabaseProviderExtensions.InitializeDatabaseAsync` to call
`context.Database.MigrateAsync()` instead of `EnsureCreatedAsync()`.

## Releasing

`.github/workflows/publish-image.yml` publishes a version-pinned image to
`ghcr.io/konradcinkusz/authservice:<tag>` automatically whenever a `v*` tag is pushed —
which is exactly what happens when you **publish a GitHub Release** (create a release,
set the tag to e.g. `v0.1.0`, publish). It can also be run manually from the Actions tab
(`workflow_dispatch`).

```bash
git tag v0.1.0
git push origin v0.1.0
```

**No secrets to configure.** This repo doesn't deploy itself anywhere — the only
credential the workflow uses is the automatic `GITHUB_TOKEN`.

One-time step after your first release: the GHCR package is created **private** by
default even though the repo is public — go to the package's own Settings on GitHub and
set visibility to Public, or every consumer will need its own `ghcr.io` pull
credentials.

## Deploying your own instance

This service is meant to be reused as-is: each consuming project runs its **own
independent instance** — own compute, own database, own `Jwt:SecretKey` — rather than
sharing one central deployment across products. There's no source-level dependency to
take on and this repo hosts no canonical instance of its own; a consuming project pulls
a released image and runs it as part of *its own* infrastructure.

Example for a project deploying to Fly.io:

```toml
# <consuming-project>/flyio/authservice.fly.toml
app = "<yourproject>-authservice"
primary_region = "fra"

[build]
  image = "ghcr.io/konradcinkusz/authservice:v0.1.0"   # pin a real tag, don't float :latest

[env]
  ASPNETCORE_ENVIRONMENT = "Production"
  ASPNETCORE_URLS = "http://+:8080"
  DatabaseProvider = "PostgreSQL"
  Jwt__Issuer = "<YourProject>"
  Jwt__Audience = "<YourProject>"
```

Deploy it with `flyctl deploy --config flyio/authservice.fly.toml --app
<yourproject>-authservice --image ghcr.io/konradcinkusz/authservice:v0.1.0`, with
`ConnectionStrings__DefaultConnection` and `Jwt__SecretKey` set as Fly secrets pointing
at *that project's own* database and *that project's own*, independently generated
signing key. Never reuse a signing key or database across two projects' instances — each
is meant to be a fully independent trust root, not a shared identity provider.

Not deploying to Fly? The same image runs anywhere that runs containers — plain `docker
run`, Azure Container Apps, Kubernetes, whatever the consuming project already uses.
Only the image reference and how you set the two secrets above change.

## API overview

All endpoints are under `/api`. See `/swagger` for the full, generated reference.

- `POST /api/auth/register`, `/login`, `/refresh`, `/logout`
- `GET/POST /api/auth/consents`, `PUT /api/auth/profile`
- `POST /api/auth/forgot-password`, `/reset-password`, `/change-password`
- `DELETE /api/auth/account`
- `GET /api/external-auth/login?provider=Google|GitHub`, `/callback`, `/providers`
- `GET/POST /api/organizations`, `GET/PUT/DELETE /api/organizations/{id}`
- `POST /api/organizations/{id}/invite`, `/restore`
- `POST /api/organizations/invitations/accept`, `GET /api/organizations/invitations`
- `DELETE /api/organizations/{id}/members/{userId}`, `/members/me`
- `GET /api/admin/stats`, `/users`, `/users/{userId}`, `/users/deleted`
- `POST /api/admin/users/{userId}/roles`, `/unlock`, `/restore`

Downstream services can validate the JWTs this service issues (same `Jwt:SecretKey`,
`Issuer`, `Audience`) without calling back into AuthService — organization membership
and role are embedded as claims (`organization`, `organization:{id}:role`).

## Testing

```bash
dotnet test
```

## License

MIT — see [LICENSE](LICENSE).
