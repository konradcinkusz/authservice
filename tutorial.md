# Tutorial: deploying and integrating with `authservice`

This document walks through four topics, step by step:

1. how to run `authservice` locally and deploy it to production (Fly.io),
2. how to use its API as a client (registration, login, organizations, admin panel),
3. how other (external) applications can use `authservice` as a central authentication
   service,
4. how the ready-made demo from `DEMO.md` works.

It assumes basic familiarity with Docker and REST APIs. All `curl` commands are ready to
copy and paste.

---

## 0. What is authservice

`authservice` is a standalone authentication and authorization microservice for
ASP.NET Core (.NET 9) that provides:

- user accounts (registration, login, password reset/change, soft-delete),
- JWT tokens (short-lived access token + long-lived, revocable refresh token),
- social login via Google/GitHub (OAuth),
- multi-tenant **organizations** with `Owner` / `Admin` / `Member` roles and email
  invitations,
- an admin API (user, role, and lockout management),
- consent tracking (Terms/Privacy/Cookies) for GDPR compliance,
- PostgreSQL (default) or SQL Server as the database.

The service is designed so that **other applications (frontend, backend, microservices)
don't have to implement login themselves** — they just need to trust the JWT tokens
issued by this service.

---

## 1. Deployment, step by step

### 1.1. Running locally with Docker Compose (fastest path)

Requirements: Docker + Docker Compose.

```bash
git clone https://github.com/konradcinkusz/authservice.git
cd authservice
docker compose up --build
```

`docker-compose.yml` starts two containers:

- `postgres` — a PostgreSQL 16 database,
- `authservice` — the service itself, listening on port `8080`.

On first startup the service:

- creates the database schema (`EnsureCreated`),
- seeds the `SuperAdmin` / `Admin` / `User` roles,
- since `InitialAdmin__Email` / `InitialAdmin__Password` are set in `docker-compose.yml`,
  immediately creates a `SuperAdmin` account (`admin@example.com` / `Admin123!`) —
  ready to use with the admin API without manually assigning roles.

Check that it's working:

```bash
curl -s http://localhost:8080/health
# {"status":"Healthy","service":"AuthService"}
```

Interactive API documentation (Swagger) is available at `http://localhost:8080/swagger`.

> The secrets baked into `docker-compose.yml` (`Jwt__SecretKey` etc.) are for **local
> experimentation only** — don't use them beyond your own machine.

### 1.2. Running locally without Docker (`dotnet run`)

Requirements: .NET 9 SDK and a running PostgreSQL (or SQL Server) instance.

```bash
cd src/AuthService
dotnet user-secrets set "Jwt:SecretKey" "some-long-random-development-secret"
dotnet user-secrets set "ConnectionStrings:DefaultConnection" \
  "Host=localhost;Port=5432;Database=authservice_dev;Username=postgres;Password=postgres"
cd ../..
dotnet restore
dotnet run --project src/AuthService
```

The minimum configuration you need to set (via `appsettings.json`, environment
variables, or `dotnet user-secrets`):

| Key | Description |
| --- | --- |
| `ConnectionStrings:DefaultConnection` | database connection string |
| `DatabaseProvider` | `PostgreSQL` (default) or `SqlServer` |
| `Jwt:SecretKey` | symmetric key used to sign tokens (32+ characters) |
| `Jwt:Issuer` / `Jwt:Audience` | default to `AuthService` |

Optional: `OAuth:Google:*`, `OAuth:GitHub:*`, `SendGrid:*`, `InitialAdmin:*`,
`Cors:AllowedOrigins`, `ConsentVersions:*` — full list in `README.md`.

### 1.3. Building and running your own Docker image

```bash
docker build -f src/AuthService/Dockerfile -t authservice .
docker run -p 8080:8080 \
  -e Jwt__SecretKey=some-long-random-secret \
  -e ConnectionStrings__DefaultConnection="Host=host.docker.internal;Port=5432;Database=authservice;Username=postgres;Password=postgres" \
  authservice
```

### 1.4. Publishing a release, and deploying your own instance

This repository **does not deploy itself anywhere** — it has no canonical hosted
instance of its own, on Fly.io or otherwise. What it does instead:

1. **Publishing** (`.github/workflows/publish-image.yml`): every `v*` tag push (i.e.
   every GitHub Release) builds `src/AuthService/Dockerfile` and pushes it to
   `ghcr.io/konradcinkusz/authservice:<tag>`. No secrets to configure — the only
   credential involved is the automatic `GITHUB_TOKEN`.

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

   One-time step after your first release: the GHCR package is created **private** by
   default even on a public repo — flip it to Public in the package's own Settings, or
   every consumer needs its own `ghcr.io` pull credentials.

2. **Deploying** is something *your own project* does, pulling that image. Each project
   that uses authservice runs its own independent instance — own compute, own database,
   own `Jwt:SecretKey` — never a shared central deployment. Example `fly.toml` for a
   project deploying to Fly.io:

   ```toml
   # <your-project>/flyio/authservice.fly.toml
   app = "<yourproject>-authservice"
   primary_region = "fra"

   [build]
     image = "ghcr.io/konradcinkusz/authservice:v0.1.0"   # pin a real tag

   [env]
     ASPNETCORE_ENVIRONMENT = "Production"
     ASPNETCORE_URLS = "http://+:8080"
     DatabaseProvider = "PostgreSQL"
     Jwt__Issuer = "<YourProject>"
     Jwt__Audience = "<YourProject>"
   ```

   ```bash
   flyctl deploy --config flyio/authservice.fly.toml \
     --app <yourproject>-authservice \
     --image ghcr.io/konradcinkusz/authservice:v0.1.0
   ```

   Set `ConnectionStrings__DefaultConnection` and `Jwt__SecretKey` as Fly secrets on
   *your* app, pointing at *your* database, with a signing key generated fresh for that
   instance — never reused across projects. Not on Fly? The same image runs anywhere
   that runs containers; only the image reference and how you set those two secrets
   change.

### 1.5. Database schema

The repository **does not include** versioned EF Core migrations — `EnsureCreated` is
called on startup so the service can be started from scratch on either supported
database. If you need migrations for a production environment with an evolving schema:

```bash
cd src/AuthService
dotnet ef migrations add InitialCreate
```

...and change `DatabaseProviderExtensions.InitializeDatabaseAsync` to call
`context.Database.MigrateAsync()` instead of `EnsureCreatedAsync()`.

---

## 2. Using authservice as an API client

All endpoints are under the `/api` prefix, with a full reference generated at
`/swagger`. Below are the most important groups.

### 2.1. Registration and login

```bash
curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "Password123!",
    "acceptedTermsVersion": "2026-01-01",
    "acceptedPrivacyVersion": "2026-01-01"
  }'
```

`acceptedTermsVersion` / `acceptedPrivacyVersion` must exactly match the values from
`ConsentVersions` in the service configuration — otherwise registration is rejected.
The response contains `accessToken`, `refreshToken`, and `expiresIn`.

Login:

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "Password123!"}'
```

Refreshing a token (the old refresh token is revoked, you get a new pair):

```bash
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refresh-token>"}'
```

Logout (`POST /api/auth/logout`) revokes the user's active refresh tokens.

### 2.2. Authorized calls

Pass the access token in the `Authorization: Bearer <token>` header:

```bash
curl -s http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

Other account endpoints: `PUT /api/auth/profile`, `POST /api/auth/change-password`,
`POST /api/auth/forgot-password` / `/reset-password`, `DELETE /api/auth/account`
(soft-delete), `GET/POST /api/auth/consents`.

### 2.3. Social login (OAuth)

```
GET /api/external-auth/login?provider=Google|GitHub&returnUrl=<frontend-url>
GET /api/external-auth/callback   (invoked by the OAuth provider)
GET /api/external-auth/providers  (list of active providers)
```

The frontend redirects the user to `/api/external-auth/login?provider=Google`, the
service drives the whole OAuth handshake, and finally redirects back to `returnUrl` with
JWT tokens appended as query parameters (`accessToken`, `refreshToken`, `expiresIn`).
`returnUrl` is validated against `OAuth:PostLoginRedirectBaseUrl` /
`OAuth:PostLoginRedirectAllowedBaseUrls`, so tokens can't be redirected to an untrusted
server (open-redirect protection).

### 2.4. Organizations (multi-tenant)

```bash
# create an organization
curl -s -X POST http://localhost:8080/api/organizations \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Acme Inc", "description": "Demo organization"}'

# invite a member (role Owner/Admin/Member)
curl -s -X POST "http://localhost:8080/api/organizations/$ORG_ID/invite" \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"email": "bob@example.com", "role": "Member"}'

# the invited user accepts the invitation
curl -s -X POST http://localhost:8080/api/organizations/invitations/accept \
  -H "Authorization: Bearer $BOB_TOKEN" -H "Content-Type: application/json" \
  -d '{"token": "<invite-token>"}'
```

Others: `GET/PUT/DELETE /api/organizations/{id}`, `GET /api/organizations/invitations`,
`DELETE /api/organizations/{id}/members/{userId}` / `/members/me`,
`POST .../restore`.

### 2.5. Admin API

Requires the `Admin` or `SuperAdmin` role:

```bash
curl -s http://localhost:8080/api/admin/stats -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer $ADMIN_TOKEN"
```

Also available: `GET /api/admin/users/{userId}`, `/users/deleted`,
`POST /api/admin/users/{userId}/roles`, `/unlock`, `/restore`.

---

## 3. How external applications can use authservice

`authservice` is meant to act as a **central identity provider** for an ecosystem of
other services — frontends and backends that don't implement login themselves.

### 3.1. Integration model

1. The frontend (SPA/mobile) talks to `authservice` directly: registration, login,
   OAuth, token refresh. It stores the `accessToken` (short-lived) and `refreshToken`
   (long-lived, used to refresh).
2. The frontend attaches the `accessToken` as `Authorization: Bearer <token>` to calls
   to **other** backend services (your actual product/API).
3. **Those other services don't need to call back into authservice** to validate the
   token — they just need to know the same `Jwt:SecretKey`, `Jwt:Issuer`, and
   `Jwt:Audience` and verify the JWT signature locally (a standard JWT Bearer
   middleware, available in practically every framework: ASP.NET Core, Express +
   `jsonwebtoken`, FastAPI + `python-jose`, Spring Security, etc.).

This makes authorization **stateless and fast** — product services don't need to ask
authservice on every request, only verify the signature locally once.

### 3.2. What's in the token (claims)

The access token issued by `TokenService` contains, among others:

| Claim | Meaning |
| --- | --- |
| `sub` / `ClaimTypes.NameIdentifier` | user ID |
| `email` | user's email |
| `ClaimTypes.Name` | username |
| `ClaimTypes.Role` | global roles (`User`, `Admin`, `SuperAdmin`) — may occur multiple times |
| `organization` | ID of an organization the user belongs to — a separate claim per organization |
| `organization:{orgId}:role` | the user's role in that organization (`Owner`/`Admin`/`Member`) |

This lets an external service check, for example, "is this user an `Owner` in
organization X" without any extra network call — it just reads the claims from the
token.

### 3.3. Example: verifying a JWT in another ASP.NET Core service

```csharp
// Program.cs of another service — same values as in authservice
var jwtSecretKey = builder.Configuration["Jwt:SecretKey"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "AuthService";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "AuthService";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey)),
            ClockSkew = TimeSpan.Zero
        };
    });
```

This configuration is identical to the one in `src/AuthService/Program.cs` — just
provide the same secret, issuer, and audience as environment variables in the other
service (e.g. `Jwt__SecretKey`) and it will start accepting tokens issued by
`authservice`, without knowing anything about the database or making any network call
to authservice.

For services in other tech stacks, the principle is the same: any JWT library (HS256,
symmetric key) will verify the token as long as it knows the same
`SecretKey`/`Issuer`/`Audience`.

### 3.4. CORS configuration for frontends

If a frontend calls authservice directly from the browser, its origin must be listed in
`Cors:AllowedOrigins` (locally) or the `CORS_ALLOWED_ORIGIN` variable (Fly.io/
production).

### 3.5. Rate limiting

Authentication endpoints (`login`, `register`, `refresh`) are limited to 20
requests/minute per IP address; other API endpoints are limited to 200 requests/minute
per user (or per IP for anonymous requests). Integrating applications should handle
`429 Too Many Requests` responses with a `retryAfter` field.

---

## 4. How the demo works (`DEMO.md`)

The ready-made demo shows a full lifecycle: from registration, through organizations, to
the admin panel — all via `curl` against the Docker Compose stack.

### Step by step

1. **Start the stack**:

   ```bash
   docker compose up --build -d
   docker compose logs -f authservice   # watch startup until you see "Now listening on..."
   ```

   On first startup, roles and the `SuperAdmin` account
   (`admin@example.com` / `Admin123!`) are seeded, because `InitialAdmin__Email/Password`
   are set in `docker-compose.yml`.

2. **Register Alice** — `POST /api/auth/register`, the result is saved to a file, and
   `accessToken` is extracted into the `ALICE_TOKEN` variable (the demo uses `jq`).

3. **Fetch the profile** — `GET /api/auth/me` with Alice's token.

4. **Create an organization** — `POST /api/organizations` as Alice; `ORG_ID` is saved
   into a variable.

5. **Invite a second user (Bob)** — `POST /api/organizations/{id}/invite`. Since no
   email provider (SendGrid) is configured in the demo, the invitation **isn't actually
   sent** — the service logs a warning containing the invitation token:

   ```bash
   docker compose logs authservice | grep "Invitation token:" | tail -1
   ```

   The token needs to be copied manually from the log.

6. **Register Bob and accept the invitation** — Bob must register with the **same
   email** the invitation was sent to, then call
   `POST /api/organizations/invitations/accept` with the copied token.

7. **Verify membership** — `GET /api/organizations/{id}` as Alice, checking the
   `members` field — Bob should appear there.

8. **Admin panel** — log in as the seeded `SuperAdmin`, then
   `GET /api/admin/stats` and `GET /api/admin/users` show admin-level data.

### Ending the demo

```bash
docker compose down -v   # -v also removes the Postgres volume, wiping demo data
```

The demo deliberately doesn't configure SendGrid or OAuth, so it can run offline, fully
locally, without any external accounts — the only "workaround" is reading the invitation
token manually from the logs instead of an email.

---

## 5. Tests

```bash
dotnet test
```

## 6. Further reading

- [`README.md`](README.md) — full configuration and API reference.
- [`DEMO.md`](DEMO.md) — the raw demo script described in section 4.
- [`EXTRACTION.md`](EXTRACTION.md) — the history and rationale behind extracting this
  service from a larger project, what was kept, and what was intentionally dropped.
