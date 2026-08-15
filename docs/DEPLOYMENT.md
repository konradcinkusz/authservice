# Deploying your own instance

This repository publishes a container image. It does not deploy itself anywhere and has no
canonical hosted instance — each consuming project runs its own, with its own compute, its own
database and its own signing key (ADR 0001).

That means the `fly.toml`, the secrets and the database live in **the consuming project's**
repository, next to the apps that depend on them. What follows is the reference those
deployments are written against.

## The image

```
ghcr.io/konradcinkusz/authservice:v0.1.0
```

Published by [`.github/workflows/publish-image.yml`](../.github/workflows/publish-image.yml) on
every `v*` tag. Pin a version rather than tracking `latest`: this is `0.x`, and the HTTP
contract may still move.

## What the container needs

| Setting | Required | Notes |
| --- | --- | --- |
| `ConnectionStrings__DefaultConnection` | yes | Startup fails naming this setting if it is missing |
| `DATABASE_PROVIDER` | no | `PostgreSQL` (default) or `SqlServer` |
| `Database__SchemaMode` | no | `EnsureCreated` (default), `Migrate`, or `None` — see [schema/README.md](schema/README.md) |
| `Jwt__PrivateKeyPem` | for RS256 | PKCS#8 RSA private key, 2048-bit minimum |
| `Jwt__SecretKey` | for HS256 | 32+ bytes. Only for deployments where this service is the sole validator |
| `Jwt__Issuer` / `Jwt__Audience` | no | Default `AuthService`. Set them per product so a token from one cannot authenticate against another |
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
  image = "ghcr.io/konradcinkusz/authservice:v0.1.0"

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

## A note on shape

The deployment above assumes the consuming project owns the topology: it declares the app,
holds the secrets, and runs the database. A common arrangement is one Postgres app with a
database per service, with this one reached over the platform's private network — but that is
the consumer's decision to make, not this repository's to prescribe.
