# Contributing

Thanks for looking. This is a small, deliberately readable authentication service, and the
readability is the product as much as the features are.

## Scope

`EXTRACTION.md` sets the boundary: **this is an auth service, not an application backend.**

In scope: identity, credentials, tokens, sessions, OAuth sign-in, organizations and their
membership roles, and the administrative surface over those things.

Out of scope: application domain models, billing, notifications beyond auth-related email,
file storage, and anything else a consuming application should own. A change that makes this
service know about your product's nouns is one we will ask you to keep in your own fork.

If you are unsure, open an issue before writing the code. That is cheaper for both of us.

## Getting set up

Requires the .NET 9 SDK, plus Docker if you want a real database.

```bash
git clone https://github.com/konradcinkusz/authservice.git
cd authservice

dotnet restore AuthService.sln
dotnet build AuthService.sln
dotnet test AuthService.sln
```

The tests run against in-memory SQLite and need neither Docker nor network access.

To run the service against Postgres:

```bash
docker compose up --build
```

That brings up Postgres and the service on <http://localhost:8080>, seeds a SuperAdmin, and
enables Swagger at `/swagger`. See `DEMO.md`.

To run it directly instead, set the two settings that have no safe default:

```bash
cd src/AuthService
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Database=authservice;Username=postgres;Password=postgres"
dotnet user-secrets set "Jwt:SecretKey" "$(openssl rand -base64 48)"
dotnet run
```

The service fails fast with a message naming the setting if either is missing or too short.

## Before you open a pull request

```bash
dotnet format --verify-no-changes        # CI enforces this
dotnet build AuthService.sln -warnaserror
dotnet test AuthService.sln
```

CI runs the same three, plus a Docker build and CodeQL.

## Conventions

**Formatting** is whatever `dotnet format` produces, governed by `.editorconfig`. Do not
reformat code you are not otherwise changing — it buries the actual diff.

**Comments** explain *why*, not *what*. The codebase is fairly consistent about this; a
comment that restates the line below it will get a review note. Comments earn their place
when a reader would otherwise wonder why the code is shaped that way — a security trade-off,
a provider quirk, an ordering constraint.

**Naming and structure**: follow the file you are editing. Controllers are thin, services hold
the logic, DTOs are records, and models are plain classes.

**Security-relevant changes** need a note in the PR description about what the change lets an
attacker do that they could not do before, or what it stops them doing. If the answer is
"nothing", say that too.

## Tests

Anything touching authentication behaviour needs a test. `tests/AuthService.Tests` boots the
real application via `WebApplicationFactory` against in-memory SQLite — the real controllers,
the real Identity stack, the real token service — so a test is usually a few HTTP calls rather
than a pile of mocks. Start from `IntegrationTestBase`.

Pin the behaviour that matters, not the shape of the JSON. A test asserting that a locked
account cannot refresh its session is worth ten asserting field ordering.

## Schema changes

The schema is created with `EnsureCreated` by default, which is a bootstrap and not an upgrade
path. If you add or change a column:

1. Update the model and `ApplicationDbContext.OnModelCreating`.
2. Add the equivalent DDL to `docs/schema/upgrade/` for both PostgreSQL and SQL Server.
3. Say so in the PR — existing deployments need to run it.

See `docs/schema/README.md`.

## Commits and pull requests

- One logical change per PR. A security fix and a refactor in the same diff is two PRs.
- Present-tense commit subjects: "Revoke refresh tokens on password change".
- Reference the issue number when there is one.
- Explain the trade-off you chose and what you rejected. This repository's issue tracker is
  written that way and PRs are easier to review when they match.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
