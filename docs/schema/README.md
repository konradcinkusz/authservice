# Schema management

## The three modes

`Database:SchemaMode` (or `DATABASE_SCHEMA_MODE`) chooses how the schema comes into existence
at startup:

| Mode | What it does | Use it for |
| --- | --- | --- |
| `EnsureCreated` (default) | Creates the schema when the database is empty. Does nothing at all when it is not. | Demos, local development, tests |
| `Migrate` | Applies EF Core migrations from `Database:MigrationsAssembly`. | Production |
| `None` | Nothing. The schema is applied out of band. | Deployments where a DBA or a separate job owns DDL |

`EnsureCreated` is a bootstrap, not an upgrade path, and the distinction is the whole problem:
against an existing database it is a no-op, including for columns added since it first ran. The
app then fails at runtime against a stale schema. Since v0.2 the service logs a warning on
every startup where `EnsureCreated` found an existing database, rather than staying quiet
about it.

The default stays `EnsureCreated` so that `docker compose up` still works with no ceremony,
against either provider, from a fresh clone.

## Why migrations are not committed

One migration set cannot serve both PostgreSQL and SQL Server: the generated DDL differs, and
so do the filtered-index expressions this model uses (`"IsDeleted" = true` versus
`[IsDeleted] = 1`). The standard answer is one migrations assembly per provider, generated
locally, which is what the wiring below supports.

## Generating migrations

Both migration projects already exist and are wired up. Generate a set into each with:

```bash
scripts/generate-migrations.sh InitialCreate
```

That runs, for each provider, what you would otherwise type by hand.
`DesignTimeDbContextFactory` reads the same `DATABASE_PROVIDER` the runtime does and needs no
reachable database, so nothing has to be running:

```bash
DATABASE_PROVIDER=PostgreSQL \
Database__MigrationsAssembly=AuthService.Migrations.PostgreSQL \
dotnet ef migrations add InitialCreate \
  --project src/AuthService.Migrations.PostgreSQL \
  --startup-project src/AuthService

DATABASE_PROVIDER=SqlServer \
Database__MigrationsAssembly=AuthService.Migrations.SqlServer \
dotnet ef migrations add InitialCreate \
  --project src/AuthService.Migrations.SqlServer \
  --startup-project src/AuthService
```

Review the generated DDL and commit it. CI's `Migrations` job turns from a no-op into a real
guard — `has-pending-model-changes` — as soon as a set is present.

### The project layout, and the cycle it exists to avoid

`dotnet ef` loads the migrations assembly out of the **startup project's** output directory,
so `AuthService` has to reference `AuthService.Migrations.*`. Those projects in turn need the
`ApplicationDbContext` type their `[DbContext(...)]` attributes name. While the context lived
in `AuthService` that was a cycle, and no combination of flags resolved it — every attempt
failed with `File '.../AuthService.Migrations.PostgreSQL.dll' not found.`

`src/AuthService.Data/` is the fix. It holds the entity types, `ApplicationDbContext`,
`DesignTimeDbContextFactory` and the provider wiring, and depends on nothing else in the
repository:

```
AuthService.Data  ←  AuthService.Migrations.PostgreSQL  ←┐
                  ←  AuthService.Migrations.SqlServer   ←┤
                  ←──────────────────────────────────── AuthService
```

Namespaces did not change with the move (`AuthService.Data`, `AuthService.Models`,
`AuthService.Extensions`), so no `using` anywhere in the service or the tests was affected.

Then run with:

```
Database__SchemaMode=Migrate
Database__MigrationsAssembly=AuthService.Migrations.PostgreSQL
```

To apply migrations from a job or a pipeline instead of at startup, set
`Database__SchemaMode=None` in the app and run `dotnet ef database update` separately.

## Upgrading an existing database

Deployments created before v0.2 have a schema `EnsureCreated` will never update. The v0.2
changes are additive, and the DDL is in this directory:

- [`upgrade/v0.2-postgresql.sql`](upgrade/v0.2-postgresql.sql)
- [`upgrade/v0.2-sqlserver.sql`](upgrade/v0.2-sqlserver.sql)

Both scripts are idempotent and safe to re-run. Take a backup first anyway.

What changes:

| Table | Change |
| --- | --- |
| `RefreshTokens` | `Token` → `TokenHash`; adds `FamilyId`, `ReplacedByTokenId`, `RevokedAt`, `RevokedReason` |
| `AuditEvents` | New table |
| `OAuthExchangeCodes` | New table |

**Existing refresh tokens do not survive the upgrade.** They were stored in plaintext and are
now stored as hashes; there is no way to convert one into the other, and keeping the plaintext
column would defeat the change. The scripts drop existing rows, which signs everyone out once.
Users log back in as usual — no data other than live sessions is affected.

## Changing the model

1. Update the model class and `ApplicationDbContext.OnModelCreating`.
2. Add the DDL to `docs/schema/upgrade/` for **both** providers.
3. Regenerate migrations in both migration projects if your deployment uses them.
4. Say so in the pull request — `EnsureCreated` deployments will not pick the change up.
