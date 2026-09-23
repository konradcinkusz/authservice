# Schema management

## The three modes

`Database:SchemaMode` (or `DATABASE_SCHEMA_MODE`) chooses how the schema comes into existence
at startup:

| Mode | What it does | Use it for |
| --- | --- | --- |
| `EnsureCreated` (default) | Creates the schema when the database is empty. Does nothing at all when it is not. | Demos, local development, tests |
| `Migrate` | Applies the EF Core migrations from `Database:MigrationsAssembly`. | Production, and any database you intend to keep |
| `None` | Nothing. The schema is applied out of band. | Deployments where a DBA or a separate job owns DDL |

`EnsureCreated` is a bootstrap, not an upgrade path, and the distinction is the whole problem:
against an existing database it is a no-op, including for columns added since it first ran. The
app then fails at runtime against a stale schema. Since v0.2 the service logs a warning on
every startup where `EnsureCreated` found an existing database, rather than staying quiet
about it.

The default stays `EnsureCreated` so that `docker compose up` still works with no ceremony,
against either provider, from a fresh clone. A database you intend to keep should run
`Migrate`: from the first schema change after it is created, `EnsureCreated` leaves it behind.

## The migration sets

There are two, one per provider, both committed:

- `src/AuthService.Migrations.PostgreSQL/Migrations/`
- `src/AuthService.Migrations.SqlServer/Migrations/`

One set cannot serve both: the generated DDL differs, and so do the filtered-index expressions
this model uses (`"IsDeleted" = true` versus `[IsDeleted] = 1`). Both sets describe the same
model and start from `InitialCreate`, which produces exactly the schema `EnsureCreated` produces.
That was checked on PostgreSQL by bringing up one database each way and diffing
`pg_dump --schema-only`: the only difference is the `__EFMigrationsHistory` table.

CI's `Migrations` job fails when either set is missing, and when the model has changed without
a matching migration (`dotnet ef migrations has-pending-model-changes`, per provider).

## Running with migrations

```
Database__SchemaMode=Migrate
Database__MigrationsAssembly=AuthService.Migrations.PostgreSQL   # or AuthService.Migrations.SqlServer
```

On an empty database this creates the whole schema. On a database `EnsureCreated` made, run the
adoption script below once first — otherwise `InitialCreate` tries to create tables that already
exist, and the service never becomes ready.

To apply migrations from a job or a pipeline instead of at startup, set
`Database__SchemaMode=None` in the app and run `dotnet ef database update` separately, or apply
the SQL that `dotnet ef migrations script --idempotent` produces for your provider.

## Moving an existing database onto migrations

A deployment on `EnsureCreated` whose database it wants to keep switches once:

1. Back up.
2. If the database predates v0.2, bring it up to date first ([below](#upgrading-a-database-from-before-v02)).
3. Run the adoption script for your provider:
   - [`upgrade/adopt-migrations-postgresql.sql`](upgrade/adopt-migrations-postgresql.sql) —
     `psql -v ON_ERROR_STOP=1 -f adopt-migrations-postgresql.sql "<connection string>"`
   - [`upgrade/adopt-migrations-sqlserver.sql`](upgrade/adopt-migrations-sqlserver.sql) —
     `sqlcmd -b -i adopt-migrations-sqlserver.sql -S <server> -d <database> …`
4. Restart with `Database__SchemaMode=Migrate` and the matching `Database__MigrationsAssembly`.

The script records `InitialCreate` as already applied and touches nothing else. It refuses an
empty database, which `Migrate` handles on its own, and a schema older than v0.2. It is
idempotent. From then on `Migrate` applies each later migration as it ships.

`InitialCreate` is the schema of every release from v0.2 until the first release that ships a
later migration, so adopt while your database is on one of those. A database first created by
`EnsureCreated` on a newer release already carries the newer tables and needs more than this
script — create any database you intend to keep with `Migrate` from the start.

## Upgrading a database from before v0.2

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

## Adding a migration

1. Change the model class and `ApplicationDbContext.OnModelCreating`.
2. Generate the migration for both providers:

   ```bash
   scripts/generate-migrations.sh AddWidgetTable
   ```

   The script runs `dotnet ef migrations add` once per provider, then strips the UTF-8
   byte-order mark `dotnet ef` writes, which the repository's format check rejects. `DesignTimeDbContextFactory` reads
   the same `DATABASE_PROVIDER` the runtime does and needs no reachable database, so nothing has
   to be running.
3. Review the generated DDL — anything provider-specific, such as a filtered index, most of
   all — and commit both sets.
4. Say so in the pull request. A deployment still on `EnsureCreated` against an existing
   database does not pick the change up; it has to move onto migrations first.

One provider by hand, for reference:

```bash
DATABASE_PROVIDER=PostgreSQL \
Database__MigrationsAssembly=AuthService.Migrations.PostgreSQL \
dotnet ef migrations add AddWidgetTable \
  --project src/AuthService.Migrations.PostgreSQL \
  --startup-project src/AuthService
```

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
