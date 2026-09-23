-- AuthService: move an existing database onto EF Core migrations — PostgreSQL
--
-- For deployments created with Database:SchemaMode=EnsureCreated at v0.2 or later, or
-- brought up to date with v0.2-postgresql.sql. Records the InitialCreate migration as
-- already applied, so Database:SchemaMode=Migrate starts from here instead of trying to
-- create tables that already exist. Touches nothing outside __EFMigrationsHistory.
-- Idempotent; safe to re-run. Back up first.
--
-- Not for an empty database: Migrate creates the whole schema there on its own.
--
--   psql -v ON_ERROR_STOP=1 -f adopt-migrations-postgresql.sql "<connection string>"

BEGIN;

-- Refuse anything that is not the schema InitialCreate describes. Marking the migration
-- applied over an older schema would leave the difference unapplied, silently and for good.
DO $$
BEGIN
    IF to_regclass('"AspNetUsers"') IS NULL THEN
        RAISE EXCEPTION 'No AuthService schema found. On an empty database, set Database:SchemaMode=Migrate and skip this script.';
    END IF;

    IF to_regclass('"AuditEvents"') IS NULL
       OR to_regclass('"OAuthExchangeCodes"') IS NULL
       OR NOT EXISTS (SELECT 1 FROM information_schema.columns
                      WHERE table_schema = current_schema()
                        AND table_name = 'RefreshTokens'
                        AND column_name = 'TokenHash') THEN
        RAISE EXCEPTION 'This schema predates v0.2. Run v0.2-postgresql.sql first.';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS "__EFMigrationsHistory" (
    "MigrationId"    character varying(150) NOT NULL,
    "ProductVersion" character varying(32)  NOT NULL,
    CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY ("MigrationId")
);

INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES ('20260923101033_InitialCreate', '10.0.11')
ON CONFLICT ("MigrationId") DO NOTHING;

COMMIT;
