-- AuthService: move an existing database onto EF Core migrations — SQL Server
--
-- For deployments created with Database:SchemaMode=EnsureCreated at v0.2 or later, or
-- brought up to date with v0.2-sqlserver.sql. Records the InitialCreate migration as
-- already applied, so Database:SchemaMode=Migrate starts from here instead of trying to
-- create tables that already exist. Touches nothing outside __EFMigrationsHistory.
-- Idempotent; safe to re-run. Back up first.
--
-- Not for an empty database: Migrate creates the whole schema there on its own.
--
-- One batch, so a refusal below stops the script before anything is written:
--
--   sqlcmd -b -i adopt-migrations-sqlserver.sql -S <server> -d <database> ...

SET XACT_ABORT ON;

-- Refuse anything that is not the schema InitialCreate describes. Marking the migration
-- applied over an older schema would leave the difference unapplied, silently and for good.
-- (THROW must follow a terminated statement; the leading semicolon supplies one.)
IF OBJECT_ID(N'[dbo].[AspNetUsers]', N'U') IS NULL
BEGIN
    ;THROW 50000, N'No AuthService schema found. On an empty database, set Database:SchemaMode=Migrate and skip this script.', 1;
END;

IF OBJECT_ID(N'[dbo].[AuditEvents]', N'U') IS NULL
   OR OBJECT_ID(N'[dbo].[OAuthExchangeCodes]', N'U') IS NULL
   OR COL_LENGTH(N'dbo.RefreshTokens', N'TokenHash') IS NULL
BEGIN
    ;THROW 50000, N'This schema predates v0.2. Run v0.2-sqlserver.sql first.', 1;
END;

BEGIN TRANSACTION;

IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
BEGIN
    CREATE TABLE [__EFMigrationsHistory] (
        [MigrationId] nvarchar(150) NOT NULL,
        [ProductVersion] nvarchar(32) NOT NULL,
        CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
    );
END;

IF NOT EXISTS (SELECT 1 FROM [__EFMigrationsHistory] WHERE [MigrationId] = N'20260923101041_InitialCreate')
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260923101041_InitialCreate', N'10.0.11');

COMMIT;
