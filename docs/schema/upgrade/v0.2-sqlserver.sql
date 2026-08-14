-- AuthService v0.2 schema upgrade — SQL Server
--
-- For deployments created with Database:SchemaMode=EnsureCreated, which never applies
-- changes to a database that already exists. Idempotent; safe to re-run. Back up first.
--
-- Live refresh tokens are dropped: they were stored in plaintext and are now stored as
-- SHA-256 hashes, and there is no way to convert one form into the other. Everyone is
-- signed out once and logs back in. Nothing else is affected.

BEGIN TRANSACTION;

-- ─── RefreshTokens: hashed storage, rotation families, revocation detail ────────────

IF COL_LENGTH('dbo.RefreshTokens', 'TokenHash') IS NULL
    ALTER TABLE [RefreshTokens] ADD [TokenHash] nvarchar(64) NULL;
GO

IF COL_LENGTH('dbo.RefreshTokens', 'FamilyId') IS NULL
    ALTER TABLE [RefreshTokens] ADD [FamilyId] nvarchar(64) NULL;
GO

IF COL_LENGTH('dbo.RefreshTokens', 'ReplacedByTokenId') IS NULL
    ALTER TABLE [RefreshTokens] ADD [ReplacedByTokenId] nvarchar(max) NULL;
GO

IF COL_LENGTH('dbo.RefreshTokens', 'RevokedAt') IS NULL
    ALTER TABLE [RefreshTokens] ADD [RevokedAt] datetime2 NULL;
GO

IF COL_LENGTH('dbo.RefreshTokens', 'RevokedReason') IS NULL
    ALTER TABLE [RefreshTokens] ADD [RevokedReason] nvarchar(64) NULL;
GO

-- Plaintext tokens cannot be migrated into hashes. Clearing the table is the migration.
DELETE FROM [RefreshTokens];
GO

IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RefreshTokens_Token' AND object_id = OBJECT_ID('dbo.RefreshTokens'))
    DROP INDEX [IX_RefreshTokens_Token] ON [RefreshTokens];
GO

IF COL_LENGTH('dbo.RefreshTokens', 'Token') IS NOT NULL
    ALTER TABLE [RefreshTokens] DROP COLUMN [Token];
GO

ALTER TABLE [RefreshTokens] ALTER COLUMN [TokenHash] nvarchar(64) NOT NULL;
GO
ALTER TABLE [RefreshTokens] ALTER COLUMN [FamilyId] nvarchar(64) NOT NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RefreshTokens_TokenHash' AND object_id = OBJECT_ID('dbo.RefreshTokens'))
    CREATE UNIQUE INDEX [IX_RefreshTokens_TokenHash] ON [RefreshTokens] ([TokenHash]);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RefreshTokens_FamilyId' AND object_id = OBJECT_ID('dbo.RefreshTokens'))
    CREATE INDEX [IX_RefreshTokens_FamilyId] ON [RefreshTokens] ([FamilyId]);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RefreshTokens_ExpiresAt' AND object_id = OBJECT_ID('dbo.RefreshTokens'))
    CREATE INDEX [IX_RefreshTokens_ExpiresAt] ON [RefreshTokens] ([ExpiresAt]);
GO

-- ─── AuditEvents: append-only security audit trail ──────────────────────────────────

IF OBJECT_ID('dbo.AuditEvents', 'U') IS NULL
BEGIN
    CREATE TABLE [AuditEvents] (
        [Id]                   uniqueidentifier NOT NULL,
        [OccurredAt]           datetime2        NOT NULL,
        [Action]               nvarchar(64)     NOT NULL,
        [ActorUserId]          nvarchar(450)    NULL,
        [ActorEmail]           nvarchar(256)    NULL,
        [TargetUserId]         nvarchar(450)    NULL,
        [TargetOrganizationId] nvarchar(450)    NULL,
        [IpAddress]            nvarchar(64)     NULL,
        [UserAgent]            nvarchar(512)    NULL,
        [Succeeded]            bit              NOT NULL,
        [Metadata]             nvarchar(max)    NULL,
        CONSTRAINT [PK_AuditEvents] PRIMARY KEY ([Id])
    );

    -- No foreign key to AspNetUsers on purpose: an audit row must outlive the account it
    -- describes, which is why ActorEmail is captured alongside the id.
    CREATE INDEX [IX_AuditEvents_OccurredAt]
        ON [AuditEvents] ([OccurredAt]);
    CREATE INDEX [IX_AuditEvents_Action_OccurredAt]
        ON [AuditEvents] ([Action], [OccurredAt]);
    CREATE INDEX [IX_AuditEvents_TargetUserId_OccurredAt]
        ON [AuditEvents] ([TargetUserId], [OccurredAt]);
    CREATE INDEX [IX_AuditEvents_ActorUserId_OccurredAt]
        ON [AuditEvents] ([ActorUserId], [OccurredAt]);
    CREATE INDEX [IX_AuditEvents_TargetOrganizationId_OccurredAt]
        ON [AuditEvents] ([TargetOrganizationId], [OccurredAt]);
END
GO

-- ─── OAuthExchangeCodes: single-use codes replacing tokens-in-the-URL ───────────────

IF OBJECT_ID('dbo.OAuthExchangeCodes', 'U') IS NULL
BEGIN
    CREATE TABLE [OAuthExchangeCodes] (
        [Id]         nvarchar(450) NOT NULL,
        [CodeHash]   nvarchar(64)  NOT NULL,
        [UserId]     nvarchar(450) NOT NULL,
        [Provider]   nvarchar(64)  NULL,
        [CreatedAt]  datetime2     NOT NULL,
        [ExpiresAt]  datetime2     NOT NULL,
        [ConsumedAt] datetime2     NULL,
        CONSTRAINT [PK_OAuthExchangeCodes] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_OAuthExchangeCodes_AspNetUsers_UserId]
            FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
    );

    CREATE UNIQUE INDEX [IX_OAuthExchangeCodes_CodeHash]
        ON [OAuthExchangeCodes] ([CodeHash]);
    CREATE INDEX [IX_OAuthExchangeCodes_ExpiresAt]
        ON [OAuthExchangeCodes] ([ExpiresAt]);
END
GO

COMMIT TRANSACTION;
GO
