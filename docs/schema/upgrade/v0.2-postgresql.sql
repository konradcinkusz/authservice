-- AuthService v0.2 schema upgrade — PostgreSQL
--
-- For deployments created with Database:SchemaMode=EnsureCreated, which never applies
-- changes to a database that already exists. Idempotent; safe to re-run. Back up first.
--
-- Live refresh tokens are dropped: they were stored in plaintext and are now stored as
-- SHA-256 hashes, and there is no way to convert one form into the other. Everyone is
-- signed out once and logs back in. Nothing else is affected.

BEGIN;

-- ─── RefreshTokens: hashed storage, rotation families, revocation detail ────────────

ALTER TABLE "RefreshTokens" ADD COLUMN IF NOT EXISTS "TokenHash"         character varying(64);
ALTER TABLE "RefreshTokens" ADD COLUMN IF NOT EXISTS "FamilyId"          character varying(64);
ALTER TABLE "RefreshTokens" ADD COLUMN IF NOT EXISTS "ReplacedByTokenId" text;
ALTER TABLE "RefreshTokens" ADD COLUMN IF NOT EXISTS "RevokedAt"         timestamp with time zone;
ALTER TABLE "RefreshTokens" ADD COLUMN IF NOT EXISTS "RevokedReason"     character varying(64);

-- Plaintext tokens cannot be migrated into hashes. Clearing the table is the migration.
DELETE FROM "RefreshTokens";

DROP INDEX IF EXISTS "IX_RefreshTokens_Token";
ALTER TABLE "RefreshTokens" DROP COLUMN IF EXISTS "Token";

ALTER TABLE "RefreshTokens" ALTER COLUMN "TokenHash" SET NOT NULL;
ALTER TABLE "RefreshTokens" ALTER COLUMN "FamilyId"  SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS "IX_RefreshTokens_TokenHash" ON "RefreshTokens" ("TokenHash");
CREATE        INDEX IF NOT EXISTS "IX_RefreshTokens_FamilyId"  ON "RefreshTokens" ("FamilyId");
CREATE        INDEX IF NOT EXISTS "IX_RefreshTokens_ExpiresAt" ON "RefreshTokens" ("ExpiresAt");

-- ─── AuditEvents: append-only security audit trail ──────────────────────────────────

CREATE TABLE IF NOT EXISTS "AuditEvents" (
    "Id"                   uuid                     NOT NULL,
    "OccurredAt"           timestamp with time zone NOT NULL,
    "Action"               character varying(64)    NOT NULL,
    "ActorUserId"          character varying(450),
    "ActorEmail"           character varying(256),
    "TargetUserId"         character varying(450),
    "TargetOrganizationId" character varying(450),
    "IpAddress"            character varying(64),
    "UserAgent"            character varying(512),
    "Succeeded"            boolean                  NOT NULL,
    "Metadata"             text,
    CONSTRAINT "PK_AuditEvents" PRIMARY KEY ("Id")
);

-- No foreign key to AspNetUsers on purpose: an audit row must outlive the account it
-- describes, which is why ActorEmail is captured alongside the id.
CREATE INDEX IF NOT EXISTS "IX_AuditEvents_OccurredAt"
    ON "AuditEvents" ("OccurredAt");
CREATE INDEX IF NOT EXISTS "IX_AuditEvents_Action_OccurredAt"
    ON "AuditEvents" ("Action", "OccurredAt");
CREATE INDEX IF NOT EXISTS "IX_AuditEvents_TargetUserId_OccurredAt"
    ON "AuditEvents" ("TargetUserId", "OccurredAt");
CREATE INDEX IF NOT EXISTS "IX_AuditEvents_ActorUserId_OccurredAt"
    ON "AuditEvents" ("ActorUserId", "OccurredAt");
CREATE INDEX IF NOT EXISTS "IX_AuditEvents_TargetOrganizationId_OccurredAt"
    ON "AuditEvents" ("TargetOrganizationId", "OccurredAt");

-- ─── OAuthExchangeCodes: single-use codes replacing tokens-in-the-URL ───────────────

CREATE TABLE IF NOT EXISTS "OAuthExchangeCodes" (
    "Id"         text                     NOT NULL,
    "CodeHash"   character varying(64)    NOT NULL,
    "UserId"     text                     NOT NULL,
    "Provider"   character varying(64),
    "CreatedAt"  timestamp with time zone NOT NULL,
    "ExpiresAt"  timestamp with time zone NOT NULL,
    "ConsumedAt" timestamp with time zone,
    CONSTRAINT "PK_OAuthExchangeCodes" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OAuthExchangeCodes_AspNetUsers_UserId"
        FOREIGN KEY ("UserId") REFERENCES "AspNetUsers" ("Id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "IX_OAuthExchangeCodes_CodeHash"
    ON "OAuthExchangeCodes" ("CodeHash");
CREATE INDEX IF NOT EXISTS "IX_OAuthExchangeCodes_ExpiresAt"
    ON "OAuthExchangeCodes" ("ExpiresAt");

COMMIT;
