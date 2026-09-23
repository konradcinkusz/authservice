# Open deviations

Known gaps between what this service does and what good practice — and its own recorded
decisions — call for.

The register exists because a weakness left open indefinitely reads as optional. Every row is
dated. A fixed deviation has its row deleted; an accepted one keeps its row with the
reasoning — an acknowledged deviation is a decision, an unacknowledged one is drift.

Last reviewed in full on **2026-08-14**; one row added on **2026-08-25**; one row closed and two
rows narrowed on **2026-09-23**.

## Open

| Since | Deviation | Why it matters | Position |
|---|---|---|---|
| 2026-08-14 | **No OTLP traces, metrics or logs.** Observability is the console logger, plus the structured audit log this service keeps for its own security events. | Anything beyond a single log line has to be reconstructed by hand | **To fix.** Less acute here than in a multi-service pipeline — this is one service and one database — but a sign-in that fails somewhere between OAuth callback, account linking and token issuance is exactly what a trace answers. |
| 2026-08-14 | **No orchestrator manifest** declaring this service's dependencies, health checks and wiring for local composition. | A consumer has to infer the topology from the docs | **Accepted.** This repository publishes an image and is deployed by whichever project consumes it (ADR 0001). Such a manifest describes a system; this is one component of somebody else's. The consuming project owns that declaration. |
| 2026-08-14 | **Two providers, one model.** PostgreSQL and SQL Server are both supported, doubling the migration surface, and the SQL Server path has no integration coverage — the test suite runs against SQLite. The SQL Server migration set was generated and reviewed, but has never been applied to a live SQL Server by anything in this repository. | Untested support is a promise the project cannot keep | **Open question, not yet decided.** Issue #30 raises whether SQL Server support earns its keep. ADR 0003's "stay small" argues against it. Dropping it would halve the migration surface. |
| 2026-08-14 | **`Program.cs` is ~500 lines and does its own service wiring** rather than delegating to composition extensions. | The file every change touches is the file hardest to review | **To fix.** Mechanical, and it has grown steadily — which is the argument for doing it soon rather than never. |
| 2026-08-14 | **`iss` is a bare string, not a URL.** Tokens carry `iss: "AuthService"` (or the deployment's override), so the discovery document reports that rather than the service's origin. *Narrowed 2026-09-23:* tokens issued to MCP connector clients carry a URL issuer, `Jwt:PublicBaseUrl`, and their RFC 8414 metadata names it (ADR 0005). Every other token is unchanged. | Consumers expecting the OIDC convention of a URL issuer have to be told otherwise | **Accepted** for the tokens this API issues. Changing it invalidates every issued token and every consumer's `ValidIssuer`, for a cosmetic gain. ADR 0002 records the reasoning; the discovery document is self-consistent as it stands. The two issuers share one key and one JWKS. |
| 2026-08-25 | **One audience for every token.** `Program.cs` validates a single `ValidAudience`, and the README tells every consumer to validate the same value. *Narrowed 2026-09-23:* tokens issued to MCP connector clients are bound to the one MCP server they were requested for (RFC 8707), and this API refuses them (ADR 0005). The tokens this API issues still share one audience. | A token minted for one service is accepted by every other service in the estate, so any service that receives a token can replay it, as the caller, anywhere | **To fix** for the tokens this API issues. Tolerable while every validator is a trusted first-party service carrying a human's request. It stops being tolerable the moment a token is handed to something autonomous — see [ADR 0004](../decisions/0004-agent-to-agent-authorization.md), which depends on the fix but is not a prerequisite for it. |

## Closed since the 2026-08-14 review

Listed once for traceability, then deleted at the next review.

- No committed migration set, so a model change never reached an existing database. Both
  providers' sets are committed as of 2026-09-23 (issue #17), CI fails when the model and a set
  disagree, and `docs/schema/upgrade/adopt-migrations-*.sql` moves an existing `EnsureCreated`
  database onto them. `EnsureCreated` stays the default for the zero-ceremony quick start.

## Closed by the 2026-08-14 review

Listed once for traceability, then deleted at the next review.

- Tokens were signed with a symmetric key shared with every validator, so any service that
  could verify a token could also mint one. Now RS256 with a published JWKS (ADR 0002).
- No secret scanner in CI — sharper here than in most repositories, since this one holds an
  identity system's signing key and its docs are full of example configuration.
- No `CODEOWNERS`, so a change to token issuance or account linking reviewed like any other.
- No `/alive`; the conventional liveness endpoint existed only as `/health`.
- The required consent versions were only readable with a token, so a sign-up form could not
  obtain the versions its registration had to accept.
