# Open deviations from the reference architecture

Required by [`architecture-standards`](https://github.com/konradcinkusz/architecture-standards)
§3a. Every row is dated. A fixed deviation has its row deleted; an accepted one keeps its
row with the reasoning, because an acknowledged deviation is a decision and an
unacknowledged one is drift.

Compliance was last reviewed in full on **2026-08-14**, against §3 of the reference
architecture.

## Open

| Since | Deviation | Principle | Position |
|---|---|---|---|
| 2026-08-14 | **No OTLP traces, metrics or logs.** Observability is the console logger, plus the structured audit log this service keeps for its own security events. | §3 "Emits OTLP traces, metrics and logs" | **To fix.** Less acute here than in a multi-service pipeline — this is one service and one database — but a sign-in that fails somewhere between OAuth callback, account linking and token issuance is exactly what a trace answers. |
| 2026-08-14 | **No Aspire AppHost, no `AddServiceDefaults()`.** | §3 "Declared in the AppHost…" | **Accepted.** This repository publishes an image and is deployed by whichever project consumes it (ADR 0001). An AppHost describes a system; this is a component of somebody else's. The consuming project owns that declaration. |
| 2026-08-14 | **No committed migration set.** `Database:SchemaMode` defaults to `EnsureCreated`, which creates a schema and then never changes it. | §3 "Schema applied by `MigrateAsync` from provider-specific migrations" | **To fix, and blocked on a refactor.** The two migration assemblies exist; generating into them fails because `dotnet ef` loads the migrations assembly from the startup project's output, so `AuthService` must reference it — and it already references `AuthService`, for the `ApplicationDbContext` type. Breaking that cycle means moving the context into a class library. See [`docs/schema/README.md`](../schema/README.md). |
| 2026-08-14 | **Two providers, one model.** PostgreSQL and SQL Server are both supported, doubling the migration surface, and the SQL Server path has no integration coverage — the test suite runs against SQLite. | §3 (implied by the migration requirement) | **Open question, not yet decided.** Issue #30 raises whether SQL Server support earns its keep. ADR 0003's "stay small" argues against it. Dropping it would unblock some of the row above. |
| 2026-08-14 | **`Program.cs` is ~500 lines and does its own wiring** rather than delegating to `ServiceCollectionExtensions`. | §3 "`Program.cs` is a manifest; wiring is in `ServiceCollectionExtensions`" | **To fix.** The reference architecture names this file specifically (§2, "399 lines (Auth)") and it has grown since. Mechanical, and it is the file every other change also touches, which is the argument for doing it soon rather than never. |
| 2026-08-14 | **`iss` is a bare string, not a URL.** Tokens carry `iss: "AuthService"` (or the deployment's override), so the discovery document reports that rather than the service's origin. | OIDC convention rather than a numbered principle | **Accepted.** Changing it invalidates every issued token and every consumer's `ValidIssuer`, for a cosmetic gain. ADR 0002 records the reasoning; the discovery document is self-consistent as it stands. |

## Closed by the 2026-08-14 review

Listed once for traceability, then deleted at the next review.

- Tokens were signed with a symmetric key shared with every validator, so any service that
  could verify a token could also mint one. Now RS256 with a published JWKS.
- No secret scanner in CI, which P5 makes mandatory — sharper here than most repositories,
  since this one holds an identity system's signing key.
- No `CODEOWNERS`, so a change to token issuance or account linking reviewed like any other.
- No `/alive`; the checklist's liveness endpoint existed only as `/health`.
- The required consent versions were only readable with a token, so a sign-up form could not
  obtain the versions its registration had to accept.
