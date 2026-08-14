# Backlog analysis and alternative fixes

Every open issue, verified against the code, with the fix that was implemented and the
alternatives that were considered and rejected. Where this change set does something other
than what the issue proposed, the reasoning is here.

**Verification note:** the container this analysis was produced in had no .NET SDK and the
network policy blocked the SDK download, so nothing here was compiled or executed locally.
Everything was verified by reading, and by the test suite added under issue #18 running in CI.

---

## Security and correctness

### #5 — OAuth linking without a verified provider email (account takeover)

**Verified.** `ExternalAuthController.Callback` resolved an existing account with
`FindByEmailAsync(email)` and then `AddLoginAsync`, with no check of Google's `email_verified`
claim or GitHub's `verified`/`primary` flags. The highest-severity issue in the backlog.

**Implemented.** `IProviderEmailVerifier`, consulted before the address is used to match *or*
create an account:

- **Google** — requires the `email_verified` claim. That claim is not mapped by the Google
  handler by default, so `ClaimActions.MapJsonKey("email_verified", ...)` was added to
  `Program.cs`. Without the mapping the verifier correctly refuses rather than silently
  passing.
- **GitHub** — the profile email proves nothing, so the verifier calls `GET /user/emails`
  (needs the `user:email` scope, already requested) and requires `verified: true`. This needs
  the provider access token, so `SaveTokens` is now on for the GitHub handler; the token lives
  in the external login cookie for the duration of the callback and is never persisted.
- **Unknown providers** default to *not verified*. Adding a provider means adding its rule
  deliberately, rather than inheriting a free pass.

**Alternatives considered.**

1. *Refuse the login outright when unverified* (what the issue leans toward). Implemented, but
   with a distinguishable redirect (`error=email_not_verified&provider=...`) so a frontend can
   explain what to do instead of showing a generic failure.
2. *Create a separate account instead of linking.* Rejected: it silently produces two accounts
   with the same address, which `RequireUniqueEmail` forbids anyway, and users experience it
   as "my account disappeared".
3. *Link only after the user authenticates locally first.* The most correct answer, and worth
   doing later as an explicit "connect account" flow. Rejected as the immediate fix because it
   requires a UI this repository does not own; the verifier closes the hole without one.
4. *Prefer `primary: true` on GitHub.* Rejected as a requirement — a verified non-primary
   address is genuinely owned by the user, and requiring primary would reject legitimate
   logins for no security gain.

`Auth:RequireVerifiedProviderEmail` (default `true`) exists as a documented escape hatch, and
the service logs a warning at startup when it is off.

### #6 — Plaintext refresh tokens, no reuse detection

**Verified.** `StoreRefreshTokenAsync` wrote the raw token; lookup compared the raw value.

**Implemented.** `RefreshToken.Token` becomes `TokenHash`, storing Base64 SHA-256. Added
`FamilyId`, `ReplacedByTokenId`, `RevokedAt` and `RevokedReason`. Presenting an
already-revoked token revokes the entire rotation family and writes an audit event.

**Alternatives considered.**

1. *A slow KDF (bcrypt/PBKDF2) instead of SHA-256.* Rejected, and the issue is right about
   why: the token is already 64 bytes of CSPRNG output, so there is no dictionary to attack
   and a slow hash only costs latency on every refresh.
2. *Encrypt rather than hash.* Rejected — it keeps a key that can turn the database back into
   live credentials, which is the property being removed.
3. *`ReplacedByTokenId` chain vs `FamilyId`.* Both are stored. The chain is useful forensics;
   the family id is what makes revocation a single indexed `UPDATE` rather than a walk.
4. *Revoke only the presented token on reuse.* Rejected. The service cannot tell the thief
   from the victim, so the only safe move is to end the session — which is what the OAuth 2.0
   Security BCP says.

`RevokedReason` was not in the issue. It is there because "this session ended" is a question
support gets asked, and "rotated" versus "reuse-detected" versus "admin-locked" are very
different answers.

### #7 — Bypassable per-IP rate limiting; dead `api` policy

**Verified.** `KnownNetworks.Clear()` + `KnownProxies.Clear()` meant `X-Forwarded-For` was
accepted from any caller, and `UseForwardedHeaders()` runs before `UseRateLimiter()`, so a
fresh header value bought a fresh bucket. The `api` policy was referenced nowhere.

**Implemented.** A `Network` configuration section: `KnownProxies`, `KnownNetworks` (CIDR),
`ForwardLimit`, `TrustAllProxies` (default `false`), and `ClientIpHeader`. Rate limiting and
audit records partition on `HttpContext.ResolveClientIp(...)`. `[EnableRateLimiting("api")]`
now sits on `OrganizationsController` and `AdminController`.

**Alternatives considered.**

1. *Just revert the `Clear()` calls.* Rejected — it breaks Fly, where the hop count is not
   knowable in advance, which is presumably why they were there.
2. *Prefer `Fly-Client-IP`* (the issue's suggestion). Generalised into `Network:ClientIpHeader`
   rather than hard-coding Fly, so Cloudflare (`CF-Connecting-IP`) and others work the same
   way. Set to `Fly-Client-IP` in `flyio/authservice.fly.toml`. This is the good answer
   because such headers are single-valued and set by the platform, unlike `X-Forwarded-For`
   which any client can pre-populate.
3. *Delete the `api` policy* (the issue offers this as the alternative). Rejected — 200/min
   per user on the organization and admin surface is a sensible limit that was simply never
   wired up.
4. *Keep `TrustAllProxies` as the default to avoid breaking existing deployments.* Rejected:
   a security default that is wrong everywhere except one platform is the wrong default. It
   is opt-in, and the startup log states which posture is active.

### #8 — Swagger served in Production

**Verified.** `UseSwagger()`/`UseSwaggerUI()` sat outside any environment check.

**Implemented.** `Swagger:Enabled`, defaulting to `app.Environment.IsDevelopment()` — exactly
the issue's suggestion, which was already the right shape. Deployments that want public API
docs keep them with one setting.

Additionally, Swagger now documents only the `/api/v1/...` routes: with the unversioned alias
in place every action has two paths, and a spec listing both describes a contract nobody has.

### #9 — `change-password` did not revoke refresh tokens

**Verified.** `ResetPassword` revoked; `ChangePassword` did not.

**Implemented.** Revocation on password change, plus a **fresh token pair in the response** —
option (b) in issue #31, which was also its recommendation. The caller's device stays signed
in; every other session dies.

**Alternatives considered.**

1. *Revoke everything including the caller* (simplest, what most services do). Available via
   `Auth:ReissueTokensOnPasswordChange=false`. Not the default, because "change your password
   and get signed out of the device you are holding" is a worse experience for no security
   gain — the caller just proved they know both passwords.
2. *Revoke everything except the caller's current token.* Rejected: it requires the endpoint
   to know which refresh token the caller holds, which it does not — the request carries an
   access token, not a refresh token.

The response shape changes from `{message}` to `{message, sessionsRevoked, tokens}`. Additive,
so existing clients reading `message` are unaffected.

### #10 — Refresh never re-validated user state

**Verified.** `RefreshTokenAsync` checked existence, revocation and expiry, and nothing about
the user.

**Implemented.** After loading the user, refresh is refused when the user is soft-deleted or
locked out, and the rotation family is revoked so a locked account cannot keep retrying.
Lockout is checked with `UserManager.IsLockedOutAsync`, which respects `LockoutEnabled`, rather
than reading `LockoutEnd` directly as the issue's snippet does — a user with lockout disabled
should not be locked out by a stale timestamp.

**On the related minor issue** (login's distinct "Account is locked out" message being an
enumeration oracle): the message is now returned **only when the supplied password was
correct**. A caller who already knows the password learns nothing new from being told the
account is locked, while an attacker probing addresses gets the same generic
`Invalid email or password` either way. This seemed better than both alternatives — keeping
the oracle, or removing a message that legitimate locked-out users need.

### #11 — Sole owner could demote themselves

**Verified.** `UpdateMemberRole` had no owner-count guard, while `RemoveMember` and
`LeaveOrganization` both did.

**Implemented.** The guard, plus the extraction the issue suggests: all three endpoints now
call one `CountOwnersAsync` helper. The count uses `IgnoreQueryFilters()` so a soft-deleted
organization is still counted consistently. Also short-circuits when the role is unchanged, so
a no-op "set Owner to Owner" is not refused by the guard.

The issue notes that with two owners either can demote the other. Left as-is deliberately —
that is a coherent model (owners are peers), and the invariant that matters is "never zero
owners", which is now enforced on every path. Documented in `docs/roles.md`.

### #12 — Admins could invite at the Owner role

**Verified.** `InviteMember` authorised Owner-or-Admin and then accepted any role.

**Implemented.** Granting Owner requires being an Owner. The response is 403 with an
explanatory message rather than a bare `Forbid()`, because the caller is legitimately
authorised for the endpoint and only the requested role is refused.

**The neighbouring boundaries the issue asks about**, now decided and documented:

- *An Admin can remove another Admin* — kept. Admins are peers; the Owner boundary is the one
  that matters.
- *An Admin can revoke an Owner-role invitation created by an Owner* — kept. Revoking is
  destructive-but-recoverable (re-invite), unlike granting.

Both are in `docs/roles.md`, which is the permission matrix the issue asked for. The model
previously existed only implicitly across ~800 lines of controller, which is how these two
gaps survived.

### #13 — Empty-string defaults defeated the startup guards

**Verified.** `appsettings.json` shipped `"DefaultConnection": ""` and `"SecretKey": ""`, so
`??` never fired and neither error message was reachable.

**Implemented.** Both empty keys deleted from `appsettings.json`, `IsNullOrWhiteSpace` checks
with messages naming the setting *and* how to set it, and the ≥ 32-byte key-length check the
issue asks for — validated with `Encoding.UTF8.GetByteCount`, not `.Length`, since a
multi-byte passphrase of 32 characters is more than 32 bytes and a check on character count
would be wrong in the safe direction but for the wrong reason.

The Docker CI job asserts the guard by running the image with no connection string and
requiring it to fail *and* to name the missing setting — so this cannot silently regress.

### #14 — `/health` reported Healthy without a database

**Verified.** A static literal, returning 200 the instant Kestrel bound, with
`flyio/authservice.fly.toml` pointing its platform check at it.

**Implemented.** Exactly the split the issue proposes: `/health` stays static liveness,
`/health/ready` reports readiness and returns 503 until `IMigrationCompletionSignal` has
completed *and* `CanConnectAsync` succeeds. The Fly check now points at `/health/ready`.

**One deviation:** the issue suggests `AddDbContextCheck()` from
`Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore`. A small custom
`IHealthCheck` is used instead — it needs both conditions in one place anyway, and this avoids
a new package dependency for about fifteen lines of code.

`IMigrationCompletionSignal` gained a non-blocking `IsCompleted` property; the existing
`WaitAsync` is unsuitable for a probe that must answer immediately.

### #15 — OAuth tokens in the redirect query string

**Verified.** Both tokens were placed in the URL, with a comment acknowledging it.

**Implemented.** Option 1 from the issue — the single-use exchange code — because it is the
only one that keeps the "any frontend, any origin" design the controller is built around.
The callback redirects with `?code=...`; the frontend POSTs it to
`/api/v1/external-auth/exchange` and receives tokens in the response body. The code is 32 bytes
of CSPRNG, stored hashed, single-use, and expires in 60 seconds.

**Alternatives considered.**

1. *`HttpOnly; Secure; SameSite=Lax` cookie.* Strictly stronger — the token never reaches
   JavaScript — but only works when the API and frontend share a registrable domain, which
   this service explicitly does not assume.
2. *Auto-submitting POST form.* Keeps tokens out of the URL but puts them in a page body and
   requires the service to render HTML, which it otherwise never does.
3. *Fragment (`#`) instead of query string.* Rejected. Better than a query string, but still
   in browser history and still one careless `location.href` from leaking.

`Auth:AllowTokensInOAuthRedirect` restores the old behaviour for frontends mid-migration, and
logs a warning at startup when enabled.

**Beyond the issue:** the exchange endpoint is also where the second factor is applied for
OAuth logins. `ExternalLoginSignInAsync` passes `bypassTwoFactor: true`, which was harmless
when 2FA did not exist and would have been a hole the moment it did — so a 2FA-enabled account
gets a challenge from the exchange call rather than tokens.

---

## Missing features

### #16 — Email verification

**Implemented.** `POST /verify-email`, `POST /resend-verification`, verification email on
registration, and `SignIn.RequireConfirmedEmail` driven by configuration.

**The design problem the issue does not address:** the default `IEmailService` is a no-op that
only logs. Turning verification on unconditionally would mean nobody can ever sign in to a
zero-configuration deployment — the docker-compose quick start would lock users out of
accounts they just created.

**Resolved with:** `Auth:RequireConfirmedEmail` defaults to *"on exactly when this deployment
can send email"* (i.e. when SendGrid is configured), and can be pinned explicitly either way.
Verification is therefore active in any real deployment and absent in the demo, without a
special case in the code. The active posture is printed in the startup log.

Registration returns **202** with `emailVerificationRequired` when verification is pending,
rather than 200 with tokens. Issuing tokens for an unproven address would make verification
decorative.

Invitation acceptance now requires a confirmed address — the access-control consequence the
issue identifies, where an unverified address is enough to join an organization that invited
someone else.

### #17 — EF migrations instead of `EnsureCreated`

**Partially implemented — the one item deliberately left incomplete, see below.**

**Implemented:** `Database:SchemaMode` (`EnsureCreated` | `Migrate` | `None`),
`Database:MigrationsAssembly` wiring for both providers, a `DesignTimeDbContextFactory` so
`dotnet ef migrations add` works without a running database, a loud warning when
`EnsureCreated` finds an existing database and does nothing, and `docs/schema/README.md` with
the exact commands.

**Not implemented:** the migration files themselves. Generating them requires `dotnet ef`,
and the SDK could not be installed in this environment. Hand-writing a full initial migration
for the entire Identity schema plus custom tables, twice, unverified, would be worse than not
shipping one.

**Instead**, since this change set alters the schema and `EnsureCreated` will not apply that to
an existing database, `docs/schema/upgrade/` contains hand-written idempotent DDL for both
PostgreSQL and SQL Server. That is a much smaller, reviewable artifact than a synthetic
migration set, and existing deployments have a path forward either way.

Note that the upgrade drops existing refresh tokens: they were plaintext, are now hashes, and
one cannot be converted into the other. Everyone signs in again once.

### #18 — No test coverage of authentication behaviour

**Verified.** Two files, ~6 assertions, covering an array literal and a `switch`.

**Implemented.** Integration tests via `WebApplicationFactory<Program>` — the real controllers,
the real Identity stack, the real token service — covering: registration and login, the
credential-response-uniformity property, refresh rotation, replay detection killing the
family, tokens never stored in plaintext, refusal to refresh for locked-out and soft-deleted
users, password change revoking other sessions while reissuing the caller's, logout, the
sole-owner demotion guard, Admin-cannot-invite-Owner, ownership transfer atomicity, 2FA
enrolment being inactive until confirmed, challenge tokens being unusable as access tokens,
data export, and Swagger being off when disabled.

**Deviation from the issue:** it suggests Testcontainers-Postgres for fidelity, or SQLite.
SQLite is used, for a specific reason: these tests must run in CI with no Docker daemon and no
network. The InMemory provider was rejected outright — it ignores the unique constraints and
filtered indexes that several of these tests depend on.

The cost is honest: SQLite cannot represent the provider-specific filtered-index syntax, so
that surface is covered by the schema documentation and the Docker build job rather than by
tests. `public partial class Program { }`, present since the extraction for exactly this
purpose, is finally used.

### #19 — Ownership transfer endpoint referenced but absent

**Implemented.** `POST /api/v1/organizations/{id}/transfer-ownership` with `{ toUserId }`:
caller must be an Owner, target must already be a member, both role changes commit in one
`SaveChanges`.

**Two decisions the issue leaves open:**

1. *What happens to the outgoing owner.* They become **Admin**, not Member. A transfer is a
   handover, not a resignation, and demoting someone two levels by surprise is the more
   damaging default. `{"retainAdminRole": false}` steps all the way down.
2. *Whether the target must accept.* **No.** Acceptance requires a pending-transfer entity, a
   notification, and an expiry — real complexity for a case where the two parties are already
   in the same organization and the outgoing owner retains Admin. Revisit if asked for.

The error messages that referenced the non-existent endpoint now name its actual path.

### #20 — Admin API could unlock but not lock

**Implemented.** `POST /users/{id}/lock` (`{until}`, null meaning indefinite),
`POST /users/{id}/revoke-sessions`, and `DELETE /users/{id}` for soft delete — the missing
counterpart to the `RestoreUser` that already existed.

**Beyond the issue:** lock also revokes sessions, because locking without revoking is theatre
— which only works because #10 made refresh re-check lockout. `AssignRole`/`RemoveRole` revoke
too, so a role change takes effect on the next request instead of up to an access-token
lifetime later.

Two guards not in the issue: an admin cannot lock or delete their own account, since both are
self-inflicted lockouts of the person best placed to undo them.

`GetLockoutEnabledAsync` is checked first — `SetLockoutEndDateAsync` is silently inert when
lockout is disabled for a user, which would have made the endpoint appear to work while doing
nothing.

### #21 — Structured audit log

**Implemented.** An `AuditEvent` entity modelled on `UserConsent`, an `IAuditService`, an
`AuditAction` constant set, and `GET /api/v1/admin/audit-events` with filters for action,
actor, target, organization, and time range.

**Design points:**

- **No foreign key to `AspNetUsers`.** An audit row must outlive the account it describes,
  which is also why `ActorEmail` is captured alongside the id rather than joined at read time.
- **`Enqueue` alongside `LogAsync`.** `Enqueue` attaches the row to the caller's unit of work
  so the audited change and its record commit together — a role change that succeeds while its
  audit row is lost is precisely the failure an audit log exists to prevent. `LogAsync` writes
  immediately where no such transaction exists.
- **Audit failure never fails the operation.** It logs at error level instead.
- Actions are string constants, not an enum, so adding one never renumbers stored history.

`AssignRole` and `RemoveRole` — the two most consequential operations in the service, which
previously logged nothing at all — are covered.

### #22 — Two-factor authentication (TOTP)

**Implemented.** `enable` / `verify` / `disable` / `recovery-codes` / `login`, all on
Identity's existing primitives.

**The security-critical detail the issue flags** — "the challenge token must not be a normal
access token" — is handled by issuing it for the audience `<audience>:2fa`. The bearer
pipeline validates against `<audience>`, so a challenge token is structurally incapable of
authenticating an API call. A test asserts this.

**Beyond the issue:**

- Enrolment is two-step: `enable` hands out a secret but does not switch 2FA on; only `verify`
  does. An abandoned setup therefore cannot lock anyone out.
- A failed second factor calls `AccessFailedAsync`, so the second factor cannot be
  brute-forced from a challenge token the way it could if only the first factor counted
  against lockout.
- `disable` requires password *and* code, and accepts a recovery code in place of the code so
  a lost device is recoverable. It also revokes all sessions, since removing a factor changes
  what every live session is worth.

### #23 — GDPR data export

**Implemented.** `GET /api/v1/auth/export` returning profile, external logins, full consent
history, memberships, invitations sent and received, and session metadata — with
`Content-Disposition: attachment` so "download my data" is one link in a frontend.

**Excluded deliberately:** password hashes, refresh token values (stored as hashes and useless
anyway — exporting them would be handing out live credentials), OAuth provider keys (the issue
agrees), and email confirmation tokens. A test asserts the response contains neither the
caller's refresh token nor anything named like a password hash.

**Not implemented:** an admin-initiated export for another user. It is a different
authorization question — one admin exfiltrating a user's data is a real risk — and deserves its
own decision.

---

## Release readiness

### #24 — Community health files

**Implemented.** `SECURITY.md` (private reporting via GitHub advisories, response targets
stated as honest targets rather than an SLA, scope, and an explicit "no external audit" plus
the symmetric-key posture), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and a
PR template.

The `SECURITY.md` out-of-scope section names the documented escape hatches
(`AllowTokensInOAuthRedirect`, `RequireVerifiedProviderEmail=false`, `TrustAllProxies=true`) so
that "I turned off the safety and found it unsafe" is not a report anyone has to triage.

### #25 — CI hardening

**Implemented.** `dependabot.yml` (nuget, github-actions, docker; framework packages grouped
so ten related bumps arrive as one PR), a CodeQL workflow with `security-and-quality` on
push/PR plus weekly, a `dotnet format --verify-no-changes` job with `.editorconfig`, a Docker
build job, and test-result artifacts.

The Docker job also smoke-tests the image by asserting the startup guard from #13 fires and
names the missing setting — the production Dockerfile had literally never been built by CI,
since the only workflow that touched it runs on `v*` tags and no tag has ever existed.

Dependabot **alerts** and **security updates** are repository settings, not file-based, and
still need enabling in Settings → Security.

### #26 — First release and container image

**Already partly done on `main`** — commits `78f4068` and `be4a042` add GHCR publishing,
which post-dates the issue. Nothing further implemented here.

**Remaining, and deliberately not done in this change set:** cutting `v0.1.0`. Tagging is a
maintainer decision, and it should not happen on the same commit as a large behavioural change
set — the tag should come after this is reviewed and merged. The issue's point that the Fly
deploy path has never actually executed still stands and is worth one `workflow_dispatch` run
against a throwaway org before anyone relies on it.

### #27 — API versioning

**Implemented, differently from the issue's suggestion.** Every controller carries both
`[Route("api/v1/[controller]")]` and `[Route("api/[controller]")]`, so `/api/v1/...` is
canonical and the unversioned path keeps working as an alias. Swagger documents only v1.

**Deviation:** the issue proposes `Asp.Versioning.Mvc` with
`[Route("api/v{version:apiVersion}/[controller]")]`. Rejected for now — it adds a dependency
to solve a problem this repository does not yet have (there is exactly one version), and the
two-attribute approach delivers the same URLs and the same deprecation window with no new
package. When v2 exists and per-version Swagger documents actually matter, adopting the
package is a contained change.

The issue's other question — URL segment versus header — is settled as **URL segment**, for
the reason it gives: the documentation is full of `curl` examples.

One deliberate exception: the OAuth callback URL registered with Google and GitHub stays
`/api/external-auth/callback`, because changing it would require re-registering the redirect
URI with both providers.

---

## Decisions

These four are the maintainer's to make. Recommendations are recorded as ADRs.

### #28 — Reference implementation, deployable service, or library?

[ADR 0001](decisions/0001-what-this-repository-is.md) — **deployable service, arrived at
incrementally**. This change set takes the cheap, reversible parts (configurable schema mode,
versioned routes, documented upgrade path) and declines the parts that create obligations
nobody has asked for (support branch, deprecation policy, stability promise).

### #29 — HS256 versus RS256 + JWKS

[ADR 0002](decisions/0002-token-signing-algorithm.md) — **stay on HS256 for now; move to
RS256 before the second independent consumer exists**, since that is the moment "can verify"
and "can forge" stop being the same trust level in practice.

**Not implemented, and the reason is not effort.** RS256 needs somewhere durable to keep a
private key — a mounted secret, a table, or a KMS — and choosing that is an infrastructure
decision. A config flag that generates an ephemeral key at startup would be worse than
nothing, because every restart would silently invalidate every token. What this change set
does do: validate the key length at startup, partition the signing key's authority by audience
for 2FA challenges, and state the posture plainly in `SECURITY.md`.

### #30 — Scope

[ADR 0003](decisions/0003-scope.md) — **stay deliberately small**. Add what is table stakes
for an auth service (done here: email verification, 2FA, audit log, data export, admin
lockout); decline OIDC provider, SAML, LDAP, SCIM and an admin UI.

### #31 — Sign-off on behaviour-breaking security fixes

The maintainer directed that all of these be implemented in this change set, ahead of the
sign-off this issue was created to gate. They are listed with their exact breakage in the pull
request description, and each has a configuration switch to restore the previous behaviour
where restoring it is coherent:

| Change | Restore with |
| --- | --- |
| OAuth linking requires a verified provider email | `Auth:RequireVerifiedProviderEmail=false` |
| `change-password` revokes sessions | `Auth:RevokeSessionsOnPasswordChange=false` |
| Refresh enforces lockout and soft-delete | *(no switch — this is the fix)* |
| Swagger off outside Development | `Swagger:Enabled=true` |
| OAuth tokens no longer in the redirect URL | `Auth:AllowTokensInOAuthRedirect=true` |
| Email verification enforced when email is configured | `Auth:RequireConfirmedEmail=false` |
| `X-Forwarded-For` no longer trusted from anywhere | `Network:TrustAllProxies=true` |
| Login returns a 2FA challenge | *(only for accounts that opted into 2FA)* |

Refresh-token re-validation has no switch on purpose: an option to keep serving locked-out
accounts is not a configuration, it is the bug.
