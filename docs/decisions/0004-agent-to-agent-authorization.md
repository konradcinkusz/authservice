# ADR 0004 — Agent-to-agent authorization

**Status:** Proposed
**Date:** 2026-08-25
**See also:** [ADR 0005](0005-mcp-authorization-server.md), which amended ADR 0003 for MCP
connector clients — the third-party, browser-facing case this ADR leaves excluded — and brought
back OpenIddict to serve it. Nothing here was accepted or rejected by it; agent issuance
remains as proposed below.

## Context

The question raised: should this service grow an "agent-authservice" capability — identity
and authorization for autonomous, non-human callers acting on a user's behalf and calling
each other?

### What the estate does today, and why it does not survive agents

The architecture standard's answer to service-to-service authorization is one line in
`SERVICE-API-PATTERNS.md` §5: **forward the inbound bearer token**, and let the callee
enforce authorization. For a handful of first-party services carrying a human's request
through one or two hops, that is honest rather than naive.

Hand the same token to an autonomous agent and four properties turn from tolerable into
load-bearing:

1. **Authority is total.** The forwarded token carries every role and every
   `organization:{id}:role` claim the user has (`TokenService.BuildClaimsAsync`). An agent
   asked to do one thing receives the user's entire authority across every service.
2. **The window is an hour.** `Jwt:ExpirationMinutes` defaults to 60. That is a reasonable
   figure for a human at a keyboard and a long time for a credential sitting in an
   autonomous process.
3. **The audit log cannot tell the difference.** `AuditEvent.ActorUserId` records the user.
   Nothing distinguishes "the user did this" from "an agent did this, unattended, at 3 a.m."
   There is no field for a non-human actor and none for a delegation chain.
4. **Revocation is all-or-nothing.** `RevokeRefreshTokensAsync(userId)` is the only lever.
   Killing one misbehaving agent means signing the human out everywhere.

There is a fifth, and it is the sharpest: **every token is minted for a single audience**.
`Program.cs` validates one `ValidAudience`, and the README instructs every consumer to
validate that same value. A token accepted by service A is therefore accepted by service B.
Between trusted first-party services that is a latent weakness. In an agent mesh it is the
whole problem: the agent you hand a token to can replay it against every other service in
the estate, as you.

**This deviation is worth fixing whether or not agents ever ship.** It is listed in
`docs/architecture/DEVIATIONS.md` as of this ADR.

### The collision with ADR 0003

ADR 0003 excludes "a standards-shaped token endpoint, consent screens, client registration,
introspection". A complete agent-to-agent authorization system in its standards-compliant
form needs a token endpoint (RFC 6749 §4.4 client credentials), token exchange for
delegation (RFC 8693), client registration, and introspection (RFC 7662) for revocation.
That is four of the excluded items, and re-adding OpenIddict to get them would undo the
extraction decision.

The collision is real and cannot be resolved by not mentioning it. It can be resolved by
separating **minting a token for a principal** — which `TokenService` already does, twice,
for access tokens and two-factor challenge tokens — from **being an authorization server**,
which is what ADR 0003 actually refuses: browser-facing flows, an authorization endpoint,
consent UI, and third-party client onboarding.

## Options

**A. Do nothing; agents keep using the user's forwarded token.** Zero cost today, and the
four properties above become incidents later. The audit gap in particular is not recoverable
after the fact: history recorded under the user's name cannot be re-attributed.

**B. A separate `agent-authservice` deployment.** A second trust root, a second signing key
and rotation procedure, a second database, a second admin surface, a second CI lane and
`fly.toml` — and the agent-to-organization relationship spanning both, with no shared
`DbContext` permitted (blueprint non-goals). Principle P3 is *service per bounded context*,
and agent identity is not a different bounded context from identity. This buys isolation
that is not needed and pays the estate's full per-service cost for one table and a
controller.

**C. A narrow agent-identity capability inside this service**, behind an off-by-default
flag: agents as a first-class principal type distinct from `ApplicationUser`, short-lived
audience-restricted tokens, an explicit delegation chain, and no authorization-server
surface at all.

**D. Adopt a full standards-compliant agent authorization stack** — token exchange, DPoP or
mTLS sender-constrained tokens, dynamic client registration, introspection, a policy engine.
Correct in the abstract, and roughly the size of the existing service. The agent
authorization standards are also still moving; pinning an immature one into a small,
readable service is an ongoing maintenance obligation, not a one-off.

## Decision

**C — and only C.**

Agent identity belongs in this service, as one bounded capability, gated behind
`Agents:Enabled` (default off) so a deployment that does not want it carries no new
surface and no new tables.

### What is in scope

- **`AgentIdentity` as its own entity**, owned by an `Organization`, with a hashed
  credential (`TokenHasher`, as refresh tokens and exchange codes already do), an enable
  flag, and its own admin surface. **Not** an `ApplicationUser`. See *Consequences* below
  for why the shortcut is refused.
- **A distinct principal namespace and claim.** `sub` as `agent:{id}` plus an explicit
  `principal_type` claim, so no downstream authorization check can confuse an agent for the
  human it acts for.
- **Direct issuance** — a client-credentials-shaped `POST /api/v1/agents/token` returning a
  token with a TTL in minutes, restricted to a named audience, and **no refresh token**. An
  agent re-authenticates; it does not hold a rotating long-lived credential.
- **Delegated issuance** — a token that says "agent A, acting for user U", carrying an
  actor chain in the shape of RFC 8693's `act` claim. Authority **narrows** at every hop and
  never widens: a delegated token's scope must be a strict subset of the delegator's.
- **A scope model**, because there is not one today. Authorization here is `ClaimTypes.Role`
  plus `organization:{id}:role`, with no `scope` claim anywhere in the codebase and no
  authorization policies beyond `[Authorize(Roles = ...)]`. Subset-checkable scopes are the
  substantial design work in this ADR, and delegation is meaningless without them.
- **Audit that records the chain** — `ActorAgentId` and `OnBehalfOfUserId` on `AuditEvent`,
  and `agent.*` action constants. `AuditAction` is deliberately constants rather than an
  enum precisely so this kind of addition never renumbers stored history.
- **RS256 required.** Startup fails when `Agents:Enabled` and the algorithm is HS256. Under
  a symmetric key every validator can also mint; in an agent mesh that means one compromised
  agent forges tokens for any user with any role. ADR 0002 made this argument for a second
  service. Agents make it non-negotiable rather than recommended.
- **Per-audience tokens**, for agents and — separately and independently — as the fix for
  the deviation named above.

### What is excluded, so it does not have to be re-litigated

- Introspection and a revocation endpoint. The design premise is that downstream services
  validate offline and never call back (`README.md`, "API overview"); introspection inverts
  it. **Containment replaces revocation**: minutes-long TTLs, no agent refresh tokens, and a
  kill switch that disables the credential — worst case an in-flight token outlives the kill
  by one TTL.
- DPoP (RFC 9449) and mTLS-bound tokens (RFC 8705). Audience restriction plus short TTL
  covers the replay path that matters here. Revisit if agents ever cross a trust boundary
  the operator does not control.
- Dynamic client registration, consent screens, an authorization endpoint, browser-facing
  flows. This is ADR 0003's exclusion and it stands unchanged.
- Agent discovery, capability negotiation, and any policy engine.

### ADR 0003 is amended, not overridden

ADR 0003's exclusion list stands, with one clause narrowed: **"a standards-shaped token
endpoint" and "client registration" are excluded for third-party, browser-facing clients,
not for a first-party workload an operator registered through the admin API.** The
distinction is the same one ADR 0003 already drew for `/.well-known/openid-configuration` —
key discovery is in scope, being an authorization server is not. Minting a token for a
registered principal is what this service does; the flows around it are what it refuses.

## Consequences

### Modelling agents as users is refused, explicitly

The cheap version of this feature is to register each agent as an `ApplicationUser` and
change nothing else. It is rejected. `ApplicationUser` drags in password policy, lockout,
email confirmation, TOTP two-factor, versioned consent, and soft-delete retention — every
one meaningless or actively harmful for a non-human principal — and it silently pollutes
`/api/v1/admin/users`, `admin/stats`, and the GDPR export at `/api/v1/auth/export`, which
would then export machine credentials as a person's data. A separate entity is more code
and the only defensible shape.

### The existing code takes this well, in specific ways

- `JwtSigningKeys` already does RS256, JWKS, `kid` derivation and rolling rotation. That is
  the hardest part of being an issuer, and agent tokens ride it unchanged.
- The `:2fa` audience suffix in `TokenService` is the exact precedent for keeping a new
  token class out of the user bearer pipeline: give agent tokens their own audience and
  `Program.cs`'s single `ValidAudience` rejects them from the user surface by construction.
- `OAuthExchangeCode` — hashed, single-use, 60-second — is the shape a delegation grant
  wants.
- Refresh-token families with replay detection are the same "one leak kills the lineage"
  discipline a delegation chain needs.
- P10 holds throughout (`ITokenService`, `IAuditService`, `IProviderEmailVerifier`,
  `IOAuthExchangeCodeService`): an `IAgentTokenService` plus one DI line is idiomatic here,
  and `ITokenService` does not change.

### And resists in four, which are the real cost

1. **Every token path is `ApplicationUser`-shaped.** `ITokenService.GenerateTokensAsync`
   takes one, `BuildClaimsAsync` calls `UserManager.GetRolesAsync`, and `RefreshToken.UserId`
   is a required FK with cascade delete. Agent issuance is a parallel path, not a parameter.
2. **There is no scope model to extend** — it has to be designed.
3. **Per-audience tokens are a documented breaking change for consumers**, not just a change
   here: every downstream `ValidAudience` and the README's consumer snippet move together.
4. **Schema cost is real and currently elevated.** Migrations are not committed,
   `Database:SchemaMode` defaults to `EnsureCreated` — which "does nothing at all" against an
   existing database — so new tables need hand-written idempotent upgrade DDL for both
   providers in `docs/schema/upgrade/`. Issue #17 is the open deviation here.

Rate limiting also partitions on `User.Identity?.Name` or client IP. An agent fleet behind
one address shares one bucket and makes far more requests than a human; agents need their
own partition and policy.

### Sequencing

**Land issue #17 (committed migrations) first.** Adding two tables while the only schema
path is `EnsureCreated` widens the estate's most acute open deviation rather than paying it
down. Then, in order, each step useful on its own:

1. `AgentIdentity`, credential, admin surface, `agent.*` audit actions — agents exist, are
   listable, and can be killed.
2. Direct issuance: short-TTL, audience-restricted, `principal_type=agent`, no refresh token.
3. Scopes, then delegated issuance with the `act` chain and subset-only narrowing.

Stop after 3.

### Size, against the thing that makes this project worth using

The narrow slice is roughly 1,200–1,800 lines with tests, against ~7,400 in `src` — call it
a fifth of the service. ADR 0003's differentiator is "~5,000 lines you can understand in an
afternoon", and that is precisely the argument for option C over option D, and for stopping
after step 3. A full standards-compliant stack would roughly double the service and lose the
only competition this project can win.

### The architecture standard has a gap this opens

`architecture-standards` has no guidance on non-human identity: the whole treatment of
service-to-service authorization is "forward the inbound bearer" in `SERVICE-API-PATTERNS.md`
§5, and `IDENTITY-AND-ACCOUNTS.md` assumes a human account throughout. If this ADR is
accepted, that standard needs a section on agent identity and delegation, or the estate's
constitution and its reference implementation will disagree — which is the one thing
`DEVIATIONS.md` exists to prevent.
