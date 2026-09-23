# AUTH-MCP-01: ticket analysis

> **Revision 4**, 2026-09-23. Lands the implementation phase's findings (§5.4), made reading the library and the code before any production change. None changes scope, so the gate stands without a re-decision. Revision 3 recorded Konrad's re-decision of the gate; revision 2 landed his answers to B1–B3 (§5.1); revision 1 was the first pass of `/ticket-analysis`.
> **Gate: decided, go.** All four conditions are met (§7), and Konrad re-decided the gate after revision 2's scope change: "Go: prompt + implement (Recommended)", 2026-09-23.
> **Ticket:** the AUTH-MCP-01 brief, "authservice as an OAuth 2.1 authorization server for MCP connectors", as pasted into the session on 2026-09-23. Appendix A holds its acceptance criteria verbatim. If the tracker id changes, this file keeps its name until it is renamed.
> **Downstream:** `AP-MCP-01` (AureliusPromptus MCP connector) is blocked on this ticket.
> **Precedence:** once accepted, this document wins over the brief (brief §10). A disagreement goes back through `/ticket-feedback` and is not settled mid-implementation.

---

## 0. Sources read

Before anything else, confirmed that each source could be opened in this session (TICKET-ANALYSIS §0).

| Source | Version read | Cited as / used for |
|---|---|---|
| `docs/architecture/00-REFERENCE-ARCHITECTURE.md`: P1–P15 and the §3 checklist | `konradcinkusz/architecture-standards@e794863` | every principle and compliance item |
| `docs/guides/IDENTITY-AND-ACCOUNTS.md` | same | §1 claims, §2 refresh, §3 OAuth, §5 enumeration, §6 lockout, §8 deletion, §9 consent, §10 key material, §12 checklist |
| `docs/guides/SERVICE-API-PATTERNS.md` (`services-and-clients:service-api-patterns`) | same | §1 rate limiting, §2 trust levels, §7 background services, §8 seeded definitions |
| `docs/guides/SECURITY-REVIEW.md` (`quality-and-process:security-review`) | same | §4 browser rule set, §5 random values, §8 authorization structure |
| `docs/guides/TESTING-STRATEGY.md` (`quality-and-process:testing-strategy`) | same | §4 tiers, §5 conventions, §6 per-test bar, §9 test entry points |
| `SHARED-SERVICE-REUSE.md`, `FRONTEND-BFF.md`, `REPO-BASELINE.md` §8 | same | per-instance trust roots; the BFF option in B3; staleness and one source of truth per variable |
| MCP Authorization specification, revision **2026-07-28**, marked "(latest)" and default in the site's `docs/docs.json` | `modelcontextprotocol/modelcontextprotocol@c7400a0`, `docs/specification/2026-07-28/` | `MCP-AUTHZ` (`basic/authorization/index.mdx`), `MCP-DISC` (`authorization-server-discovery.mdx`), `MCP-REG` (`client-registration.mdx`), `MCP-SEC` (`security-considerations.mdx`), `MCP-CHANGES` (`changelog.mdx`) |
| Anthropic, "Authentication for connectors" | <https://claude.com/docs/connectors/building/authentication>, fetched 2026-09-23 | `CLAUDE-AUTH` |
| Anthropic, "Troubleshooting connectors" | <https://claude.com/docs/connectors/building/troubleshooting>, fetched 2026-09-23 | `CLAUDE-TS` |
| Anthropic Help Center, "Get started with custom connectors using remote MCP" | support.claude.com article 11175166, dated 2026-08-11 | `CLAUDE-HELP` |
| OpenIddict source, tag **7.7.1** (latest stable; 8.0 is in preview) | `openiddict/openiddict-core@7.7.1` | `OI`: checks the library defaults the brief's §7 warns about |

**Routes that failed, and how each was handled.** Every document the brief names was read; only these access routes failed:

- This environment's egress policy denies `modelcontextprotocol.io` for both shell and web fetch. The specification was therefore read from the repository the site is generated from.
- `rfc-editor.org` and `datatracker.ietf.org` are also denied. Where this document makes an RFC-level statement, it cites the MCP specification or Anthropic's pages, which restate the RFC. Nothing is cited from memory of an RFC.
- The older Anthropic article "Building custom connectors via remote MCP servers" returns 404 on support.claude.com, and its support.anthropic.com URL is denied. `CLAUDE-AUTH` supersedes it. The one detail that only the old article carried is marked where it is used (N8).

---

## 1. The ticket, read against the architecture

**The change in one sentence.** authservice adds an OAuth 2.1 authorization-code-with-PKCE surface for pre-registered MCP clients, Claude first, and enables it through configuration. The surface issues audience-bound JWT access tokens and rotating refresh tokens, signed with the existing RS256 key and published through the existing JWKS. Every existing token, endpoint and discovery document stays byte-for-byte the same.

**Owning bounded context (P3): identity, meaning authservice.** Confidence is high. Everything the ticket asks for is token issuance, sign-in and consent for users this service already owns. The MCP server that consumes the tokens belongs to another context and another ticket (`AP-MCP-01`, brief §6). Each consuming system runs its own instance with its own key (SHARED-SERVICE-REUSE.md §1). The authorization server is therefore per instance, and nothing here makes authservice a central shared server.

**Is this one ticket?** Yes, by P3's test: one context, one service, one database. Revision 1 named two things that could split it; both are now settled:
- ~~**B1:** there is no migration set for the schema change to join.~~ The baseline landed on its own in PR #65 (issue #17). This ticket adds one incremental migration per provider on top of it.
- ~~**B3:** if sign-in and consent render in a consumer's frontend, a second repository is involved.~~ authservice provides both modes (A11). A consumer that picks External builds its own pages, in its own repository, as its own work. Nothing in this ticket touches another repository.

**Principle-level flags** (TICKET-ANALYSIS §1)

| # | What the ticket needs | Principle | Evidence | Status |
|---|---|---|---|---|
| 1 | New tables for clients, authorizations and tokens, "added via migrations" (brief §7), with no migration set to add them to | P4 | Neither `src/AuthService.Migrations.PostgreSQL` nor `src/AuthService.Migrations.SqlServer` contains a migration or a model snapshot. `docs/architecture/DEVIATIONS.md` L18: "No committed migration set … To fix". `docs/schema/README.md` L113–118 still prescribes hand-written upgrade DDL | ~~Open → B1~~ **Kept.** PR #65 committed the migration sets, and this ticket adds an incremental migration (revision 2) |
| 2 | An authorization endpoint, a token endpoint, a consent screen, client registration, and OpenIddict | P14 (decisions are recorded, and are reversed only by another recorded decision) | ADR 0003 L36–38 excludes exactly these and says "re-adding OpenIddict would undo the extraction decision". ADR 0004 L132 and L137–138 restate the exclusion for "third-party, browser-facing clients" | ~~Open → B2~~ **Decided:** amend ADR 0003 through ADR 0005 (Konrad, 2026-09-23) |
| 3 | New secret material: client secrets, plus a token-encryption key the library requires | P5 | `OI` will not start without an encryption credential (`OpenIddictServerConfiguration.cs` L250, `ID0085`) | Decided → A4 |
| 4 | Resource servers must be able to verify tokens without being able to mint them | P5 ("Exactly one service holds a signing key") | Under HS256 the JWKS is empty by construction (`JwtSigningKeys.cs` L54–78). `OI` will not start without an asymmetric signing key (`OpenIddictServerConfiguration.cs` L255, `ID0086`) | Decided → A3 |
| 5 | A new public contract (authorization-server metadata and the MCP token shape) for `AP-MCP-01` to build against, while the existing contract stays fixed | P11, AC7 | The existing discovery document is `Program.cs` L472–496, and `JwksEndpointTests.cs` L46 and L59 pin its content | Decided → A1, A2, A9 |
| 6 | An optional capability that must not change a deployment that doesn't use it | P8 | The same pattern already covers Google and GitHub (`Program.cs` L202–236) and SendGrid (L300–307) | Decided → A5 |
| 7 | "Authorize and token events are traced" (brief §7), with no tracing pipeline in place | P15 | `DEVIATIONS.md` L16: "No OTLP traces … To fix" | Assumption → N5 |
| 8 | More wiring in a `Program.cs` that is already a recorded deviation | P9 | `DEVIATIONS.md` L20; `Program.cs` is 530 lines | Kept → A6 |
| 9 | The identity service rendering HTML for the first time, in Hosted mode | P14 (a recorded stance) | `docs/issue-analysis.md` L235: "requires the service to render HTML, which it otherwise never does". `src/` has no Razor, no views and no `wwwroot` | ~~Open → B3~~ **Decided:** Hosted pages ship, and they are the default mode (Konrad, 2026-09-23; A11). ADR 0005 records that the "renders no HTML" stance changes |

### 1a. Where the brief and the sources disagree

Brief §1 says the specification wins and any difference is a finding. F1–F4 change what gets built. F5–F12 are facts the brief could not have known without reading the sources or the code.

| # | The brief says | The sources say | Consequence |
|---|---|---|---|
| F1 | §6: "The design must allow adding DCR later" | `MCP-CHANGES` "Deprecated" item 4, and the warning in `MCP-REG` "Dynamic Client Registration": DCR is deprecated in favour of Client ID Metadata Documents (CIMD) and kept only for backwards compatibility | Read §6 as "allow adding a second registration mechanism later, CIMD first". The library's client table serves either mechanism, so no schema rewrite is needed (Q3) |
| F2 | AC1 and AC2 don't mention the `iss` authorization-response parameter | `MCP-AUTHZ` "Authorization Response Validation": authorization servers SHOULD include `iss` (RFC 9207), and an AS that does MUST advertise `authorization_response_iss_parameter_supported`. The spec adds that "a future revision … is expected to upgrade … from SHOULD to MUST" | Add both to AC1 and AC2. `OI` already emits `iss` and advertises the flag by default (`OpenIddictServerHandlers.Discovery.cs` L859); keep that default |
| F3 | AC4: tokens "validate against the existing JWKS", with nothing about `iss` | `MCP-DISC` "Authorization Server Metadata Discovery": the metadata's `issuer` MUST be identical to the issuer identifier the well-known URL was built from, or the client MUST NOT use the metadata. `CLAUDE-TS` "Issuer mismatch": the metadata's `issuer` must match the issuer that signs the tokens | The MCP issuer has to be an https URL. Existing tokens carry the bare string `AuthService` (`TokenService.cs` L252 reads `Jwt:Issuer`; ADR 0002 L95–98; `DEVIATIONS.md` L21), and AC7 forbids changing them. So MCP tokens get a URL issuer and existing tokens keep theirs: two issuers, one key, one JWKS (A1) |
| F4 | AC1: "RFC 8414, and OIDC discovery if already served" | OIDC discovery *is* already served, but only for key discovery (`Program.cs` L472–496: bare `issuer`, empty `response_types_supported`), and two existing tests pin exactly that (`JwksEndpointTests.cs` L46, L59). `MCP-AUTHZ` Overview item 5 requires only one of the two mechanisms. `CLAUDE-TS`: Claude "tries `/.well-known/oauth-authorization-server` (RFC 8414) first, then falls back" | Putting AS endpoints or a URL issuer into the OIDC document would break AC7 and give existing consumers an issuer their tokens don't carry. Serve RFC 8414 only and leave the OIDC document byte-identical (A2) |
| F5 | AC3: "an access token and a refresh token" | `OI` issues a refresh token only when `offline_access` has been granted (`OpenIddictServerHandlers.cs` L3460). `CLAUDE-AUTH` "DCR and CIMD details": Claude appends `offline_access` only when the AS metadata lists it in `scopes_supported` | `offline_access` has to appear in `scopes_supported` and in every client's allowed scopes. Otherwise AC3 never issues a refresh token |
| F6 | §7: "Authorize and token events are traced" | authservice emits no traces (`DEVIATIONS.md` L16) | See N5 |
| F7 | AC2: "authservice's existing sign-in" | authservice has no sign-in *page*. Sign-in is a JSON API (`AuthController.cs` L200–278); the pages live in consumer frontends | See B3, answered in revision 2: both modes (A11) |
| F8 | §7 "Key material": use the existing key and its rotation | The library signs and encrypts the codes and refresh tokens it issues. `JwtSigningKeys` keeps a retired key as public-only (`JwtSigningKeys.cs` L120–143) | If the library validates its own stored tokens against the current key only, one rolling rotation (IDENTITY-AND-ACCOUNTS.md §10) kills every outstanding MCP refresh token, and every Claude connection must be re-authorised. This was not verified here, so AC4 carries a rotation test |
| F9 | — | `CLAUDE-AUTH` "Endpoint latency": Claude waits at most 10 s for the discovery, registration and token endpoints, and 30 s for a refresh | An instance scaled to zero whose cold start is slower than that fails connections (P7). The runbook must say so (AC9) |
| F10 | §7: "Rate limiting on the authorization and token endpoints" | `CLAUDE-AUTH` "Network reference": Anthropic's traffic comes from `160.79.104.0/21` | Every Claude user's token and refresh calls arrive from a handful of addresses. The per-IP `auth` policy and the global limiter (`Program.cs` L328–337, L354–364) would lump them into shared buckets: the corporate-NAT failure in SERVICE-API-PATTERNS.md §1. See N4 |
| F11 | AC5: take Claude's redirect URIs from Anthropic's docs | `CLAUDE-AUTH` "Callback URLs": `https://claude.ai/api/mcp/auth_callback` serves Claude.ai web, Desktop, mobile and Cowork. `CLAUDE-HELP` "Network requirements": every client brokers connectors through Anthropic's cloud. Claude Code uses loopback redirects and its own CIMD | One redirect URI covers the brief's "web, desktop and mobile". v1's pre-registered model can't reach Claude Code (out of scope) |
| F12 | D3: "Claude's connector settings accept a client id and secret" | `CLAUDE-HELP`: "Optionally, click 'Advanced settings' to specify an OAuth Client ID and OAuth Client Secret". `CLAUDE-AUTH` "Custom connectors": pre-registered static credentials avoid DCR entirely. `CLAUDE-AUTH` "Credentials entered at connection time": if the secret is left blank, Claude acts as a public client | D3 is confirmed. v1 accepts confidential clients only (AC5), so the runbook must say the secret is required |

---

## 2. Analysis table

One row per acceptance criterion. Criteria are abbreviated here; Appendix A has the verbatim text. Revision 2: B1–B3 are answered, so every row's files are final and no row carries a blocking question. AC2 now covers both interaction modes (A11).

| AC | Acceptance criterion | Owning context and layer | Governed by | Guide to load | Files | Blocking question |
|---|---|---|---|---|---|---|
| AC1 | Discovery: RFC 8414 metadata listing the authorization and token endpoints, `code`, `S256`, scopes, and a `jwks_uri` for the existing key set | identity (authservice) · HTTP surface: an anonymous well-known endpoint generated from the AS configuration | P5, P8, P11 | IDENTITY-AND-ACCOUNTS.md §3 rule 2, §10; SERVICE-API-PATTERNS.md §2; SECURITY-REVIEW.md §8; `MCP-DISC`; `MCP-SEC` "Authorization Code Protection"; `MCP-AUTHZ` "Authorization Response Validation"; `CLAUDE-TS` | `src/AuthService/Extensions/AuthorizationServerExtensions.cs` (new); `src/AuthService/Services/AuthorizationServerOptions.cs` (new); `src/AuthService/Program.cs` (registration and map calls, plus a startup-banner field; the existing `/.well-known/openid-configuration` and `/.well-known/jwks.json` handlers are unchanged); `src/AuthService/appsettings.json` (empty section, no secrets); `tests/AuthService.AuthorizationServer.Tests/DiscoveryTests.cs` (new) | none (confirm A1, A2) |
| AC2 | Authorization endpoint: `code` with PKCE (`S256` only); exact `client_id` and `redirect_uri`; `state`; `resource`; sign-in including external providers, then resume; consent showing the client's display name and scopes | identity · HTTP surface (anonymous authorization endpoint), plus interaction in one of two modes (A11): **Hosted**, pages rendered by authservice (a new layer for this service), or **External**, an interaction API a consumer's frontend calls through its BFF; plus service domain (a password-sign-in decision shared with the API) | P5, P9, P10, P13, P14 | IDENTITY-AND-ACCOUNTS.md §3 rules 2–3, §4, §5, §6, §9; SECURITY-REVIEW.md §4, §5, §8; SERVICE-API-PATTERNS.md §1, §2; FRONTEND-BFF.md §1, §3 (the External mode's contract with a consumer's BFF); `MCP-AUTHZ` "Authorization Flow Steps" and "Resource Parameter Implementation"; `MCP-SEC` "Open Redirection" and "Mix-Up Attacks" | *Both modes:* `src/AuthService/Controllers/AuthorizationController.cs` (new; passthrough for the authorization endpoint, dispatching on the mode); `src/AuthService/Extensions/AuthorizationServerExtensions.cs` (AS cookie scheme, Razor Pages, antiforgery, headers, PKCE settings, mode). *Hosted:* new pages `src/AuthService/Pages/Connect/SignIn.cshtml` + `.cs`, `TwoFactor.cshtml` + `.cs`, `Consent.cshtml` + `.cs`, `ExternalReturn.cshtml` + `.cs` (served at `/oauth/callback`), `src/AuthService/Pages/_ViewImports.cshtml`, `src/AuthService/Pages/Shared/_ConnectLayout.cshtml`. `src/AuthService/Services/SignInFlow.cs` (new; the decision extracted from `AuthController.Login`). `src/AuthService/Controllers/AuthController.cs` (`Login` delegates to it; behaviour unchanged). `tests/AuthService.Tests/SignInCharacterizationTests.cs` (new; written before the extraction). *External:* `src/AuthService/Controllers/AuthorizationInteractionController.cs` (new; `GET /api/v1/oauth/interactions/{id}`, `POST …/{id}/accept`, `POST …/{id}/deny`); `src/AuthService.Data/Models/AuthorizationInteraction.cs` (new entity, mapped in `ApplicationDbContext` and created by the AC3 migration). *Tests:* `tests/AuthService.AuthorizationServer.Tests/AuthorizationFlowTests.cs` and `…/ExternalInteractionTests.cs` (new) | none |
| AC3 | Token endpoint: a single-use, short-lived, PKCE-verified code becomes an access token plus a refresh token; the `refresh_token` grant rotates single-use | identity · HTTP surface (client-authenticated token endpoint), plus service domain (refresh re-checks the user and rebuilds claims), plus persistence (codes, authorizations and tokens in authservice's own database) | P3, P4, P5, P13 | IDENTITY-AND-ACCOUNTS.md §1, §2; SERVICE-API-PATTERNS.md §1, §7; `MCP-SEC` "Token Theft" and "Authorization Code Protection"; `CLAUDE-AUTH` "Token refresh" and "Endpoint latency" | `src/AuthService/Controllers/AuthorizationController.cs` (token passthrough); `src/AuthService/Extensions/AuthorizationServerExtensions.cs` (grants, lifetimes, reuse leeway, token-endpoint rate-limit policy); `src/AuthService.Data/Data/ApplicationDbContext.cs` (library entities mapped in `OnModelCreating`); `src/AuthService.Data/AuthService.Data.csproj` (`OpenIddict.EntityFrameworkCore` 7.7.x); `src/AuthService/AuthService.csproj` (`OpenIddict.AspNetCore` 7.7.x); `src/AuthService.Migrations.PostgreSQL/Migrations/<timestamp>_AddAuthorizationServer.cs` and `.Designer.cs` (new), `ApplicationDbContextModelSnapshot.cs` (changed), with the same three in `src/AuthService.Migrations.SqlServer/Migrations/`, all on top of the baseline from PR #65, and also creating the `AuthorizationInteraction` table (AC2, External); `src/AuthService/Services/UserCleanupService.cs` (hourly prune); `tests/AuthService.AuthorizationServer.Tests/AuthorizationFlowTests.cs` | none (~~B1~~ closed by PR #65) |
| AC4 | Access tokens: signed, not encrypted; the existing key and `kid`; validate through the existing JWKS; `aud` set to the resource; `sub` the same user id; a `scope` claim; claims enriched as they are today | identity · service domain (token issuance and claim building) | P5, P11, P13 | IDENTITY-AND-ACCOUNTS.md §1, §10; SECURITY-REVIEW.md §4; `MCP-AUTHZ` "Token Handling"; `MCP-SEC` "Token Audience Binding and Validation"; `CLAUDE-TS` "Audience mismatch" and "Issuer mismatch" | `src/AuthService/Services/ITokenService.cs` and `src/AuthService/Services/TokenService.cs` (expose the existing private `BuildClaimsAsync`, L217–245, for reuse; `GenerateTokensAsync` output unchanged); `src/AuthService/Controllers/AuthorizationController.cs` (the principal: `sub`, enriched claims, scopes, resource as `aud`); `src/AuthService/Extensions/AuthorizationServerExtensions.cs` (signing key taken from `JwtSigningKeys`, access-token encryption off, issuer, RS256 check); `tests/AuthService.AuthorizationServer.Tests/AccessTokenTests.cs` (new; includes the F8 rotation test) | none (confirm A1, A3, A9) |
| AC5 | Client registration v1: pre-registered confidential clients in configuration (id, display name, redirect URIs, scopes, resources); secrets from platform secrets only; Claude first, with its redirect URIs in configuration | identity · configuration (options and startup validation), plus persistence (sync into the library's client store) | P5, P8, P10 | SERVICE-API-PATTERNS.md §7, §8; IDENTITY-AND-ACCOUNTS.md §10; `MCP-REG` "Pre-registration"; `MCP-SEC` "Communication Security"; `CLAUDE-AUTH` "Callback URLs" and "Custom connectors"; `CLAUDE-HELP` "Add a custom connector" | `src/AuthService/Services/AuthorizationServerOptions.cs` (new); `src/AuthService/Services/AuthorizationClientSync.cs` (new hosted service); `src/AuthService/Extensions/AuthorizationServerExtensions.cs` (startup validation and registration); `src/AuthService/appsettings.json`; `tests/AuthService.AuthorizationServer.Tests/ClientRegistrationTests.cs` (new) | none (confirm A5, A8) |
| AC6 | Revocation: global revocation also revokes MCP refresh tokens and authorizations; a user can revoke one connected client | identity · service domain (the single global revocation operation), plus HTTP surface (an authenticated user endpoint), plus persistence | P9, P13 | IDENTITY-AND-ACCOUNTS.md §2, §8; SERVICE-API-PATTERNS.md §2; SECURITY-REVIEW.md §8 | `src/AuthService/Services/TokenService.cs` (`RevokeRefreshTokensAsync`, L95–113, also revokes the user's MCP authorizations and tokens; its 11 call sites stay as they are); `src/AuthService/Services/UserCleanupService.cs` (deletes MCP rows at permanent deletion); `src/AuthService/Controllers/ConnectedClientsController.cs` (new; `DELETE /api/v1/auth/connected-clients/{clientId}`); `src/AuthService.Data/Models/AuditEvent.cs` (new `AuditAction` constants); `docs/roles.md` (the revoke-sessions statement and the endpoint rows); `tests/AuthService.AuthorizationServer.Tests/RevocationTests.cs` (new) | none (~~B1~~ closed by PR #65) |
| AC7 | No regression: the existing suite passes untouched, plus a test of the pre-change token shape | identity · tests (characterisation of the existing contract) | P11, P13 | TESTING-STRATEGY.md §5, §6, §9 | `tests/AuthService.Tests/TokenContractCharacterizationTests.cs` (new; HS256; written first, against unchanged code); `tests/AuthService.AuthorizationServer.Tests/TokenContractRs256CharacterizationTests.cs` (new; the RS256 half; written first); no existing file under `tests/` is touched | none |
| AC8 | End-to-end: the full flow plus negative cases (wrong verifier, reused code, mismatched `redirect_uri`, wrong audience, unknown client, `plain`) | identity · integration tests (in-process host, HTTP level, SQLite) | P13 | TESTING-STRATEGY.md §4, §5, §6, §9; `MCP-SEC`; `CLAUDE-AUTH` "Token refresh" | `tests/AuthService.AuthorizationServer.Tests/AuthService.AuthorizationServer.Tests.csproj` (new project); `tests/AuthService.AuthorizationServer.Tests/Infrastructure/AuthorizationServerFactory.cs` and `…/Infrastructure/AuthorizationFlowClient.cs` (new); `tests/AuthService.AuthorizationServer.Tests/AuthorizationFlowTests.cs` (new); `tests/AuthService.AuthorizationServer.Tests/ExternalInteractionTests.cs` (new; the same flow in External mode); `AuthService.sln` (adds the project so CI's `dotnet test AuthService.sln` runs it) | none (~~B3~~ answered) |
| AC9 | Documentation: an ADR for the decisions in brief §8, and a runbook section "Registering an MCP client" with placeholder values | identity · docs | P14, P5 | 00-REFERENCE-ARCHITECTURE.md P14 and its stale-README corollary; REPO-BASELINE.md §8; IDENTITY-AND-ACCOUNTS.md §10 | `docs/decisions/0005-mcp-authorization-server.md` (new); `docs/decisions/0003-scope.md` and `docs/decisions/0004-agent-to-agent-authorization.md` (status and cross-reference lines only); `docs/DEPLOYMENT.md` (a new "Registering an MCP client" section between "Pointing a service at it" and "A note on shape", rows in "What the container needs", secrets in the `fly.toml` block); `README.md` (API overview, "What's intentionally not here", the configuration table, and a line distinguishing this "MCP" from the `integrate` server); `CONTRIBUTING.md` (scope boundary); `SECURITY.md` (scope and posture); `.github/ISSUE_TEMPLATE/feature_request.yml` (scope wording); `docs/architecture/DEVIATIONS.md` (the `iss` and single-audience rows); `docs/roles.md` (shared with AC6) | none (~~B2~~ answered) |

### Row notes: requirements derived for each row

These are part of the table and travel with it into the master prompt.

**AC1**
- `issuer` is the configured public URL (A1). Metadata is served only at `/.well-known/oauth-authorization-server` (A2).
- It advertises:
  - `authorization_endpoint` and `token_endpoint`;
  - `jwks_uri` set to the existing `/.well-known/jwks.json`;
  - `response_types_supported: ["code"]`;
  - `grant_types_supported: ["authorization_code", "refresh_token"]`;
  - `code_challenge_methods_supported: ["S256"]`, and nothing else (per `MCP-SEC`, clients refuse to proceed without it);
  - `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]` (N9);
  - `scopes_supported`, including `offline_access` (F5);
  - `authorization_response_iss_parameter_supported: true` (F2).
- It omits `registration_endpoint`, `introspection_endpoint`, `client_id_metadata_document_supported` and the `none` auth method (out of scope; D3, D4).
- It returns 404 when no client is configured (A5).
- Tests assert each of these fields, and assert that the OIDC document and the JWKS are unchanged (shared with AC7).

**AC2**

*Both modes*
- PKCE is required, and `plain` is removed from the library's code-challenge methods. By default the library enables `plain` and doesn't require PKCE (`OpenIddictServerOptions.cs` L494–498, L533).
- Exactly one `resource` is required, and it must be in the client's allowed list (N10).
- `redirect_uri` must match a configured value exactly. Errors found before `redirect_uri` is validated are shown on an authservice page and never redirected (`MCP-SEC` "Open Redirection"). That error page is the only page External mode renders. *(Revision 4.)* It is the library's own local error response, which it returns instead of redirecting for exactly these errors, so no page file is added for it.
- Every authorization response carries `iss` (F2).
- The mode comes from `AuthorizationServer:Interaction:Mode`: `Hosted`, the default, or `External` (A11).

*Hosted mode*
- The authorization session uses its own cookie scheme, **never `Identity.Application`**. The external callback signs into that scheme with `bypassTwoFactor: true` (`ExternalAuthController.cs` L114–118), so trusting it would skip the second factor.
- Password sign-in runs the same decision as `POST /api/v1/auth/login` (`AuthController.cs` L213–266; IDENTITY-AND-ACCOUNTS.md §5, §6):
  - a generic failure message;
  - lockout is disclosed only to a caller who gave the correct password;
  - an unconfirmed email is refused;
  - a 2FA-enabled account gets a challenge.
- Resuming after an external provider reuses the existing exchange-code handoff, with no change to `ExternalAuthController`:
  1. The sign-in page starts `/api/v1/external-auth/login` with `returnUrl=<issuer>/oauth/callback`. `IsAllowedReturnUrl` already accepts that path (`ExternalAuthController.cs` L349).
  2. The landing page redeems the code server-side through `IOAuthExchangeCodeService` and applies the second factor.
  3. It then resumes the authorization request.
  - The issuer's origin must be listed in `OAuth:PostLoginRedirectAllowedBaseUrls` (runbook).
  - *(Revision 4.)* The round trip is bound to the browser that started it: the sign-in page puts a CSPRNG nonce in the `returnUrl` it hands `ExternalAuthController` (which keeps any query on an allowed path) and the same nonce in an HttpOnly cookie, and the landing page refuses a code whose nonce does not match. Without it, a link carrying the attacker's own exchange code signs the victim's pending request in as the attacker: the login-CSRF scenario External mode's binding cookie answers (SECURITY-REVIEW.md §8).
- Consent shows the client's display name, the host of the redirect URI, and each scope's configured description (N2).
- The pages send the header set from SECURITY-REVIEW.md §4, with `frame-ancestors 'none'` so consent can't be clickjacked.
- Legal consent and account state are handled as in N6 and N7.

*External mode* (A12, A13). The consumer's frontend signs the user in with the flows it already has, unchanged: password, 2FA and external providers. authservice renders nothing beyond the error page above.
1. authservice validates the authorization request exactly as in Hosted mode.
2. It records a pending `AuthorizationInteraction` (a hashed handle, what it needs to resume the request, client, scopes, resource, a 10-minute expiry). It sets an HttpOnly, Secure, SameSite=Lax cookie on its own origin that binds the interaction to this browser, then redirects to `<ExternalUrl>?interaction=<handle>`.
3. The frontend's BFF calls `GET /api/v1/oauth/interactions/{handle}` with the user's bearer token and gets the client's display name, the redirect host and the scope descriptions.
4. On the user's decision, the BFF calls `POST /api/v1/oauth/interactions/{handle}/accept` or `…/deny` with the same token. authservice binds the interaction to that user and returns a `redirectTo` on its own origin carrying a single-use ticket: hashed, 60 s, the `OAuthExchangeCode` shape.
5. The browser follows `redirectTo`. authservice redeems the ticket **atomically** (a conditional update, unlike `OAuthExchangeCodeService.RedeemAsync`, §4.6), checks it belongs to the interaction this browser's cookie names, and completes the authorization response with a code and `iss`. A denial completes with `access_denied`.
- The frontend can accept or deny only what was requested and allowed; it cannot add a scope or a resource (A13).
- The interaction API is bearer-authenticated, on the authenticated trust level (SERVICE-API-PATTERNS.md §2), under the `api` rate-limit policy. It needs no CORS, because a BFF calls it server-side (FRONTEND-BFF.md §1).
- The browser-binding cookie defeats login CSRF: without it, an attacker could finish a victim's flow with a ticket issued to the attacker's own account, and the victim's Claude would be connected to the attacker's data.
- The consumer's pages live in the consumer's repository (out of scope). The runbook documents the contract they call (AC9).

**AC3**
- An authorization code lives 60 s and is single-use. Refresh tokens rotate with a reuse leeway of 0; the library default is 30 s (`OpenIddictServerOptions.cs` L302). See N3.
- Every refresh rebuilds the claims from the current user and refuses deleted or locked-out users, as `TokenService.RefreshTokenAsync` does today (L77–86; IDENTITY-AND-ACCOUNTS.md §1). See A10.
- A dead refresh token returns `invalid_grant`, and request bodies are form-urlencoded (`CLAUDE-AUTH` "Token refresh").
- Rate limiting follows N4.
- Persistence joins the migration set that B1 produces. The library's entities are mapped in `OnModelCreating`, so the SQLite test host's `EnsureCreatedAsync` (`AuthServiceFactory.cs` L123) creates their tables as well.

**AC4**
- The signing credential is `JwtSigningKeys.SigningKey`. Its RFC 7638 `KeyId` survives because the library derives a key id only when none is set (`OpenIddictServerConfiguration.cs` L552).
- Call `DisableAccessTokenEncryption()`: by default the library encrypts access tokens (`OpenIddictServerOptions.cs` L385).
- The claim shape is A9.
- Existing tokens are written by `JwtSecurityTokenHandler` (`TokenService.cs` L259), and its serialised names for `ClaimTypes.*` are what consumers read today. Whether the library shortens those names the same way is unverified here. The AC7 characterisation test records the exact names, and AC4's test holds MCP tokens to them.
- Tests check that:
  - `alg` is RS256 and the `kid` appears in `/.well-known/jwks.json`;
  - the token is not a JWE and validates with the published keys;
  - `aud`, `iss`, `sub` and `scope` match A9;
  - authservice's own API rejects the token, because it validates a single `ValidAudience` (`Program.cs` L194; this is the `:2fa` precedent).
- Rotation test (F8): issue a token under key A, rotate so A becomes the previous key, and confirm a refresh still succeeds. If it fails, that is an implementation-phase stop condition, and it goes back through `/ticket-feedback`.

**AC5**
- Configuration shape, with placeholder values only. The section is `AuthorizationServer`, not `OAuth:*`, which already holds the Google and GitHub settings:

  | Key | Holds |
  |---|---|
  | `AuthorizationServer:Clients:0:ClientId`, `…:DisplayName` | client identity |
  | `…:ClientSecret` | platform secret only, set as `AuthorizationServer__Clients__0__ClientSecret` |
  | `…:RedirectUris:0`, `…:AllowedScopes:0`, `…:AllowedResources:0` | per-client lists |
  | `AuthorizationServer:Scopes:<n>:Name`, `…:Description` | the consent description for each scope. *(Revision 4: a list, not `Scopes:<name>`. `:` is the configuration key delimiter, so a scope named `notes:read`, the form N1 recommends, cannot be a key.)* |
  | `AuthorizationServer:EncryptionKey` | platform secret (A4) |
  | `AuthorizationServer:PreviousEncryptionKeys:<n>` | platform secret, decryption only, for a rolling rotation (A4) |
  | `AuthorizationServer:AuthorizationCodeLifetimeSeconds`, `…:AccessTokenLifetimeMinutes`, `…:RefreshTokenLifetimeDays` | lifetimes (N1) |
  | `…:Clients:0:TokenRequestsPerMinute` | that client's token-endpoint limit (N4) |
  | `AuthorizationServer:Interaction:Mode`, `…:ExternalUrl` | the interaction mode (A11) |

- Startup validation fails with a message naming the setting (the ADR 0002 posture) unless all of these hold:
  - the secret is present and at least 256 bits;
  - redirect URIs are https or loopback (`MCP-SEC` "Communication Security");
  - resources are absolute https URIs with no fragment (`MCP-AUTHZ` "Canonical Server URI");
  - `offline_access` is allowed (F5);
  - the signing algorithm is RS256 (A3);
  - the issuer is set (A1).
- The sync hosted service waits for `IMigrationCompletionSignal` (SERVICE-API-PATTERNS.md §7; `UserCleanupService.cs` L33 shows the pattern) and treats configuration as authoritative (A8).
- The library stores client secrets hashed: PBKDF2-SHA256 with 10,000 iterations (`OpenIddictApplicationManager.cs` L1714–1722). Recorded here as SECURITY-REVIEW.md §5 asks.
- Claude's entry uses the redirect URI `https://claude.ai/api/mcp/auth_callback` (N8).

**AC6**
- There is one revocation operation (IDENTITY-AND-ACCOUNTS.md §2). Extending `RevokeRefreshTokensAsync` covers all 11 call sites:

  | Path | Call site |
  |---|---|
  | password reset, password change, logout, self-delete | `AuthController.cs` L807, L849, L881, L922 |
  | 2FA disable | `TwoFactorController.cs` L159 |
  | admin role changes, lock, revoke-sessions, soft-delete | `AdminController.cs` L210, L241, L285, L335, L370 |
  | the permanent-deletion reaper | `UserCleanupService.cs` L79 |

- The library's stores must be registered even when no client is configured, and their tables must exist in every database, including the test host's. Otherwise the extended operation breaks the existing `PasswordChangeTests` (A5).
- Access tokens already issued stay valid until they expire (D4). The short MCP access-token lifetime (N1) is what contains them.
- Permanent deletion removes the user's MCP rows. The library stores the user id as a plain subject string with no foreign key, so the cascade that clears `RefreshTokens` (`ApplicationDbContext.cs`) doesn't reach them (IDENTITY-AND-ACCOUNTS.md §8).
- Per-client revocation needs an authenticated user, touches only that user's own authorizations, and writes an audit event (N5).

**AC7**
- Written first, against the unchanged code (P13: characterisation tests are written "before the move, not after"). No existing test decodes an access token.
- For tokens from login, refresh and 2FA login, it asserts:
  - the header: `alg`, `typ`, and whether a `kid` is present;
  - every claim name;
  - `iss`, `aud` and the lifetime.
- It runs under HS256 in the existing project and under RS256 in the new project. `JwksEndpointTests.cs` already pins the bodies of the OIDC document and the JWKS.
- "Untouched" holds only if A2 holds. `JwksEndpointTests.cs` L46 and L59 fail as soon as the OIDC document gains a URL issuer or any response types.

**AC8**
- This needs a second test project. The existing host is configured through process-wide environment variables set once, in a static constructor (`AuthServiceFactory.cs` L35–62), and test classes run in parallel, so an RS256 host in the same process would race the HS256 one (N14).
- The happy path covers, in order:
  1. discovery;
  2. authorize, sign-in and consent;
  3. the code, with `iss`;
  4. the token exchange, with PKCE;
  5. a call to a test resource that validates the token through the JWKS;
  6. a refresh, then a second refresh.
- Negative cases are the brief's list plus these:
  - a missing `resource`, and a disallowed `resource`;
  - a replayed refresh token revokes the chain;
  - a locked or deleted user cannot refresh;
  - a confidential client without its secret is refused;
  - authservice's own API rejects the MCP token;
  - captured logs contain no code, token, secret or verifier (N5).
- External mode runs the same flow, with the consumer's frontend simulated by calls to the interaction API using the user's bearer token. Its negative cases:
  - a replayed ticket;
  - a ticket from another interaction;
  - a missing or mismatched browser-binding cookie;
  - an expired interaction;
  - a different user accepting;
  - the frontend trying to add a scope.
- The mode is read through options at request time (A11). *(Revision 4.)* The new project's hosts take every setting through `UseSetting`, which Program.cs sees during its top-level configuration reads, so each host has its own keys, clients and mode with nothing process-wide; `ConfigureAppConfiguration` is not needed (N14).
- No sleeps. Clock-dependent cases use the library's `TimeProvider` (TESTING-STRATEGY.md §6).

**AC9**
- ADR 0005 records:
  - D1–D4 and their status here;
  - A1–A10;
  - the answers to B1–B3;
  - that ADR 0003's first exclusion is amended for configured MCP clients while the rest of its list stands;
  - that OpenIddict returns now that it has a use (`EXTRACTION.md` L46–48 removed it for being unused);
  - the token contract `AP-MCP-01` validates against (A9);
  - both interaction modes, how they're chosen, and the External mode's protocol (A11–A13), including that authservice now renders HTML in Hosted mode;
  - the size of the service after the change (§4.6).
- The runbook section covers:
  - the configuration shape, with placeholders only (P5; `.gitleaks.toml` allowlists only the demo files);
  - generating the client secret and the encryption key with a platform-neutral instruction (IDENTITY-AND-ACCOUNTS.md §10);
  - adding the Claude connector through "Advanced settings", with the secret required (F12);
  - `min_machines_running = 1`, or a cold start well under 10 s (F9, P7);
  - trusting forwarded headers, so the library sees HTTPS;
  - adding the issuer's origin to `OAuth:PostLoginRedirectAllowedBaseUrls`;
  - what `AP-MCP-01` puts in its protected-resource metadata: the issuer listed first in `authorization_servers` (`CLAUDE-AUTH` "Cross-host authorization servers");
  - choosing the interaction mode, and for External mode, the contract the consumer's frontend calls: the three interaction endpoints, the bearer token they take, the redirect the frontend follows, and the 10-minute window;
  - that the initial migration set from PR #65 must be adopted first by a deployment still on `EnsureCreated`, because the authorization server's tables arrive as a migration.
- After this change "MCP" means two things in this repository: the `integrate` server (`src/AuthService.Mcp`, README section "MCP integration server"), and MCP connector clients. The runbook heading and the README must say which one they mean.

### Every file the table names

This list is for the definition-of-done check "no file touched outside the analysis table".

- **New (src):**
  - `src/AuthService/Extensions/AuthorizationServerExtensions.cs`
  - `src/AuthService/Services/AuthorizationServerOptions.cs`
  - `src/AuthService/Services/AuthorizationClientSync.cs`
  - `src/AuthService/Services/SignInFlow.cs`
  - `src/AuthService/Controllers/AuthorizationController.cs`
  - `src/AuthService/Controllers/ConnectedClientsController.cs`
  - `src/AuthService/Controllers/AuthorizationInteractionController.cs`
  - `src/AuthService.Data/Models/AuthorizationInteraction.cs`
  - `src/AuthService/Pages/_ViewImports.cshtml`
  - `src/AuthService/Pages/Shared/_ConnectLayout.cshtml`
  - `src/AuthService/Pages/Connect/{SignIn,TwoFactor,Consent,ExternalReturn}.cshtml` and `.cshtml.cs`
  - `src/AuthService.Migrations.{PostgreSQL,SqlServer}/Migrations/<timestamp>_AddAuthorizationServer.cs` and `.Designer.cs`
- **New (tests):**
  - `tests/AuthService.Tests/TokenContractCharacterizationTests.cs`
  - `tests/AuthService.Tests/SignInCharacterizationTests.cs`
  - `tests/AuthService.AuthorizationServer.Tests/` containing: the `.csproj`, `Infrastructure/AuthorizationServerFactory.cs`, `Infrastructure/AuthorizationFlowClient.cs`, `DiscoveryTests.cs`, `ClientRegistrationTests.cs`, `AuthorizationFlowTests.cs`, `ExternalInteractionTests.cs`, `AccessTokenTests.cs`, `RevocationTests.cs`, `TokenContractRs256CharacterizationTests.cs`
- **New (docs):** `docs/decisions/0005-mcp-authorization-server.md`
- **Changed:**
  - `src/AuthService/Program.cs`
  - `src/AuthService/appsettings.json`
  - `src/AuthService/AuthService.csproj`
  - `src/AuthService/Controllers/AuthController.cs`
  - `src/AuthService/Services/ITokenService.cs`
  - `src/AuthService/Services/TokenService.cs`
  - `src/AuthService/Services/UserCleanupService.cs`
  - `src/AuthService.Data/Data/ApplicationDbContext.cs`
  - `src/AuthService.Data/AuthService.Data.csproj`
  - `src/AuthService.Data/Models/AuditEvent.cs`
  - `src/AuthService.Migrations.{PostgreSQL,SqlServer}/Migrations/ApplicationDbContextModelSnapshot.cs`
  - `AuthService.sln`
  - `README.md`, `CONTRIBUTING.md`, `SECURITY.md`
  - `docs/DEPLOYMENT.md`, `docs/roles.md`, `docs/architecture/DEVIATIONS.md`
  - `docs/decisions/0003-scope.md`, `docs/decisions/0004-agent-to-agent-authorization.md`
  - `.github/ISSUE_TEMPLATE/feature_request.yml`
- **Left alone by design:**
  - `src/AuthService/Controllers/ExternalAuthController.cs`
  - `src/AuthService/Services/JwtSigningKeys.cs`
  - the OIDC discovery and JWKS handlers in `Program.cs`
  - every existing test file, including `tests/AuthService.Tests/Infrastructure/AuthServiceFactory.cs`
  - `EXTRACTION.md`, `docs/issue-analysis.md` (both historical records)
  - `tutorial.md`, `docs/index.html`
  - `src/AuthService.Mcp/`
- *(Revision 1 listed alternative file sets for other answers to B1 and B3. Both questions are closed, so the list above is final.)*

### Out of scope

**From the brief (§6), for the reasons it gives:**
- Dynamic Client Registration and client metadata documents. v1 uses pre-registered clients. F1 rewords the "later" clause.
- Any MCP server. That is `AP-MCP-01`, and it includes the server's RFC 9728 protected-resource metadata, its `WWW-Authenticate` challenges, and scope enforcement.
- Keycloak, or a hosted IdP.
- Changes to existing consumers.
- The device flow and the client-credentials grant. Claude doesn't support client credentials either: `CLAUDE-AUTH` "Anthropic-held client credentials" says "A pure machine-to-machine `client_credentials` grant … is not supported".

**Added by this analysis:**
- OpenID Connect itself: ID tokens, `userinfo`, end-session. The MCP flow needs only OAuth (`MCP-AUTHZ`), and an OIDC provider would reopen F4.
- Token introspection (D4), and an RFC 7009 revocation endpoint for clients. AC6 asks for revocation by the user, and Claude's documentation doesn't say it calls such an endpoint.
- Claude Code as a client (loopback redirects and its own CIMD; F11).
- Public clients (AC5 says confidential).
- Registration and password reset on the authorization server's pages (N7).
- A "list my connected clients" endpoint, and MCP authorizations in the GDPR export (N11, N12). Both are cheap to add, but neither is asked for.
- The single-audience deviation (`DEVIATIONS.md` L22) for existing tokens. MCP tokens are audience-bound; existing tokens belong to AC7.
- OTLP tracing (`DEVIATIONS.md` L16); see N5.
- Refactoring the existing `Program.cs` (`DEVIATIONS.md` L20). A6 only avoids making it worse.
- ~~The initial migration set. B1 recommends it land separately.~~ It landed in PR #65 (issue #17).
- The sign-in and consent pages a consumer's frontend renders in External mode. They belong to that consumer's repository (for AureliusPromptus, `AP-MCP-01` or its frontend ticket). This ticket delivers the interaction API and documents its contract.
- ADR 0004's scope model. MCP scopes here are opaque configured strings that the resource server enforces, not ADR 0004's subset-checkable model.

---

## 3. What the change puts at risk

The compliance checklist is walked only for the layers the table names (TICKET-ANALYSIS §3). Each item is marked as kept, as decided (by a recorded decision), or as open.

**Reference architecture, §3 checklist**

| Item | At risk because | Status |
|---|---|---|
| Owns its database; no other service connects to it | New tables | **Kept.** The library's tables live in `ApplicationDbContext` (P3). Resource servers validate offline (D4) and never read them |
| Schema applied by `MigrateAsync` from provider-specific migrations, in a hosted service | There was no migration set | ~~Open → B1~~ **Kept.** The sets landed in PR #65. This ticket adds one incremental migration per provider, and CI's `Migrations` job enforces model/migration agreement |
| All configuration from environment variables; no secret in source, config file, or comment, with a secret scanner in CI | Client secrets and the encryption key | **Kept.** Both exist only as platform secrets. `appsettings.json` carries empty values, as it already does for `OAuth:Google:ClientSecret`. The runbook uses placeholders, tests generate their own values, and gitleaks runs in CI (`.github/workflows/secret-scan.yml`) |
| Exactly one service holds a signing key; all others validate against its JWKS endpoint | The library's own JWKS; HS256 deployments | **Kept** by A2 (library JWKS off, one JWKS) and A3 (RS256 required) |
| Every optional integration has a working no-op or fallback | A new capability | **Kept** by A5 |
| The health endpoint reports the state of every optional integration, and the startup banner prints the same list | A new capability | **Banner kept:** A5 adds the AS posture next to `Program.cs` L386–392. The health endpoint reports no integration at all today, SendGrid and the OAuth providers included, and `DEVIATIONS.md` doesn't record that. Not made worse here; reported as a finding for the register (§4.6) |
| Multi-stage Dockerfile; runtime major version equals the TFM | Razor Pages | **Kept.** Pages compile into the assembly, so the Dockerfile doesn't change |
| One `fly.toml`; `min_machines_running = 1` if another service calls it in-request | Claude's 10 s timeout (F9) | This repository has no `fly.toml`: consumers own it (ADR 0001; SHARED-SERVICE-REUSE.md §4). The runbook states the requirement |
| `Program.cs` is a manifest; wiring lives in `ServiceCollectionExtensions` | New wiring | **Kept** for the new code by A6 |
| Extension points are interfaces registered in DI, not base classes | Library handlers | **Kept.** Passthrough controllers and DI-registered handlers (P10) |
| Has a test project; the logic-bearing layer is covered; characterisation tests come before a move | The `Login` extraction; changes to the token path | **Kept** by AC7 (written first) and `SignInCharacterizationTests` (written before `SignInFlow` is extracted). N14 adds a second test project |
| Its architectural decisions are recorded in `docs/` | Reverses ADR 0003 | ~~Open → B2~~ **Decided:** ADR 0005 amends ADR 0003 (Konrad, 2026-09-23). AC9 is the record itself |

**IDENTITY-AND-ACCOUNTS.md §12**

| Item | Status |
|---|---|
| Authorization facts stamped into claims at issuance; no downstream callback | **Kept.** One shared claim builder (AC4), rebuilt on every refresh (A10) |
| Refresh tokens: CSPRNG, single-use rotation, stored hashed, global revocation from logout, reset and deletion | **Decided.** The library's default 30 s reuse leeway contradicts "single-use", so N3 sets it to 0. Global revocation: AC6 extends the one operation. Stored hashed: the library hashes reference identifiers with SHA-256 (`OpenIddictTokenManager.cs` L1147–1154). The implementation must still confirm that, in the chosen token mode, the database holds no token that could be presented |
| OAuth: middleware callback paths; explicit public callback base URL; `returnUrl` in state, validated against an allowlist | **Kept.** External-provider resume reuses the existing flow unchanged (AC2 notes). The issuer comes from configuration, never from `Request.Host` (A1) |
| Forgot and reset are enumeration-safe | **Kept.** The AS pages link out for reset (N7), and sign-in goes through the shared `SignInFlow` (AC2) |
| Lockout enabled, with an admin unlock endpoint | **Kept.** Same `CheckPasswordSignInAsync(lockoutOnFailure: true)` path. The unlock endpoint exists (`AdminController.cs` L303) |
| Soft delete, retention, reaper | **Kept**, plus the AC6 note on rows without a foreign key |
| Consent versions in configuration; immutable acceptance rows | See N6 (a sign-in with stale legal consent) |
| Keys generated rather than invented; the private half held only by the identity service; `kid` derived from the key | **Kept.** The existing key is reused and its `kid` preserved (AC4 notes). The new encryption key is generated (A4) |
| Rotation is rolling | **At risk (F8).** The AC4 rotation test decides it |
| Key generation works on every platform contributors use | The runbook's instructions for the client secret and the encryption key must be platform-neutral (AC9) |
| Local development keys are distinct from deployed ones | **Kept.** Tests and development generate their own |
| The deploy asserts that the published key set is non-empty | No CI job asserts this today. A3 makes an MCP-enabled instance fail at startup without an RS256 key, which covers the MCP case. The general assertion stays with the deploying system (`docs/DEPLOYMENT.md`) |

**SERVICE-API-PATTERNS.md §10, SECURITY-REVIEW.md §10, TESTING-STRATEGY.md §10**

| Item | Status |
|---|---|
| Rate limiting partitioned by user with an IP fallback; `auth`, `api` and global policies; a uniform 429 body | **Decided (N4)**, because of F10 |
| Anonymous surfaces: one client resolver; rejections not queued | The new policies use `ResolveClientIp` and `QueueLimit = 0`. The existing `auth` policy queues 5 (`Program.cs` L336); that predates this ticket and isn't made worse |
| Endpoint groups make trust levels visible | **Kept.** The extension groups endpoints by trust level: anonymous (metadata, authorize, token, sign-in pages), AS cookie (consent), and bearer (connected clients) |
| Background services wait for the migration completion signal | **Kept.** Client sync (AC5) and pruning (AC3) |
| Seeded definitions: insert if missing, never overwrite | **Deliberately different** (A8) |
| Deny by default, with a short `[AllowAnonymous]` list and an endpoint × role matrix | The anonymous list gains the metadata, authorize and token endpoints and the sign-in pages. They get listed in `docs/roles.md` (AC6, AC9). The External interaction API is authenticated, not anonymous |
| Findings stated as attack scenarios (the External mode's handoff) | **Decided (A12, A13).** Login CSRF is stopped by the browser-binding cookie; ticket replay by atomic single-use redemption; scope widening by accepting only what was requested and allowed |
| No tokens in web storage; cookies set server-side; the header set on every page | The AS cookie is HttpOnly, Secure, SameSite=Lax and scoped to its paths. The AS pages send the header set (AC2) |
| CSPRNG for anything a caller can present as proof | Codes and tokens are generated by the library. Client secrets are generated as the runbook instructs (IDENTITY-AND-ACCOUNTS.md §10) |
| Encode at render time | Razor encodes by default. Client names and scope descriptions come from configuration, which is trusted |
| The four recurring launch blockers | CORS is unchanged: server-to-server calls and top-level navigation need none. Rate limiting is N4 |
| Every committed test configuration is executed by CI; the per-test bar | The new project goes into `AuthService.sln` (AC8). No sleeps and no flaky tests (AC8 notes) |

---

## 4. The exploratory round (read-only)

### 4.1 Where the behaviour lives today

| Concern | Where | Notes |
|---|---|---|
| Access-token issuance | `TokenService.cs` L172–196, L247–260 | Uses `JwtSecurityTokenHandler`. `iss` and `aud` are read from configuration (L252–253). Default lifetime is 60 min (L284–285) |
| Claim enrichment | `TokenService.cs` L217–245 | Private. `sub` = `user.Id`; one claim per role; `organization` and `organization:{id}:role` |
| Refresh rotation and replay detection | `TokenService.cs` L34–93 | Looks up the hash; reuse revokes the whole family; deleted and locked-out users are refused |
| Global revocation | `TokenService.cs` L95–113 | 11 call sites (AC6 notes) |
| Key material | `JwtSigningKeys.cs` | HS256 is inferred when no PEM is configured (L185–205). The RS256 key carries an RFC 7638 `kid` (L110–116). Retired keys are kept public-only (L120–143) |
| Bearer validation | `Program.cs` L185–199 | One `ValidIssuer` and one `ValidAudience` |
| JWKS / discovery | `Program.cs` L466–470 / L472–496 | Discovery covers key discovery only, and its comment cites ADR 0003 |
| Public origin | `Program.cs` L119–122 (`Jwt:PublicBaseUrl`) | The natural issuer (A1) |
| Rate limiting | `Program.cs` L324–380 | `auth`: per IP, 20/min, queue 5. `api`: 200/min. Global: 500/min per user or IP |
| Startup posture | `Program.cs` L386–400 | Where A5 adds the AS posture |
| Password sign-in | `AuthController.cs` L200–278 | Enumeration-safe; discloses lockout only to a caller with the correct password; checks email confirmation; issues the 2FA challenge |
| External sign-in | `ExternalAuthController.cs` L40–88, L96–275, L288–318 | `returnUrl` allowlist (L47–66, L344–366); `bypassTwoFactor: true` (L114–118); exchange code (L272–274); 2FA applied at the exchange (L306–312) |
| Exchange code | `OAuthExchangeCodeService.cs`, `OAuthExchangeCode.cs` | Hashed, single-use, 60 s: the same shape an authorization code needs |
| Audit | `AuditEvent.cs` (`AuditAction`), `AuditService.cs` | Actions are constants, not an enum |
| Background work | `UserCleanupService.cs` (waits on `IMigrationCompletionSignal`, L33) | The pattern for client sync and pruning |
| Schema mode | `DatabaseProviderExtensions.cs`, `MigrationBackgroundService.cs`, `docs/schema/README.md` | `EnsureCreated` is the default. `Migrate` has no migrations to apply |
| Configuration | `appsettings.json` | Sections `Jwt`, `OAuth` (Google and GitHub), and `FrontendBaseUrl` |

### 4.2 What already exists, and would otherwise be duplicated

| Existing | Reused for |
|---|---|
| RS256 key, `kid`, JWKS and rolling rotation (`JwtSigningKeys`) | AC4 signing, so no second signing key |
| `BuildClaimsAsync` | AC4 claims, so no second claim builder |
| `RevokeRefreshTokensAsync` | AC6, so no second revocation operation |
| The `OAuthExchangeCode` handoff | AC2's external-provider resume, without touching `ExternalAuthController` |
| The `:2fa` audience precedent (`TokenService.cs` L28–29, L281–282) | Keeping MCP tokens out of authservice's own API by audience |
| `Jwt:PublicBaseUrl` | The issuer (A1) |
| Provider discovery, `GET /api/v1/external-auth/providers` (`ExternalAuthController.cs` L324–336) | Deciding which provider buttons the sign-in page shows (IDENTITY-AND-ACCOUNTS.md §3 rule 4) |
| `IMigrationCompletionSignal` | Client sync and pruning |

### 4.3 What is tested today

The suite has 13 classes and 67 cases in `tests/AuthService.Tests`.

| Area | Covered | Layer |
|---|---|---|
| Access-token shape | **No test decodes a token** | none |
| Discovery and JWKS | `issuer` = "AuthService", the `jwks_uri` suffix, the HS256 alg, empty `response_types_supported`, and an empty JWKS (`JwksEndpointTests.cs`) | integration, HS256 only |
| RS256 | Unit tests only (`JwtSigningKeysTests.cs`) | unit |
| Refresh rotation, replay, lockout, soft delete | Yes (`RefreshTokenTests.cs`) | integration |
| Revocation paths | Only logout and password change. Reset, the admin paths, self-delete, 2FA disable and the reaper are untested | integration |
| External auth and exchange code | None (no provider is registered under test) | none |
| Rate limiting | None | none |
| Login enumeration safety | Yes (`AuthenticationTests.cs`). The lockout-disclosure and confirmed-email branches are untested | integration |
| The test host itself | HS256 through process-wide environment variables (`AuthServiceFactory.cs` L35–62); shared in-memory SQLite; hosted services removed; `EnsureCreatedAsync` | none |

### 4.4 The end-to-end flow: today versus what the ticket assumes

- **Today, no request to authservice carries a browser session.**
  - Password sign-in returns tokens as JSON.
  - The external flow ends in a single-use code that the *frontend* redeems.
  - The only cookie is the transient external-login cookie. There is also an `Identity.Application` cookie that `ExternalLoginSignInAsync` sets and nothing reads.
- **The ticket assumes authservice can recognise the user** when Claude sends a browser to its authorization endpoint. That needs either a session on authservice's own origin (B3 = a), or a handoff to a frontend that already has one (B3 = b). Neither exists yet.
- **The ticket assumes "the existing key material and kid".** That holds only under RS256; the quick start and the test suite run HS256 (A3).
- **The ticket assumes migrations.** There are none (B1).

### 4.5 Library defaults that break the acceptance criteria

OpenIddict 7.7.1, read in source.

| Default | Where | Breaks | Override |
|---|---|---|---|
| The configuration endpoint serves `.well-known/openid-configuration` **and** `.well-known/oauth-authorization-server` | `OpenIddictServerOptions.cs` L69–73 | AC7: it takes over the existing OIDC document | Serve only `.well-known/oauth-authorization-server` (A2) |
| The library runs its own JWKS endpoint at `.well-known/jwks` | `OpenIddictServerOptions.cs` L93–96 | AC1 ("the existing key set"), and P5's single JWKS | Turn it off, and point `jwks_uri` at the existing JWKS |
| Access tokens are encrypted | `OpenIddictServerOptions.cs` L385 | AC4 | Call `DisableAccessTokenEncryption()` |
| `plain` and `S256` are both enabled, and PKCE is optional | `OpenIddictServerOptions.cs` L494–498, L533 | AC2 | Require PKCE and remove `plain` |
| Refresh tokens have a 30 s reuse leeway | `OpenIddictServerOptions.cs` L302 | AC3, and IDENTITY-AND-ACCOUNTS.md §2 "single-use" | Set it to 0 (N3) |
| Lifetimes: code 5 min, access token 1 h, refresh token 14 days | `OpenIddictServerOptions.cs` L245, L252, L296 | Q2 | Set them explicitly (N1) |
| A refresh token is issued only when `offline_access` is granted | `OpenIddictServerHandlers.cs` L3460 | AC3, whenever Claude doesn't ask for it | Advertise and allow `offline_access` (F5) |
| Startup requires an encryption key and an asymmetric signing key, and the error text suggests `AddEphemeral…` or `AddDevelopment…` | `OpenIddictServerConfiguration.cs` L250–257; `ID0085`/`ID0086` in `OpenIddictResources.resx` | P5 and IDENTITY-AND-ACCOUNTS.md §10: an ephemeral key dies at every restart, and a scaled-to-zero machine restarts often | Use the existing RS256 key and a durable encryption key (A3, A4) |
| Logged request payloads redact codes, tokens and secrets, but not `code_verifier`; and the token generator logs every token it creates, in full, at Trace | `OpenIddictMessage.cs` L411–422; `OpenIddictServerHandlers.Protection.cs` L1771 *(revision 4)* | Brief §7: no secrets in logs | Raise the library's log level, and add a log-capture test (N5). *(Revision 4.)* The cap is applied in code to every `OpenIddict` category, so no configuration can lower it |
| `resource` is compared ordinally against each registered resource's `Uri.AbsoluteUri` | `OpenIddictServerHandlers.Authentication.cs` L1548, L3601 | AC2, for an MCP server at an origin root | Test both forms (N10). *(Revision 4.)* `AbsoluteUri` always ends an origin in `/`, so the registry can never match the form Claude sends. The registry check is turned off; each client's resource permissions carry both forms of an origin-root resource (`…Authentication.cs` L1885 compares the permission string), and the passthrough requires exactly one resource |
| *(Revision 4.)* Signing credentials are sorted with symmetric keys first, and every token but an identity token is signed with the first one | `OpenIddictServerConfiguration.cs` L545, L572; `OpenIddictServerHandlers.Protection.cs` L1485 | A3 and P5, were a symmetric key ever registered: access tokens would be HS256. F8: a retired key must validate without becoming the signing key | Register only `JwtSigningKeys.SigningKey`, then each retired public key after it (order among RSA keys is kept), and fail startup unless the first signing credential is the current key |
| *(Revision 4.)* The issuer is written as `Uri.AbsoluteUri`, which ends an origin in `/`; the configuration endpoint's document also carries OIDC fields (claims, identity-token algorithms, subject types, prompt values) | `OpenIddictServerHandlers.cs` L3711–3717; `…Discovery.cs` L230; `…Authentication.cs` L2246 | A1 (trailing slash trimmed), and `MCP-DISC`'s identical-issuer rule for a protected-resource document that lists the origin | The library's configuration endpoint is off entirely. authservice serves the RFC 8414 document from the AS options, and two event handlers write A1's form into the authorization response's `iss` and the access token's `iss`. The library's own validation accepts both forms (`…Protection.cs` L191–202) |

Defaults the library gets right, which should stay:
- `iss` in authorization responses, and its metadata flag (`OpenIddictServerHandlers.Discovery.cs` L859).
- Per-client resource permissions (`OpenIddictServerHandlers.Authentication.cs` L1885).
- A `kid` that is already set is kept (`OpenIddictServerConfiguration.cs` L552).
- Access tokens carry `typ: at+jwt` and a `client_id` claim.
- Reference identifiers and client secrets are stored hashed.

### 4.6 Other observations

None of these is in scope; they are recorded so they aren't lost.

- `OAuthExchangeCodeService.RedeemAsync` reads `ConsumedAt` and then writes it with no concurrency guard (L53–77), so two concurrent redemptions can both succeed. It matters here only if the pattern were copied for authorization codes. The library's own code redemption is used instead.
- The health endpoint reports no optional integration at all (a P8 checklist item), and `DEVIATIONS.md` doesn't record the gap.
- `SECURITY.md` lists "the Fly.io deployment configuration" as in scope, but the repository has held no Fly configuration since commit `47e8236`.
- `tutorial.md` is stale regardless of this ticket: its instructions are HS256-only, it describes tokens in the redirect URL, and it advises editing `EnsureCreated`.
- Actual size: 7,818 lines of C# under `src/`, 6,611 of them in `AuthService`. ADR 0003 says about 5,000 and ADR 0004 about 7,400.
- `CONTRIBUTING.md` says CI builds with `-warnaserror`; `ci.yml` does not.
- *(Revision 4.)* The 403 branch in `AuthController.Login` (L247–254) cannot be reached while one setting drives both switches: with confirmation enforced, Identity's pre-sign-in check refuses an unconfirmed account before the password is checked, and the caller gets the generic 401 (`SignInCharacterizationTests` pins it). `SignInFlow` keeps the behaviour, and N6's citation now points here.
- *(Revision 4.)* A failed external sign-in started from the AS sign-in page ends on the product frontend's login page, because `ExternalAuthController` sends failures to `OAuth:ErrorRedirectBaseUrl` and stays unchanged by design. The runbook says so.
- *(Revision 4.)* With the legacy `Auth:AllowTokensInOAuthRedirect` on, the callback carries tokens rather than a code, so the AS pages cannot resume an external sign-in. They refuse it with a message rather than accept tokens in their own URL.
- Names already taken, to avoid colliding with:
  - `OAuth:*` (the Google and GitHub settings);
  - `UserConsent` and `ConsentType` (legal consent);
  - `OAuthExchangeCodes` (social-login codes);
  - "Configuring an MCP client" in `src/AuthService.Mcp/README.md` (that heading is about the stdio server).
- **Environment:** this container has no .NET SDK, and its network policy denies the SDK download host (`builds.dotnet.microsoft.com`); NuGet is reachable. Nothing was compiled for this analysis. The implementation phase needs an environment with the .NET 10 SDK.

---

## 5. Questions

### 5.1 Blocking

Revision 2: all three are answered. They stay here, struck, with the answer and who gave it (TICKET-ANALYSIS §2). Revision 1's text follows each struck heading unchanged.

~~**B1: How does the schema change reach the database? (P4)**~~

> **Closed, revision 2.** Option (a): the initial migration set landed on its own as PR #65 (issue #17), which Konrad authorised on 2026-09-23 ("Yes, merge when green (Recommended)", in answer to whether the #17 PR could be merged ahead of AUTH-MCP-01). This ticket adds an incremental migration on top.
*Question:* The new tables need migrations (P4; brief §7), and neither migrations project contains a migration set (`DEVIATIONS.md` L18). Which of these happens?
- (a) The initial migration set (issue #17) lands first, as its own change.
- (b) It lands inside AUTH-MCP-01.
- (c) AUTH-MCP-01 deviates from P4 and ships hand-written idempotent DDL, as v0.2 did (`docs/schema/README.md` L113–118).

*Blocks:* the persistence files for AC3 and AC6; whether this is one ticket (§1); and CI's `migrations` job turning from a no-op into a real guard.
*Recommendation:* **(a)**.
- ADR 0004 already sequences it: "Land issue #17 (committed migrations) first" (L190).
- A baseline is repo-wide schema work unrelated to MCP. The library's four tables are readable as an incremental migration; mixed into a synthetic baseline, they are not.
- (b) would make the diff mostly unrelated baseline for two providers, plus a baselining story for existing `EnsureCreated` databases.
- (c) records a P4 deviation that ADR 0004 says "widens the estate's most acute open deviation rather than paying it down". It also means hand-writing the library's DDL for two providers.
- Either way, the baseline can't be generated in this container (§4.6).

~~**B2: Does AUTH-MCP-01 knowingly amend ADR 0003? (P14)**~~

> **Answered, revision 2.** "Amend via ADR 0005 (Recommended)", from Konrad, 2026-09-23, in the session. D1 is confirmed as a knowing amendment of ADR 0003, recorded by AC9's ADR 0005.
*Question:* D1 turns authservice into an OAuth authorization server. ADR 0003 excludes exactly that: "authorization code flow, an authorization endpoint, a standards-shaped token endpoint, consent screens, client registration, introspection … re-adding OpenIddict would undo the extraction decision" (L36–38). ADR 0004 (Proposed) restates the exclusion for "third-party, browser-facing clients" (L132, L137–138), and Claude is one. Is the amendment intended?
*Blocks:* whether this ticket proceeds in this repository at all; the ADR's content (AC9); and the README, CONTRIBUTING, SECURITY and issue-template changes.
*Recommendation:* **Yes, through ADR 0005.** ADR 0005 would amend ADR 0003's first exclusion for configured MCP clients only and keep the rest of the list (OIDC provider features, introspection, DCR, admin UI). Its grounds:
- P3: identity owns the capability.
- SHARED-SERVICE-REUSE.md §1: each system's instance is its own authorization server, with no shared trust root.
- AC7: existing consumers are unaffected.
- A5: a deployment without clients carries no new surface.
- `EXTRACTION.md` L46–48: OpenIddict was removed as unused, and that no longer holds.

The brief records D1 as decided, but the brief was written "before the repository was read" (its own header). So whether D1 accepted reversing ADR 0003 cannot be inferred from it, and TICKET-ANALYSIS §6 says such a condition is treated as unmet.

~~**B3: Where do sign-in and consent render? (brief Q1)**~~

> **Answered, revision 2. This is a scope change** (FEEDBACK.md §2). Konrad's words, 2026-09-23, verbatim: *"Consumer should have an option to choose , we should provide some pages as well ondly dconsumer frontend"*.
> **Reading:** both modes, chosen per deployment. authservice ships its own sign-in and consent pages (Hosted, the default), and a deployment can instead have its own frontend render them through an interaction API (External). A11–A13 hold the design; AC2's row and notes carry the files and requirements. If the reading is wrong, correct it through `/ticket-feedback`: AC2, AC8, A11–A13 and the master prompt would all go stale.
*Question:* The two options are:
- (a) **authservice-hosted pages.** A dedicated AS cookie session. Password sign-in shares `SignInFlow` with the API. External providers resume through the existing exchange-code handoff, with `ExternalAuthController` unchanged. 2FA is applied on the page.
- (b) **The consumer's frontend, through its BFF.** An interaction handoff in the style of Ory Hydra: authservice exposes "get request / approve / deny" to a frontend that already has the user's session (FRONTEND-BFF.md §1, §3).

*Blocks:* AC2's files and layers; the security surface (HTML, a cookie session, CSRF, clickjacking); and whether a second repository is involved (§1).
*Recommendation:* **(a)**.
- Brief §6 excludes changes to existing consumers, and one flow has to serve every Claude surface.
- AC2 speaks of "authservice's existing sign-in".
- The library's supported model is a session held by the host.

The costs of (a), to be recorded in ADR 0005:
- This is the service's first HTML surface (`docs/issue-analysis.md` L235).
- It needs a cookie scheme of its own (AC2 notes: never `Identity.Application`), antiforgery, and the SECURITY-REVIEW.md §4 header set.
- `AuthController.Login`'s decision gets extracted, with characterisation tests written first (P13).

(b) keeps authservice free of HTML and reuses the frontend's sign-in, external providers and 2FA unchanged. In exchange it needs a second ticket in the consumer's repository, and the flow then works only for consumers that have such a frontend.

### 5.2 Non-blocking: the assumption to proceed on

Each assumption goes into the pull request (TICKET-ANALYSIS §5).

| # | Question | Assumption, and its basis |
|---|---|---|
| N1 | Lifetimes and scope naming (brief Q2) | **Lifetimes:** code 60 s (as `OAuthExchangeCode.DefaultLifetime`); MCP access token 15 min; refresh token 30 days, sliding; all configurable. Existing tokens stay at 60 min and 7 days. The 15 minutes has three grounds: IDENTITY-AND-ACCOUNTS.md §1 (staleness until refresh); ADR 0004's second property ("a long time for a credential sitting in an autonomous process"); and D4, which means an issued JWT can't be recalled, so its lifetime is the containment. Claude refreshes on a 401, and proactively up to 5 min before expiry (`CLAUDE-AUTH` "Token refresh"). **Scopes:** opaque strings configured per client. The recommended form is lowercase `<area>:<action>`, matching `MCP-AUTHZ`'s `files:read`, plus `offline_access` (F5). The naming convention belongs to `AP-MCP-01`, because the resource server enforces scopes (`MCP-AUTHZ` "Scope Selection Strategy") |
| N2 | Is consent remembered? | Yes. It is explicit, remembered per user and client for the granted scopes, and asked again when new scopes are requested. AC6 revocation forgets it |
| N3 | Refresh-token reuse leeway | 0 (IDENTITY-AND-ACCOUNTS.md §2 "single-use"). The risk: Claude's concurrent refreshes (reactive plus proactive) could trip replay detection and revoke the chain, forcing a reconnect. Watch the reuse audit event, and revisit through `/ticket-feedback` with evidence |
| N4 | Rate-limit partitions | The authorize endpoint and sign-in pages use the `auth` policy, per IP, because the callers are browsers. The token endpoint is partitioned by the authenticated `client_id`, with a limit sized to that client's users, and rejections are not queued (SERVICE-API-PATTERNS.md §1). It is kept out of the global per-IP bucket (`Program.cs` L354–364), because all Claude calls come from one range (F10) |
| N5 | What "traced" means (brief §7) | Audit events (new `AuditAction` constants for consent granted or denied, client revoked, and refresh reuse) plus structured logs. No code, token, secret or verifier is logged: the library's request logging runs at Warning in production (§4.5), and a log-capture test enforces it. OTLP stays an open row in `DEVIATIONS.md` (L16) |
| N6 | A user whose accepted legal-consent versions are stale (IDENTITY-AND-ACCOUNTS.md §9) | The AS sign-in refuses, with an instruction to accept the new versions in the product. authservice gets no terms UI. Unconfirmed emails are refused as they are today, by Identity's pre-sign-in check, with the generic failure (§4.6, revision 4) |
| N7 | Registration and password reset on the AS pages | Neither is offered; the pages link to the product (`FrontendBaseUrl`) |
| N8 | Claude's redirect URI | `https://claude.ai/api/mcp/auth_callback` (`CLAUDE-AUTH`). `https://claude.com/api/mcp/auth_callback` may be added. It appears only in a search excerpt of the retired article (§0), and the current page lists only claude.ai. It lives in configuration, not code (AC5) |
| N9 | Token-endpoint client authentication | Accept both `client_secret_basic` and `client_secret_post`; Anthropic's pages don't say which Claude uses. Don't advertise `none`, so Claude never attempts CIMD (`CLAUDE-AUTH` "DCR and CIMD details") |
| N10 | `resource` form | Exactly one, required, and in the client's list. A root URL is accepted with or without a trailing slash (§4.5; `CLAUDE-TS` "Audience mismatch": Claude sends no trailing slash). Recommend that `AP-MCP-01`'s endpoint have a path such as `/mcp` |
| N11 | MCP authorizations in the GDPR export | Not included: it isn't asked for. Flag it in the PR |
| N12 | Listing connected clients | Not built: AC6 asks only for revocation |
| N13 | Permanent deletion | Deletes the user's library rows, which have no foreign key. The existing hourly reaper loop prunes expired and revoked rows (IDENTITY-AND-ACCOUNTS.md §8) |
| N14 | A second test project | The existing host's process-wide environment configuration (`AuthServiceFactory.cs` L35–62), combined with parallel test classes, rules out a second key configuration in the same process. A separate project runs in its own process, and adding it to `AuthService.sln` means CI runs it (TESTING-STRATEGY.md §9). This departs slightly from P13's "one project per service" wording, and is recorded here for that reason. *(Revision 4.)* The new project configures its hosts through `UseSetting` rather than environment variables, so it has no process-wide state of its own (AC8 notes) |

### 5.3 The brief's own questions

| Q | Status |
|---|---|
| ~~Q1: Where do sign-in and consent render, and how does the flow resume after external sign-in?~~ | Answered through B3 (Konrad, 2026-09-23): both modes (A11). ~~Open → B3.~~ The resume mechanism is in AC2's notes |
| Q2: Scope naming and token lifetimes for MCP clients | **Proposed → N1.** Open until confirmed |
| ~~Q3: Does the library's storage fit authservice's persistence and migration approach?~~ | Answered by this analysis from the code and the library source. The library's EF Core stores live in `ApplicationDbContext` (P3), are portable across providers, and are applied by migrations (P4), once B1 supplies a migration set. They must be mapped in `OnModelCreating` (AC3 notes) |
| ~~Q4: Which discovery document does Claude request?~~ | Answered from `CLAUDE-TS`: RFC 8414 first, then OIDC discovery as a fallback, and one is enough. → A2 |
| Q5: What is the public issuer URL in each environment? | **Proposed → A1.** The issuer is `Jwt:PublicBaseUrl`, and its per-environment value is the deploying system's configuration (ADR 0001; SHARED-SERVICE-REUSE.md §4). Open until confirmed |

### 5.4 Findings from the implementation phase (revision 4)

Landed through `/ticket-feedback` (FEEDBACK.md): facts about the library and the code that the implementation phase found before any production change, stated as they were found. Each is a correction or new information, not a scope change, so no condition in §7 needs a person's re-decision.

| # | Finding, as found | Kind | Lands in |
|---|---|---|---|
| I1 | "`AuthorizationServer:Scopes:<name>` cannot hold a scope named `notes:read`: `:` is the configuration key delimiter, so the name splits into nested sections and the description is lost." | Correction | AC5 notes' configuration table |
| I2 | "OpenIddict writes the issuer as `Uri.AbsoluteUri`, so an origin becomes `https://auth.example.com/` in the metadata, the authorization response and the token, where A1 trims the slash." | New information | §4.5; A1 stands, and is kept by serving the metadata from authservice and rewriting `iss` in two event handlers |
| I3 | "OpenIddict sorts signing credentials symmetric-first and signs with the first; a retired RSA key registered for validation has to come after the current one." | New information | §4.5; A3 and F8 stand |
| I4 | "The resource registry compares against `AbsoluteUri`, which can never equal an origin-root resource without its slash." | Correction to §4.5's override for that row | §4.5; N10 stands |
| I5 | "The token generator logs every token it creates, in full, at Trace." | New information | §4.5; N5 stands, with the cap enforced in code |
| I6 | "An external sign-in started from a Hosted page can be finished by a link carrying someone else's exchange code, unless the round trip is bound to the browser." | New information | AC2 notes (Hosted) |
| I7 | "`WebApplicationFactory`'s `UseSetting` reaches Program.cs's top-level configuration reads on .NET 10, so the new test project needs no environment variables at all." | Correction | AC8 notes, N14 |
| I8 | "The 403 unverified-email branch of `AuthController.Login` is unreachable: Identity refuses the account first, with the generic 401." | New information | §4.6, N6 |
| I9 | "Failed external sign-ins end on the product frontend, and the legacy tokens-in-redirect switch leaves the AS pages nothing to resume from." | New information | §4.6; the runbook |

---

## 6. Decisions

### 6.1 The brief's decisions

| D | Status after this analysis | Basis |
|---|---|---|
| D1: Extend authservice; it stays the only IdP | Consistent with P3 and SHARED-SERVICE-REUSE.md §1. ~~Pending B2~~ **Confirmed:** Konrad answered B2, amending ADR 0003 through ADR 0005 (2026-09-23) | Amending ADR 0003 has to be a recorded decision (P14) |
| D2: Use a maintained library, with OpenIddict the candidate | **Confirmed**, with the overrides in A7 | OpenIddict is the maintained open-source .NET authorization-server library (Apache-2.0). Duende IdentityServer is commercially licensed and wasn't considered further for an MIT image that other systems deploy. The library's defaults for a public third-party client are the right ones (`iss` in responses, exact redirect matching, per-client resource permissions, token-chain revocation), and those are exactly where hand-rolled servers fail. A hand-rolled server in the style of ADR 0004 was considered: one refresh store, one claim builder, no encryption key. It was rejected because the two things it simplifies are recovered anyway, by one revocation operation spanning both stores (IDENTITY-AND-ACCOUNTS.md §2) and one shared claim builder (§1) |
| D3: Static pre-registered clients, no DCR | **Confirmed** | Pre-registration is one of the three mechanisms in `MCP-REG`. Claude's custom connectors accept a client id and secret (F12). F1 rewords "DCR later" |
| D4: Resource servers validate JWTs through the JWKS; no introspection | **Confirmed** | IDENTITY-AND-ACCOUNTS.md §1 (no callback) and P5. The resource server's audience check (`MCP-AUTHZ` "Token Handling") works on `aud`. Consequence: revocation stops refreshes, not tokens already issued, which is why N1 keeps them short-lived |

### 6.2 Decisions this analysis derives: confirm or overrule

| # | Decision | Basis |
|---|---|---|
| A1 | The issuer is `Jwt:PublicBaseUrl`: an absolute https URL with no query or fragment and the trailing slash trimmed. It is required when any client is configured, and never derived from the request. MCP tokens carry it in `iss`; existing tokens keep `Jwt:Issuer` | F3; AC7; `MCP-DISC`; `CLAUDE-TS`; IDENTITY-AND-ACCOUNTS.md §3 rule 2; REPO-BASELINE.md §8 (one source of truth per variable) |
| A2 | RFC 8414 metadata only, at `/.well-known/oauth-authorization-server`. The OIDC document and the JWKS stay byte-identical. The library's default configuration paths and JWKS endpoint are overridden (§4.5) | F4; AC7; `MCP-AUTHZ` Overview item 5; `CLAUDE-TS` |
| A3 | RS256 is required. If a client is configured and the algorithm isn't RS256, startup fails naming `Jwt:Algorithm` and `Jwt:PrivateKeyPem` | P5; ADR 0002's rule that "a bad key is a startup failure naming the setting"; library `ID0086` |
| A4 | The library's mandatory encryption key is a durable 256-bit symmetric key, supplied as a platform secret (`AuthorizationServer__EncryptionKey`) and generated from a documented, platform-neutral instruction. It is never an ephemeral or development credential. The rotation procedure is established during implementation and written into the runbook | P5; IDENTITY-AND-ACCOUNTS.md §10; `ID0085` |
| A5 | With no client configured, no AS endpoint, page or metadata exists, and the startup banner says so. The library's stores are registered and their tables exist regardless, so revocation and pruning still work after clients are removed | P8; IDENTITY-AND-ACCOUNTS.md §3 rule 4 (by analogy); AC7 |
| A6 | All AS wiring lives in `Extensions/AuthorizationServerExtensions.cs`. `Program.cs` gains calls, not configuration | P9; `DEVIATIONS.md` L20 |
| A7 | D2's overrides: serve only the RFC 8414 path; library JWKS off; access-token encryption off; PKCE required and `plain` removed; the existing signing key; a durable encryption key; reuse leeway 0; explicit lifetimes; `offline_access` advertised and allowed; library request logging at Warning | §4.5 |
| A8 | Configuration is authoritative for clients. The sync upserts configured clients and disables any removed from configuration. This deliberately overrides SERVICE-API-PATTERNS.md §8's "never overwrite", because §8 protects edits admins make at runtime, and v1 has none; meanwhile a stale row for a removed client would keep accepting its secret | AC5; SERVICE-API-PATTERNS.md §8 |
| A9 | The MCP token contract: `typ` `at+jwt`; `iss` as in A1; `aud` set to the single requested resource; `sub` = `ApplicationUser.Id`; `client_id`; `scope`, space-delimited; `jti`, `iat` and `exp`; and the enriched claims under the names existing tokens carry (AC7 establishes those names). ADR 0005 records it as the contract `AP-MCP-01` validates against | AC4; IDENTITY-AND-ACCOUNTS.md §1; `MCP-AUTHZ` "Token Handling" |
| A10 | Every refresh rebuilds claims from the user's current state and refuses deleted or locked-out users, as the existing refresh does | IDENTITY-AND-ACCOUNTS.md §1 ("a role change takes effect at the next token"); `TokenService.cs` L77–86 |
| A11 | Two interaction modes, chosen per deployment by `AuthorizationServer:Interaction:Mode`: `Hosted` (the default; authservice renders sign-in, 2FA and consent) or `External` (the consumer's frontend renders them). `External` requires `AuthorizationServer:Interaction:ExternalUrl`, an absolute https URL validated at startup, and the redirect is always built from that setting, never from the request. The mode is read through options at request time | B3's answer (Konrad, 2026-09-23, quoted in §5.1); the reading confirmed by Konrad the same day ("Yes, per deployment (Recommended)"); P8 (the default works with no frontend at all); SECURITY-REVIEW.md §8 (no open redirect) |
| A12 | The External handoff: a pending `AuthorizationInteraction` (CSPRNG handle stored hashed, a 10-minute expiry, what is needed to resume); an HttpOnly, SameSite=Lax cookie binding it to the browser that started it; a bearer-authenticated interaction API (get, accept, deny) on the authenticated trust level; on acceptance, a single-use 60 s ticket that authservice redeems atomically on its own origin before completing the authorization response itself | AC2; SECURITY-REVIEW.md §5 (CSPRNG for anything presentable as proof), §8 (attack scenarios); SERVICE-API-PATTERNS.md §2 (trust levels); the `OAuthExchangeCode` precedent (`OAuthExchangeCodeService.cs`), with redemption made atomic (§4.6) |
| A13 | authservice, not the frontend, decides what can be granted. Accepting confirms the requested scopes and resource, intersected with the client's allowed lists, and nothing more. The client's display name, redirect host and scope descriptions shown to the user come from authservice's configuration through the interaction API | SECURITY-REVIEW.md §8 (authorization enforced at the resource, not in the UI); FRONTEND-BFF.md §4 ("the middleware is UX, the services are the boundary") |

### 6.3 Accepted risks

None yet. An accepted risk names the person who accepted it (TICKET-ANALYSIS §6).

| Condition | Why it is unmet | Who accepted it | What it costs if the assumption is wrong |
|---|---|---|---|
| *(none)* | | | |

---

## 7. The gate

| # | Condition | Result | Evidence |
|---|---|---|---|
| 1 | Zero blocking questions outstanding | **Met** | B1 is closed (PR #65 landed the migration sets). B2 and B3 are answered by Konrad (2026-09-23), with his words recorded in §5.1. B3's answer brought in the External mode, whose design is recorded as decisions A11–A13 (confirm or overrule) rather than left as new questions |
| 2 | Every acceptance criterion has a complete row | **Met** | AC1–AC9 each name a layer, principles, guides and files (§2), and no row's last column carries a blocking question |
| 3 | The owning bounded context is named, and the ticket is one ticket | **Met** | The context is identity/authservice (P3). The migration baseline landed separately (PR #65). Both interaction modes live in authservice; a consumer that picks External builds its pages in its own repository, as its own work |
| 4 | Every compliance item at risk is kept, or covered by a recorded decision | **Met** | P4 is kept (committed migration sets, plus an incremental migration). P14 is decided (ADR 0005). Every other item in §3 is kept or covered by A1–A13 or an N assumption |

**Re-decided.** B3's answer changed the scope by adding a second interaction mode, so FEEDBACK.md §2 had a person re-decide the gate. Konrad did, on 2026-09-23: "Go: prompt + implement (Recommended)". The same day he confirmed A11's reading of B3 ("Yes, per deployment (Recommended)") and authorised merging the implementation once CI is green with no open review comments ("Yes, merge when green").

**Next:** `docs/analysis/AUTH-MCP-01.master-prompt.md`, generated from the latest revision, then `/implementation-phase`.

**Definition of done**, verbatim from brief §9, so the master prompt can carry it:

- The build is green.
- Every acceptance criterion is covered by a test at the layer holding the logic.
- The AC7 regression is proven.
- `quality-and-process:security-review` has been run over the diff with no open blocking finding.
- No file is touched outside the analysis table.

**Revision 4 re-test.** The four conditions are still met. §5.4's findings correct rows and notes without changing scope, adding a criterion or naming a new file, so FEEDBACK.md §2 asks for no re-decision. The master prompt generated from revision 3 is stale, and is generated again from this revision.

---

## Revision log

| Run | What changed | What closed it | Still open |
|---|---|---|---|
| 1, 2026-09-23 | First pass. §2 table for AC1–AC9 with row notes; 12 findings against the brief (F1–F12); blocking questions B1–B3; assumptions N1–N14; D2–D4 confirmed and D1 pending B2; decisions A1–A10; Q3 and Q4 struck; Q1 → B3, Q2 → N1, Q5 → A1 | The brief; `architecture-standards@e794863`; MCP specification 2026-07-28; `CLAUDE-AUTH`, `CLAUDE-TS`, `CLAUDE-HELP`; OpenIddict 7.7.1 source; the read-only exploratory round | B1, B2, B3; confirmation of N1, A1–A10 |
| 2, 2026-09-23 | Landed Konrad's answers: B1 closed (the migration sets landed in PR #65), B2 answered (amend ADR 0003 through ADR 0005), B3 answered as a scope change (both interaction modes). AC2 rewritten for both modes, files and notes; AC3, AC6, AC8 and AC9 unblocked; A11–A13 added; F7, flags 1/2/9, the §3 P4 and P14 rows, Q1 and D1 updated; out of scope restated. Gate re-tested: all four conditions met, re-decision requested | Konrad's answers in the session (2026-09-23); PR #65 | Konrad's re-decision of the gate; confirmation of N1 and A1–A13 |
| 3, 2026-09-23 | Recorded Konrad's re-decision of the gate (go), his confirmation of A11's reading of B3, and his authorisation to merge when green. Copied the brief's definition of done into §7, verbatim, for the master prompt to carry. Nothing else changed | Konrad's answers in the session (2026-09-23) | Confirmation of N1, A1–A10, A12 and A13 happens at PR review |
| 4, 2026-09-23 | Landed the implementation phase's findings I1–I9 (§5.4): the scope-description configuration shape (AC5 notes); four library facts in §4.5, with their overrides; the browser binding of a Hosted external sign-in (AC2 notes); `UseSetting` for the new project's hosts (AC8 notes, N14); three observations in §4.6 and N6's corrected citation. Gate re-tested, still met; no re-decision needed | The implementation phase's reading of `openiddict-core@7.7.1` and the code, before any production change; `SignInCharacterizationTests` | Confirmation of N1, A1–A10, A12 and A13 happens at PR review |

---

## Appendix A: acceptance criteria, verbatim from the brief

- **AC1 — Discovery.** authservice publishes authorization-server metadata (RFC 8414, and OIDC discovery if already served) listing the authorization and token endpoints, response type `code`, code challenge method `S256`, supported scopes, and a `jwks_uri` pointing at the existing key set.
- **AC2 — Authorization endpoint.** Supports `response_type=code` with PKCE: `S256` mandatory, `plain` rejected. Validates `client_id` and an exact `redirect_uri` match, round-trips `state`, and accepts the `resource` parameter (RFC 8707). Unauthenticated users go through authservice's existing sign-in, including external providers, and return to the flow. A consent step shows the client's display name and requested scopes.
- **AC3 — Token endpoint.** Exchanges a single-use, short-lived, PKCE-verified code for an access token and a refresh token. Supports the `refresh_token` grant with single-use rotation, as `IDENTITY-AND-ACCOUNTS.md` already requires.
- **AC4 — Access tokens.** Signed JWTs, not encrypted, signed with authservice's existing key material and `kid` so they validate against the existing JWKS. `aud` is bound to the requested resource, `sub` is the same user id existing consumers see, scopes are in the `scope` claim, and claims are enriched at issuance as today.
- **AC5 — Client registration v1.** Clients are pre-registered and confidential, defined in configuration: client id, display name, redirect URIs, allowed scopes, allowed resources. Secrets come from platform secrets only. The first client is Claude; its redirect URIs are taken from Anthropic's connector documentation at implementation time and held in configuration, not code.
- **AC6 — Revocation.** The existing global revocation (logout, password reset, account deletion) also revokes refresh tokens and authorizations issued to MCP clients. An endpoint lets a user revoke a single connected client.
- **AC7 — No regression.** Token issuance, refresh and validation for all existing consumers is unchanged. This is proven by the existing test suite passing untouched, plus a test asserting the pre-change token shape is still produced for existing flows.
- **AC8 — End-to-end test.** An automated integration test runs the full flow (authorize, sign-in, consent, code, token with PKCE, refresh) against a test resource and validates the token via JWKS. Negative cases: wrong verifier, reused code, mismatched `redirect_uri`, wrong audience, unknown client, `plain` challenge method.
- **AC9 — Documentation.** An ADR records the decisions in §8, and a runbook section "Registering an MCP client" shows the configuration shape with placeholder values.
