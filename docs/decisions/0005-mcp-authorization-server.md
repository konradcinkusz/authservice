# ADR 0005 — An OAuth 2.1 authorization server for MCP connector clients

**Status:** Accepted — **implemented** (AUTH-MCP-01). Amends [ADR 0003](0003-scope.md).
**Date:** 2026-09-23

## Context

MCP clients — Claude's web, desktop and mobile apps first — reach an MCP server on a user's
behalf through OAuth: the MCP Authorization specification (revision 2026-07-28) has the client
discover an authorization server, send the user through the authorization-code flow with PKCE,
and present the access token it gets to the MCP server. `AP-MCP-01` (the AureliusPromptus MCP
connector) needs an authorization server for its users, and those users already live here.

ADR 0003 excluded exactly this: "authorization code flow, an authorization endpoint, a
standards-shaped token endpoint, consent screens, client registration, introspection … re-adding
OpenIddict would undo the extraction decision." ADR 0004 restated the exclusion for
third-party, browser-facing clients, and Claude is one.

The full analysis, with every source read and every finding, is
[`docs/analysis/AUTH-MCP-01.md`](../analysis/AUTH-MCP-01.md). This ADR records what was decided.

## Decision

**authservice becomes an OAuth 2.1 authorization server for pre-registered MCP clients,
built on OpenIddict, and only when a deployment configures one.** With
`AuthorizationServer:Clients` empty — the default — no endpoint, page or metadata document
exists, and nothing about the service changes.

### The brief's decisions, as they stand

| | Decision | Status |
|---|---|---|
| D1 | Extend authservice rather than add Keycloak or a hosted IdP; it stays the only identity provider | Confirmed, as a knowing amendment of ADR 0003 (Konrad, 2026-09-23: "Amend via ADR 0005 (Recommended)") |
| D2 | Use a maintained library, not hand-rolled endpoints | Confirmed: OpenIddict 7.7.1, with the overrides below |
| D3 | Static pre-registered clients, no dynamic registration | Confirmed. Claude's connector settings take a client id and secret under "Advanced settings" |
| D4 | Resource servers validate JWTs through the JWKS; no introspection | Confirmed. Revocation stops refreshes, not tokens already issued, which is why MCP access tokens live 15 minutes |

**Why OpenIddict.** It is the maintained open-source .NET authorization-server library
(Apache-2.0). Duende IdentityServer is commercially licensed, which does not fit an MIT image
other systems deploy. The library's defaults for a third-party client are the right ones —
`iss` in authorization responses, exact redirect matching, per-client resource permissions,
token-chain revocation — and those are exactly where hand-rolled servers go wrong. A
hand-rolled server in the style ADR 0004 proposes was considered and rejected: the two things it
would simplify are recovered anyway, by one revocation operation spanning both token stores and
one shared claim builder. OpenIddict was removed at extraction for being unused
(`EXTRACTION.md`); it now has a use.

### ADR 0003, amended

ADR 0003's first exclusion no longer covers **pre-registered MCP connector clients**. For them
this service has an authorization endpoint, a token endpoint, consent, and client registration
from configuration. The rest of ADR 0003's list stands: no OpenID Connect provider features
(no identity tokens, `userinfo` or end-session), no introspection or client-facing revocation
endpoint, no dynamic client registration, no admin UI, no SAML, LDAP or SCIM.

### How the server is shaped

| # | Decision |
|---|---|
| A1 | The issuer of MCP tokens is `Jwt:PublicBaseUrl` — an absolute https URL, trailing slash trimmed, required when any client is configured, never derived from the request. Existing tokens keep `Jwt:Issuer`. Two issuers, one key, one JWKS |
| A2 | RFC 8414 metadata only, at `/.well-known/oauth-authorization-server`. The OIDC discovery document and the JWKS are byte-for-byte what they were; the library's own discovery and key-set endpoints are off |
| A3 | RS256 is required. A deployment with a client configured and HS256 signing fails at startup naming `Jwt:Algorithm` and `Jwt:PrivateKeyPem` |
| A4 | The library's mandatory token-encryption key is a durable 256-bit key from a platform secret (`AuthorizationServer__EncryptionKey`), never an ephemeral or development one. Retired keys go in `AuthorizationServer:PreviousEncryptionKeys` and only decrypt, so rotation is rolling |
| A5 | No client configured, no authorization server: no endpoint, page, metadata or API, and the startup banner says so. The library's stores and tables exist regardless, so revocation and pruning keep working |
| A6 | All wiring lives in `Extensions/AuthorizationServerExtensions.cs`; `Program.cs` gains two calls and a banner field, plus the registration of `SignInFlow`, which the login API shares |
| A7 | The library's defaults that had to change: only the RFC 8414 path; no library JWKS; access tokens not encrypted; PKCE required, `S256` only; the existing signing key; a durable encryption key; refresh-token reuse leeway 0; explicit lifetimes; `offline_access` advertised and allowed; library logging capped at Warning |
| A8 | Configuration is authoritative for clients: `AuthorizationClientSync` creates or updates each configured client at startup, secret included, and deletes any client no longer configured together with its authorizations and tokens. This deliberately departs from SERVICE-API-PATTERNS.md §8's "never overwrite", which protects runtime admin edits that v1 does not have |
| A9 | The token contract, below |
| A10 | Every refresh rebuilds the claims from the user's current state and refuses deleted or locked-out users, as the existing refresh does |

### The token contract (A9)

What `AP-MCP-01` validates against. An MCP access token is a compact JWS, never a JWE:

- header: `alg` `RS256`, `kid` the key's RFC 7638 thumbprint (the same `kid` the JWKS publishes),
  `typ` `at+jwt`;
- `iss`: `Jwt:PublicBaseUrl`, no trailing slash — the same string the metadata's `issuer` carries;
- `aud`: the one resource the token was requested for, as the client sent it;
- `sub`: `ApplicationUser.Id` — the same user id existing consumers see;
- `client_id`, `scope` (space-delimited), `jti`, `iat`, `exp` (15 minutes by default);
- the claims existing tokens carry, from the same builder and under the same names:
  `email`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`,
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`,
  `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` (a string, or an array for several roles), `organization`,
  and `organization:{id}:role`.

Nothing else: the library's private `oi_*` claims (internal ids of the authorization, the
presenter and the token entry), which it otherwise leaves in the JWT, are removed.
`TokenContractCharacterizationTests` pins the existing tokens' names; `AccessTokenTests` holds MCP
tokens to them. A resource server validates signature (from the JWKS the metadata names), `iss`,
`aud` against its own canonical URI, and `exp`, and enforces `scope` itself — authservice's own
API rejects an MCP token, because its audience is not `Jwt:Audience`.

### Who renders sign-in and consent (A11–A13)

Asked where sign-in and consent should render, Konrad answered (2026-09-23) that the consumer
should be able to choose, and that authservice should provide pages of its own as well as
supporting the consumer's frontend; he confirmed the choice is made per deployment. (The analysis,
§5.1, keeps his words verbatim.) So there are two modes, chosen by
`AuthorizationServer:Interaction:Mode` and read at request time:

**Hosted** (the default). authservice renders the pages itself — the first HTML this service has
ever served. Sign-in (`/connect/signin`) runs the same decision as `POST /api/v1/auth/login`,
extracted into `SignInFlow` with characterisation tests written first; external providers go
through the existing `ExternalAuthController`, unchanged, and land on `/oauth/callback`; the
second factor has its own page; consent shows the client's display name, where the browser will
be sent, and each scope's configured description, and is remembered per user and client. The
pages hold a session in the authorization server's own cookie — never `Identity.Application`,
which the external callback signs into with the second factor bypassed — and send the
SECURITY-REVIEW.md §4 header set with `frame-ancestors 'none'` and no script at all.

**External.** The consumer's frontend renders sign-in and consent with the flows it already has.
The protocol:

1. The client sends the browser to `/connect/authorize`; the library validates the request.
2. authservice records a pending `AuthorizationInteraction` — a hashed CSPRNG handle, the request
   to resume, a 10-minute expiry — sets an HttpOnly, Secure, SameSite=Lax cookie binding it to
   this browser, and redirects to `<Interaction:ExternalUrl>?interaction=<handle>`. The URL comes
   from configuration, never the request.
3. The frontend's BFF calls `GET /api/v1/oauth/interactions/{handle}` with the user's bearer token
   and gets the client's name, the redirect host, the scopes with their descriptions, and the resource.
4. On the user's decision it calls `POST …/{handle}/accept` or `…/deny` with the same token.
   authservice binds the interaction to that user — the first decision wins, atomically — and
   returns a `redirectTo` on its own origin carrying a single-use, 60-second ticket.
5. The browser follows it. authservice redeems the ticket with one conditional UPDATE, checks it
   belongs to the interaction this browser's cookie names and that the request is the one that
   was paused, and completes the authorization response itself, with a code and `iss` — or with
   `access_denied`.

authservice, not the frontend, decides what is granted (A13): accepting confirms the requested
scopes and resource, which the library has already checked against the client's permissions, and
nothing more; an accept that names anything else is refused. The account must still be in good
standing (not deleted or locked out, email confirmed where required, current Terms and Privacy
accepted). The browser-binding cookie is what defeats login CSRF: without it, an attacker could
finish a victim's flow with a ticket issued to the attacker's own account, and the victim's client
would be connected to the attacker's data. A Hosted external-provider sign-in is bound to its
browser the same way, by a nonce carried in the return URL and in a cookie.

The consumer's pages are the consumer's work, in its own repository;
[`DEPLOYMENT.md`](../DEPLOYMENT.md#registering-an-mcp-client) documents the contract they call.

### The answers that shaped it

- **Where the schema change lands (B1).** The initial migration sets landed first, on their own
  (PR #65, issue #17). The authorization server's tables arrive as the `AddAuthorizationServer`
  migration, for both providers.
- **Whether ADR 0003 is amended (B2).** Yes, knowingly, through this ADR.
- **Where sign-in and consent render (B3).** Both, per deployment, as above.

## Consequences

- **Revocation is one operation across both stores.** `TokenService.RevokeRefreshTokensAsync` — called
  from logout, password reset and change, turning off 2FA, the admin paths, self-delete and the reaper
  — now also revokes the user's MCP authorizations and tokens. A user can disconnect one client with
  `DELETE /api/v1/auth/connected-clients/{clientId}`, which also forgets their consent. Permanent
  deletion deletes the library's rows, which carry the user id with no foreign key.
- **Key rotation must keep the previous key longer.** The library signs the codes and refresh tokens
  it issues with the RS256 key too. The analysis could not tell whether a rotation would kill every
  MCP connection (F8); the tests settled it: with the retired public key in
  `Jwt:PreviousPublicKeyPem`, a refresh token issued before the rotation still refreshes; without
  it, every connection ends. With the authorization server on, keep the previous key for a
  refresh-token lifetime (30 days by default), not an access-token lifetime.
- **The database holds no token that could be presented.** Refresh and access tokens are held by the
  client, with only a status row here. An authorization code is a reference whose hash is the lookup
  key; its encrypted payload is stored, but is useless without the client's secret and the PKCE
  verifier, for its 60 seconds.
- **Rate limiting is per client at the token endpoint.** Every Claude user's token and refresh calls
  come from Anthropic's egress range, so the endpoint is taken out of the global per-IP limiter and
  limited per authenticated client instead (`TokenRequestsPerMinute`), in the endpoint itself,
  because clients authenticate after the rate-limiting middleware runs. The authorization endpoint
  and the pages use the existing per-IP `auth` policy; the interaction API the `api` policy.
- **Size.** 7,822 lines of C# under `src/` (migrations excluded) before; 10,387 after, 2,457 of them
  in the authorization server's controllers, pages, options, sync and wiring, plus 219 lines of
  Razor markup. ADR 0003's "readable in an afternoon" is harder than it was, and this is the largest
  single addition since the extraction. The feature is off by default, and every line of it sits in
  files named for it.
- **"MCP" means two things in this repository.** The `integrate` server (`src/AuthService.Mcp`)
  is an MCP server this repository ships; the authorization server issues tokens *to* MCP clients
  for MCP servers other projects run. The README and the runbook say which they mean.

### Residual risks, accepted with the change

- **The token endpoint has no pre-authentication limit.** The per-client limit counts requests the
  library has already accepted; a flood of requests with a valid client id and a wrong secret costs a
  PBKDF2 verification each, from any number of addresses. The login endpoint has the same exposure
  behind its per-IP limit. The platform's edge is the backstop.
- **Concurrent refreshes may trip replay detection (N3).** With a reuse leeway of zero, a client that
  refreshes twice with the same token revokes its own chain and must reconnect. Claude refreshes on a
  401 and ahead of expiry; `oauth.refresh.reuse_detected` audit rows will show whether it happens,
  and the leeway is one setting.
- **An issued access token cannot be recalled (D4).** Revocation stops the next refresh; the token in
  hand works for up to 15 minutes.
- **The pages' cookies depend on ASP.NET Core Data Protection**, as the existing external sign-in's
  do. A restart in the middle of someone's sign-in makes them start again; more than one instance
  needs a shared key ring, or sticky sessions.
- **A failed external sign-in started on a Hosted page ends on the product frontend's login page**,
  because `ExternalAuthController` sends failures to `OAuth:ErrorRedirectBaseUrl` and was left
  unchanged by design. And with the legacy `Auth:AllowTokensInOAuthRedirect` on, the pages cannot
  resume an external sign-in at all; they refuse it.
