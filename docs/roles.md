# Roles and permissions

Two independent role systems exist. They do not interact.

- **Platform roles** — `SuperAdmin`, `Admin`, `User`. Stored in ASP.NET Core Identity, seeded
  by `DbSeeder`, and used to authorize `/api/v1/admin/*`.
- **Organization roles** — `Owner`, `Admin`, `Member`. Stored per membership in
  `OrganizationMemberships`, scoped to a single organization.

A platform `SuperAdmin` has no rights inside an organization they are not a member of. An
organization `Owner` has no platform admin rights. That separation is deliberate: the admin
surface is for operating the service, not for reaching into tenants.

## Platform roles

| Capability | SuperAdmin | Admin | User |
| --- | :-: | :-: | :-: |
| List users, view user detail | ✅ | ✅ | ❌ |
| List organizations, list any organization's invitations | ✅ | ✅ | ❌ |
| Platform statistics | ✅ | ✅ | ❌ |
| Lock / unlock a user | ✅ | ✅ | ❌ |
| Revoke a user's sessions | ✅ | ✅ | ❌ |
| Soft-delete / restore a user | ✅ | ✅ | ❌ |
| Read the audit log | ✅ | ✅ | ❌ |
| Assign / remove platform roles | ✅ | ❌ | ❌ |

Granting and revoking platform roles is `SuperAdmin` only, because it is the one operation
that can manufacture more admins.

Both role-change endpoints revoke the target's refresh tokens, so a role change takes effect
on the next request rather than up to one access-token lifetime later.

Revoking a user's sessions also ends every MCP connection the user has made
([ADR 0005](decisions/0005-mcp-authorization-server.md)). That holds for every path that
revokes: the admin paths above, and the user's own logout, password change or reset, turning
off 2FA, and account deletion. The user's authorizations are revoked, which also forgets their
consent, together with every refresh token issued under them. An MCP access token already
issued runs out on its own, within `AuthorizationServer:AccessTokenLifetimeMinutes`.

The first `SuperAdmin` comes from `InitialAdmin:Email` / `InitialAdmin:Password` at startup,
and only when no `SuperAdmin` exists yet.

## Organization roles

| Capability | Owner | Admin | Member |
| --- | :-: | :-: | :-: |
| View the organization and its members | ✅ | ✅ | ✅ |
| Update name / description / image | ✅ | ✅ | ❌ |
| Invite a member as `Member` or `Admin` | ✅ | ✅ | ❌ |
| Invite a member as `Owner` | ✅ | ❌ | ❌ |
| List / resend / revoke invitations | ✅ | ✅ | ❌ |
| Remove a `Member` or `Admin` | ✅ | ✅ | ❌ |
| Remove an `Owner` | ✅ | ❌ | ❌ |
| Change a member's role | ✅ | ❌ | ❌ |
| Transfer ownership | ✅ | ❌ | ❌ |
| Leave the organization | ✅¹ | ✅ | ✅ |
| Soft-delete / restore / hard-delete the organization | ✅ | ❌ | ❌ |

¹ Not while they are the only `Owner`.

### Invariants

**An organization always has at least one Owner.** Every path that could remove the last one
is guarded, and all of them count owners through the same helper:

- `DELETE /members/{userId}` refuses to remove the last `Owner`.
- `DELETE /members/me` refuses to let the last `Owner` leave.
- `PUT /members/{userId}/role` refuses to demote the last `Owner`.

Without the third guard an organization could be left with zero Owners, and every recovery
path — promote, delete, restore, hard-delete — requires `Owner`. There is no admin escape
hatch for that state; recovery would mean direct database access.

**Nobody can grant a role above their own.** An `Admin` may invite at `Admin` or `Member` but
not at `Owner`. Without that, an `Admin` invites a second address they control as `Owner`,
accepts it, and holds rights the role model explicitly denies them.

**Only verified addresses can accept an invitation.** Invitations are matched on email address,
so an unverified address would otherwise be enough to join an organization that invited someone
else. Enforced when `Auth:RequireConfirmedEmail` is on, which defaults to on wherever the
deployment can actually send email.

### Ownership transfer

`POST /api/v1/organizations/{id}/transfer-ownership` with `{ "toUserId": "..." }` promotes an
existing member to `Owner` and steps the caller down to `Admin` — or to `Member` with
`"retainAdminRole": false`. Both changes commit together, so the organization is never
momentarily ownerless or briefly double-owned.

## MCP connector clients

These endpoints exist only once an MCP client is configured
([ADR 0005](decisions/0005-mcp-authorization-server.md)). None of them takes a platform or
organization role. Each acts for the signed-in user, on that user's own account.

| Endpoint | Called by | Access |
| --- | --- | --- |
| `GET /.well-known/oauth-authorization-server` | Anyone | Anonymous. Public metadata |
| `GET/POST /connect/authorize` | The user's browser, sent by a registered client | Anonymous, because it is where sign-in starts. It serves only registered clients, redirects only to their exact redirect URIs, and requires PKCE |
| `POST /connect/token` | A registered client | The client's secret, plus a code and its PKCE verifier or a refresh token. Rate-limited per address before the client authenticates, then per client and per user |
| `/connect/signin`, `/connect/2fa`, `/connect/consent`, `/oauth/callback` (Hosted mode) | The user's browser | Anonymous, because these pages are the sign-in. Every form carries an antiforgery token |
| `GET /api/v1/oauth/interactions/{handle}`, `POST …/accept`, `…/deny` (External mode) | The consumer's BFF, with the user's token | Any authenticated user holding the handle. Deciding also needs a token from a session that has not been revoked. The first user to decide an interaction is the only one who can. A decision grants only what the client asked for and is allowed |
| `DELETE /api/v1/auth/connected-clients/{clientId}` | The user | Any authenticated user, for their own connections only |

## Token claims

Tokens carry organization membership so downstream services can authorize without calling back:

```
organization                      = <organizationId>     (one per membership)
organization:<organizationId>:role = Owner | Admin | Member
```

Tokens issued to MCP clients carry the same claims, rebuilt from the user's current state on
every refresh. Membership changes reach a token on the next refresh. Where a change must take
effect immediately, revoke the user's refresh tokens — `POST /api/v1/admin/users/{id}/revoke-sessions`,
which ends their MCP connections as well.

## Adding an endpoint

If you add an endpoint to `OrganizationsController`, `AdminController` or the authorization
server, add a row to the matching table above in the same pull request. The permission model
previously existed only implicitly across ~800 lines of controller, which is how the two gaps
fixed above went unnoticed.
