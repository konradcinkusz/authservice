# ADR 0003 — Scope: stay small

**Status:** Proposed (tracks issue #30)
**Date:** 2026-08-14

## Context

`EXTRACTION.md` records that OpenIddict was configured but never exercised, and was removed
rather than shipped as an unused OAuth2/OIDC server surface. That was right for the extraction,
and it means this service deliberately is **not** an OAuth2/OIDC provider — it is a
purpose-built auth API with its own token format.

Anyone evaluating this repository is also looking at Keycloak, Zitadel, Ory Kratos/Hydra,
Authentik, Logto, SuperTokens, and ASP.NET Core Identity plus OpenIddict rolled by hand. All of
them do more, and most have more contributors.

## Decision

**Stay deliberately small, and say so.**

Competing on feature count is unwinnable. The underserved niche is real: a small, readable,
self-contained .NET auth service you can understand end to end in an afternoon. Keycloak is a
large Java application; Ory is several services; Zitadel needs its own infrastructure. This is
~5,000 lines of straightforward C# with a docker-compose file — and that *is* the feature, one
that gets destroyed by trying to match anyone's feature list.

### What that admits

Features that are table stakes for an authentication service, and whose absence is why an
evaluator leaves. This change set adds the ones already identified: email verification, TOTP
two-factor, a structured audit log, a data-export endpoint, and the missing half of the admin
lockout surface.

### What it excludes

- Becoming an OIDC provider (authorization code flow, consent screens, client registration,
  `/.well-known/openid-configuration`). That is Keycloak's and Ory's job, and re-adding
  OpenIddict would undo the extraction decision.
- SAML, LDAP or Active Directory federation.
- SCIM provisioning.
- A built-in admin UI.
- Passwordless, WebAuthn, magic links — reconsider individually if asked for, not as a set.
- Anything an application should own: domain models, billing, notifications beyond auth email.

## Consequences

- The README should lead with what this is (small, readable, forkable, complete for its scope)
  rather than with a feature list that invites the comparison it loses.
- Feature requests get measured against this ADR, which is why `CONTRIBUTING.md` states the
  scope boundary and the issue template asks contributors to confirm it.
- "We do not do that, here is what does" is a legitimate and expected answer.
