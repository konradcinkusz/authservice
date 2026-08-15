# ADR 0001 — What this repository is

**Status:** Accepted (closes issue #28)
**Date:** 2026-08-14

## Context

The README reads like a product — "bring it up as its own microservice and point any frontend
or backend at it over HTTP" — while the repository was built like a reference implementation:
no migrations, no versioning, no published artifact, no release, `EnsureCreated` at startup,
and a documented instruction to go and edit `InitializeDatabaseAsync` yourself if you want
production schema management.

That gap, not any individual missing feature, is the largest thing between the current state
and a public audience. Most other open issues have a different right answer depending on which
of the three the project is.

## Options

**A. Reference implementation to fork.** Migrations matter less, versioning is unnecessary, no
published image needed. Readability and documentation are the product — already this repo's
strongest assets. The README should say *fork this* and stop implying a stable HTTP contract.

**B. Deployable service you run as-is.** Requires migrations, a published image, API
versioning, a release cadence, and a support story for upgrades. Much more work, and an
ongoing obligation rather than a one-off.

**C. Library.** Rejected outright — the artifact is a service with a database and an HTTP
surface, not a package.

## Decision

**B, arrived at incrementally, with A's virtues preserved.**

The work in this change set commits to the parts of B that are cheap and reversible, and
declines the parts that create obligations before anyone has asked for them:

- Migrations: the *mode* is now configurable (`EnsureCreated` / `Migrate` / `None`) with a
  documented generation procedure, rather than a hard-coded `EnsureCreated` and a README note
  telling the reader to go and edit the source.
- Versioning: routes are served at `/api/v1/...` with the unversioned path kept as an alias,
  so there is a place to put v2 without breaking anyone.
- Upgrades: hand-written, idempotent DDL for both providers, so an existing deployment has a
  path forward.

What we do not take on: a support branch, a deprecation policy, or a promise that `/api/v1`
never changes before 1.0.

## Consequences

- The README must stop describing an upgrade path that does not exist and start describing
  the one that does.
- "Small and readable" stays the differentiator. Competing on feature count against Keycloak,
  Zitadel, Ory or Authentik is unwinnable and would destroy the actual advantage.
- Each further step toward B (published image, release cadence, deprecation policy) is a
  separate, deliberate decision rather than an implication of this one.
