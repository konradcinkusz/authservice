# ADR 0002 — Token signing: HS256 today, RS256 when there is a second consumer

**Status:** Proposed — **not implemented** (tracks issue #29)
**Date:** 2026-08-14

## Context

Tokens are signed with symmetric HMAC-SHA256 using `Jwt:SecretKey`, and the README tells
downstream services to validate them with that same secret.

With a symmetric key, verifying and signing are the same capability. Every service that can
validate a token can also mint one — for any user, with any roles, including `SuperAdmin`,
with any organization claims. The blast radius grows with every service added: a read-only
reporting service that only needs to know who the caller is ends up holding the keys to the
whole identity system, and one leaked config file in the least important service compromises
everything.

There is also no rotation story. Rotating `Jwt:SecretKey` means updating every service
simultaneously and invalidating every outstanding token, with no overlap period.

## Options

**A. Keep HS256.** Simplest thing that works. Correct while AuthService is the only thing
that mints *and* the only thing that validates, or where every validator is equally trusted.

**B. RS256 (or ES256) with a `/.well-known/jwks.json` endpoint.** AuthService holds the
private key and is the only thing that can issue. Downstream services fetch the public key and
can only verify. Rotation becomes routine: publish the new key alongside the old, sign with the
new, retire the old once outstanding tokens have expired. This is what every identity provider
does, for exactly these reasons.

**C. Support both, chosen by configuration.** Superficially attractive, and considered for this
change set. Rejected for now: it is not the code that is hard, it is the key material. RS256
needs somewhere durable to keep a private key — a mounted secret, a new table, or a KMS — and
picking that is an infrastructure decision with real consequences. Shipping a config flag that
generates an ephemeral key at startup would be worse than not shipping it, because every
restart would silently invalidate every token.

## Decision

**Stay on HS256 for now; move to B before the second independent consumer exists.**

The trigger is concrete rather than aspirational: the first time a service that is not
AuthService needs to validate a token, HS256 stops being adequate, because that is the moment
"can verify" and "can forge" stop being the same trust level in practice.

This change set deliberately does **not** implement RS256. It does reduce the surrounding
risk:

- The key is now validated at startup for length (≥ 256 bits), instead of failing from inside
  the signing call at the first successful login.
- Two-factor challenge tokens use a separate audience, so the signing key's authority is at
  least partitioned by purpose.
- `SECURITY.md` states the symmetric-key posture plainly rather than leaving evaluators to
  infer it.

## Consequences

- The README must say, without hedging, that any service given `Jwt:SecretKey` can mint tokens
  for any user — so only give it to services you would trust to do that.
- When B lands it is a breaking change for every downstream validator, and wants the `/api/v2`
  slot or a flag day.
- Until then, rotating the secret is a coordinated outage. That is the cost being accepted.
