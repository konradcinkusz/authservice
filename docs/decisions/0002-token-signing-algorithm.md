# ADR 0002 — Token signing: RS256 with a published JWKS

**Status:** Accepted — **implemented** (closes issue #29)
**Date:** 2026-08-14 (superseded the deferral on the same date, when the trigger fired)

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

**B — RS256 with a published JWKS.**

The previous revision of this ADR deferred B behind a deliberately concrete trigger: *"the
first time a service that is not AuthService needs to validate a token."* **That trigger has
now fired** — a downstream service validates tokens minted here.

That is the moment "can verify" and "can forge" stop being the same trust level in practice.
Under HS256 the second service, whatever it does, holds the ability to mint `SuperAdmin`
tokens for this identity system — and the blast radius grows with every service added after
it.

The independent constraint is that
[`architecture-standards`](https://github.com/konradcinkusz/architecture-standards) does not
treat this as optional. Its reference architecture lists token signing as **"Asymmetric +
JWKS — P5; required, not aspirational"**, and its compliance checklist reads *"exactly one
service holds a signing key; all others validate against its JWKS endpoint."* Shipping the
two-service topology on HS256 would have been a knowing deviation from the standard this
project is measured against.

### What was built

- `JwtSigningKeys` resolves key material once, at startup, and validates it there — a bad key
  is a startup failure naming the setting, not a first-login exception.
- `Jwt:Algorithm` selects `HS256` or `RS256`. Unset, it is **inferred**: configuring a private
  key selects RS256. That asymmetry is deliberate — the dangerous mistake is supplying a
  keypair and silently continuing to sign symmetrically, so that combination cannot occur.
- `GET /.well-known/jwks.json` publishes the public half, with a `kid` derived from the key
  itself (RFC 7638 thumbprint) rather than configured. A rotated key therefore cannot reuse
  its predecessor's id, which is precisely when an ambiguous key set would do most damage.
- `GET /.well-known/openid-configuration` publishes just enough metadata for a consumer to set
  `JwtBearerOptions.Authority` and nothing else. It advertises no `response_types`: this is key
  discovery, not a claim to be an OIDC provider (ADR 0003).
- Rotation is a rolling change, not a flag day. `Jwt:PreviousPublicKeyPem` keeps a retired key
  in the validation set and in the JWKS while tokens signed with it are still alive; only the
  current key ever signs.

### On option C

The earlier revision rejected "support both" on the grounds that the hard part is key material,
not code. That reasoning stands, and the shipped design respects it: there is no mode that
generates an ephemeral keypair at startup, because a restart would silently invalidate every
outstanding token. HS256 survives only as the zero-ceremony path for `docker compose up` and
the test suite, where the service is the sole validator. Both paths are exercised by tests.

## Consequences

- **HS256 remains the default when no private key is configured.** The quick start does not
  change, and neither does the test suite. What changes is that a deployment with a second
  consumer is expected to configure a keypair, and logs a warning at startup if it has not.
- **The symmetric key is never published.** Under HS256 the JWKS is an empty key set rather
  than a 404 — a consumer gets "no keys I can use" instead of "no JWKS here" — and a test
  asserts the secret does not appear in the document.
- **Consumers need no shared secret.** A downstream service points `MetadataAddress` at this
  service's discovery document and holds no key material at all.
- **Key material is now an operational concern**, as predicted. It is a PEM in a platform
  secret (`fly secrets set Jwt__PrivateKeyPem=...`), which the escaped-newline handling in
  `JwtSigningKeys` exists to make survivable.
- **`iss` is still the bare string `AuthService`, not a URL.** The discovery document reports
  that value rather than the service's own origin, so a consumer validating `iss` against
  discovery gets a match. Changing it to a URL would be a breaking change for every issued
  token and is not worth doing on its own.
