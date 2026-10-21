---
title: "ADR 0004: Derive per-purpose signing keys from one root secret"
description: "The gateway signs three unrelated things:"
---

**Status:** accepted
**Date:** 2026-10-01

## Context

The gateway signs three unrelated things:

- **owner session tokens** — proof that a human authenticated via the enclave,
- **agent grant tokens** — the capability that governs every memory read,
- **the OAuth `state` parameter** — CSRF protection on the consent redirect.

All three were signed with `SESSION_JWT_SECRET`. `OAUTH_STATE_SECRET` existed
but defaulted to it ("falls back to the session secret only so local dev needs
one variable"), and grants never had a key of their own at all — `scope_grant`
and `scope_introspect` both reached for `config.session_jwt_secret`.

A previous commit fixed the *confusion* half of this: each token now declares a
`typ` and is rejected when presented as another, replacing an accident of the
struct shapes with an actual check. That was the right fix and it is not this
one.

What remained is **blast radius**. One key means anything that can read it can
mint all three token types. A leaked OAuth state secret — the lowest-value of
the three, protecting a redirect — could forge an owner session. A leaked
session key could mint agent grants over any owner's memory, with any scope and
any sensitivity ceiling, and the permission check would correctly honour them
because a grant *is* its signature. For a system whose entire access-control
story is "the grant is the capability", a single key behind all three is the
weakest link in the design.

## Decision

Derive three independent keys from one root secret:

```
key(purpose) = hex(HMAC-SHA256(root, "kleos/signing/v1/" || purpose))
```

for `purpose` in `session`, `grant`, `oauth_state`. The root comes from
`SIGNING_ROOT_SECRET`, falling back to `SESSION_JWT_SECRET` so existing
deployments keep working.

**Derived rather than three separate secrets.** Three independent env vars is
the obvious design and it hands the operator a worse option: paste the same
value into all three and be exactly where we started, with nothing to detect
it. One root cannot be misconfigured that way. It also keeps provisioning a
single `openssl rand -hex 32`, which is what makes a strong secret the easy
path rather than the diligent one.

**HMAC rather than a prefix hash.** `SHA256(label || root)` would be shorter
and is vulnerable to length-extension; HMAC is the standard construction and
gives the property the whole module exists for — a key recovered from a token
signed with it reveals neither the root nor its two siblings.

**Versioned domain string.** `kleos/signing/v1/` so a future change to the
derivation can coexist with tokens signed under the old scheme during a
rollover.

**Per-purpose overrides.** `SESSION_SIGNING_KEY`, `GRANT_SIGNING_KEY`,
`OAUTH_STATE_SIGNING_KEY` each override one derived key. This is what makes
rotating a single key possible: invalidating every live owner session because a
grant key leaked would be an availability cost with no security benefit. The
historical `OAUTH_STATE_SECRET` is accepted as an alias, so it is now an
override of a derived key rather than a value that silently defaults to the
session secret.

**Refuse to boot on a bad root in `nitro` mode.** `Config::from_env` is now
fallible. In `nitro` it rejects the public development default
(`dev-insecure-secret-change-me`) and any root under 32 characters — 32 bytes
is the derivation's output width, so a shorter root caps the entropy of all
three keys below what they can carry. In mock mode it warns instead, because
making `./scripts/run_local.sh` require a secret is a cost with no local
benefit. A gateway that boots with a publicly known signing secret looks like
it is working, which is worse than one that refuses to start.

## Alternatives

- **Three independent env vars.** Rejected above: it permits the exact
  misconfiguration it is meant to prevent, and triples provisioning effort for
  no gain over derivation.
- **Asymmetric keys (Ed25519, per purpose).** The real destination, and
  genuinely better: the orchestrator could verify a grant without holding
  anything that can mint one, and `fastcrypto`'s `Ed25519KeyPair` is already in
  the tree for the enclave's attestation signing. Deferred because grants are
  due to become on-chain objects whose verification is a signature check
  against an owner's key — that redesign subsumes this, and doing an interim
  asymmetric migration first would be work thrown away. Noted as the direction.
- **Keep one key and rely on `typ`.** Already the status quo. `typ` stops a
  cooperating caller from mixing token types; it does nothing about an attacker
  who holds the key and can set `typ` freely.
- **Move signing into the enclave.** Would mean the host could not mint a grant
  at all, which is a real improvement to the trust story. Rejected for now
  because it puts session issuance on the VSOCK path for every request and
  grows the TCB with something that is not a confidentiality operation — the
  test the enclave's surface is held to.

## Consequences

- **Every existing token is invalidated** by this deploy, including live owner
  sessions and any outstanding agent grant: the keys that sign them changed.
  Acceptable now, when there are no users and grant TTLs are an hour; it would
  need a dual-verification window after the step 7 beta.
- `Config::from_env` returns `Result`, so `main` propagates it. One call site.
- A deployment that was relying on `SESSION_JWT_SECRET` keeps working, with its
  value now used as the root rather than directly as a signing key.
- The three keys are hex strings slotted into the existing `&str` secret
  parameters, so `jsonwebtoken` usage is unchanged — HS256 over a 32-byte key
  presented as 64 hex characters.
- Still symmetric: whoever holds the grant key can mint grants. The real
  mitigation is asymmetric signing or on-chain grants, both out of scope here.
  This narrows the blast radius; it does not change the trust model.
- Nothing in the enclave is affected. It has its own config and shares no
  secret with the gateway, which is the property that makes the confidentiality
  argument work and is untouched by this.
