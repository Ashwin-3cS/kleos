---
title: "ADR 0011: The owner signs grants, not the gateway"
description: "The threat model was inconsistent, and ADR 0004 narrowed the inconsistency without removing it."
---

**Status:** accepted
**Date:** 2026-10-02
**Supersedes the grant-key half of:** ADR 0004

## Context

The threat model was inconsistent, and ADR 0004 narrowed the inconsistency without
removing it.

The gateway is **untrusted for confidentiality**. That is the reason the OAuth code
exchange happens inside the enclave, the reason TLS terminates in the TEE, and the
reason upstream hostnames are compile-time constants. The whole Phase 1
architecture is built on not trusting this process with plaintext.

The gateway was **fully trusted for authorization**. It held the grant signing key.
`POST /memory/scope/grant` minted a grant for any agent, over any owner's memory,
with any source list and any sensitivity ceiling — and the permission check would
then correctly honour it, because a grant *is* its signature.

So an operator could not read your mailbox and could mint themselves a grant over
your entire resolved record. Worse than reading the database directly, because it
is indistinguishable from legitimate access: the read log would show reads under a
grant, and nothing would say the owner never issued it.

ADR 0004 gave grants their own derived key, which narrowed blast radius between the
three token classes. It could not help here: the key is still on the host, and
whoever holds a signing key can sign.

## Decision

Grants are signed by a key the owner holds. The gateway verifies and cannot mint,
because there is no private key in the process.

- **`shared/src/grants.rs`** carries the format — `kgrant.v1.<payload>.<signature>`,
  Ed25519 over the payload bytes as received. In `shared` so the signer and verifier
  cannot disagree about what is covered.
- **Device keys are registered** (`POST /auth/device/register`), listed
  (`GET /auth/device/keys`) and revoked (`POST /auth/device/revoke`), all under an
  owner session. The private half never leaves the device.
- **`POST /memory/scope/grant` is gone.** Its absence is the feature, and a test
  asserts the route 404s.
- **`POST /memory/scope/introspect` verifies** against the registered key, checks
  revocation, and rejects a scope whose `owner_id` is not the key's owner.
- **The derived `grant` key is removed from `SigningKeys`.** Keeping key material
  for a purpose nothing uses would imply a capability this process no longer has.
- **`kleos-device`** is the client side, because grants now need a signer and the
  smoke script is not one.

### Revocation, as a side effect

Revoking a device key invalidates every grant it ever signed. The README has listed
"a grant cannot be revoked before it expires" as a sharp edge since grants existed;
this is the first lever against it. It is coarse — per device, not per grant — and
deliberately terminal: re-registering a revoked key does **not** un-revoke it,
because that would make revocation meaningless.

## What this prevents, and what it does not

Precisely, because this is easy to overclaim and the overclaim would be worse than
the original gap.

**Prevented: silent minting.** There is no key on the host that produces a valid
grant. The attack is gone, not mitigated.

**Not prevented: key substitution.** Registration is authorised by an owner session,
and owner sessions are still host-signed. A host that forges a session can register
a key of its own and sign with it. What it cannot do is that *invisibly*:

- the registration is a stored, timestamped row;
- `GET /auth/device/keys` shows every key to the owner, revoked ones included, so a
  client that remembers its own key id can see one it never created;
- reads under that grant appear in the read log by fingerprint (ADR 0005), so an
  owner sees activity attributed to a grant they did not issue.

So the honest description is: **an undetectable attack has become a detectable
one.** That is a real increment and it is not the end state.

Making it impossible requires a verification root the operator cannot substitute.
Two candidates, both out of scope here: an enclave key gated on attestation (the
standard Nitro pattern is a KMS policy that releases key material only to a measured
enclave, which this repo has not built), or an on-chain grant registry — which is
already the stated direction, with `Scope` shaped to become that object. `verify_grant`
takes its keys through a closure specifically so that swap is a change of one caller.

The deeper fix is to the **session**, not the grant: as long as owner authentication
is host-signed, the host can forge consent for anything an owner session authorises.
Device keys are the material that fixes it — a session could become a client-signed
assertion verified against the same registered key — and that is the natural next
step now that the keys exist.

## Alternatives

- **Three independent secrets, or rotating the grant key more often.** What ADR 0004
  did, and it cannot address an attacker who holds the key by design.
- **Mint grants inside the enclave.** Moves the key off the host, and does not help
  alone: the enclave mints for whichever owner the request names, the host authenticates
  that request with a session key it holds, so the host still gets any grant it wants.
  Fixing grants without fixing sessions is incomplete whichever component signs.
- **Keep gateway minting and log every mint.** A detection-only answer, strictly weaker
  than this one, and it was the fallback if device keys proved too large. They did not.
- **Go straight to on-chain grants.** The end state, and it brings a wallet, a chain
  dependency and an on-chain policy object into a system that has no users yet. The
  format here is deliberately the same shape, so that migration is a change of
  verification root rather than of protocol.
- **Asymmetric JWTs (EdDSA) instead of a bespoke token.** Standard, and it would mean
  reconciling fastcrypto's raw Ed25519 keys with the JWT library's expected encodings
  for a token nothing outside this system parses. The compact format is 40 lines,
  versioned, and verifies over the received bytes without a library's help.

## Consequences

- **Every outstanding grant is invalid.** Acceptable now, with no users and hour-long
  TTLs; it would need a dual-verification window after a beta.
- The orchestrator can no longer ask for a grant, and `GatewayClient.grant_scope` is
  gone. Callers that need one sign it, which means agents are issued grants by the
  owner out of band — which is what a capability is.
- Losing a device key is now a way to lose access to one's own memory. Real, and the
  reason `keygen` refuses to overwrite; a product needs multiple registered devices
  and a recovery path, neither of which exists.
- The in-memory device key store loses registrations on restart, which for this store
  is worse than for the sealed token store: forgetting a key does not lose a
  convenience, it invalidates every grant that key signed. Set a real store for
  anything but a mock run.
- `POST /auth/device/register` is now the most security-sensitive route in the
  gateway, since it decides what the verification root is. It is the right place to
  add an enclave attestation over the binding when that lands.
