---
title: "ADR 0029: A local install has an owner of its own"
description: "Signing in to Kleos means proving a Google or GitHub account, and on a laptop that is both too much and not enough."
---

**Status:** accepted
**Date:** 2026-10-29

## Context

Signing in means proving a Google or GitHub account to the enclave, which
derives `owner_id = hex("google:<subject>")` and issues a session. On a laptop
that is both too much and not enough.

**Too much**: a personal install should not need an OAuth app, a client secret,
a redirect URI and a round trip to Google before it can store a note for you.

**Not enough**: without a real OAuth app the only way in is mock mode, which
accepts `mock_google_<subject>` from anyone. The owner id is a deterministic
hash of the subject, so the session is not even guessable — it is *derivable*.
Paired with the old `0.0.0.0` bind, that was a complete takeover of a personal
install from anywhere on the same network. The bind is fixed; the sign-in is
still a development shortcut doing a product's job.

There is already a key in the system that means "this is me": the device key
that signs grants, held by the owner, never sent to the gateway (ADR 0011). A
local install has that key and uses it for everything *except* saying who it
is.

## Decision

**A local owner is a keypair, and the gateway enrols it.**

```
first run                        afterwards
─────────                        ──────────
kleos-device keygen              kleos-device sign-session
POST /auth/local/enrol           POST /auth/local/session
  { code, public_key }             { signed assertion }
      ↓                                ↓
  owner_id = hex("local:<key_id>")  the same owner_id
  key registered, session issued    a session
```

### The owner id is derived from the key

`hex("local:" + key_id)`, which is the shape every other owner id already has —
`hex("<scheme>:<subject>")` — so nothing downstream learns a new format. The
owner id is not a name anyone picks, which also means two people enrolling on
two laptops cannot collide.

### It is the gateway's job, not the enclave's

Every other identity is established in the enclave, because the claim is "this
token was verified against Google" and an attestation over an unverified claim
is worthless (README's own argument). A local identity makes no such claim: it
says *this request was signed by a registered key*, and the registry lives in
the gateway. Putting it in the enclave would mean putting the device key
registry inside the measured image — precisely what ADR 0028 declined to do,
for the same reason.

So **a local session carries no attestation, and that is not a gap**. There is
nothing an enclave could attest to that the gateway did not already check. On a
local install the operator is the owner, and the question an attestation
answers does not arise.

### Enrolment needs a code, and the code is a file

The gateway writes a random code to `.local/enrolment-code` (mode `0600`) on
first start and logs that it did. Enrolment requires it.

Possession of a file on the machine is the authentication, which is the right
strength for this: anything that can read that file can already read the Neo4j
volume and the blob store. What it stops is the thing the bind fix also stops —
a stranger who can reach the port enrolling themselves as a brand-new owner.
Defence in depth rather than the only lock.

Single owner per code, and the code is consumed on use. A second device for the
same owner goes through `/auth/device/register` under a session, which already
exists and is what the dashboard uses.

### Signing in afterwards is a signed assertion, not a challenge

`POST /auth/local/session` takes `{key_id, issued_at_ms, nonce, signature}`
over a fixed string. Verified against the registered public key, refused if the
timestamp is more than 60 seconds from now, and the nonce is remembered for as
long as it could still be replayed.

A challenge-response round trip would be the textbook answer. Rejected because
it needs a server-side challenge store with its own lifetime for a property the
timestamp and nonce already give, and because a one-shot assertion is something
`kleos-device` can print offline and a script can pipe into curl — which keeps
the device CLI free of an HTTP client, as it has been deliberately.

### Mock sign-in stops being free

`/auth/session` with a `mock_*` token now requires `ALLOW_MOCK_IDENTITY`, off by
default, the same shape as `ATTESTATION_ALLOW_MOCK` (ADR 0026). The test
suites and the smoke scripts set it; a person running Kleos does not, and does
not need it, because they have a real local owner.

## Alternatives rejected

**Keep mock sign-in and just bind loopback.** Cheapest, and it is what the
previous commit already did. Rejected as the *whole* answer: it leaves the
product's front door labelled "development only", leaves every local install
sharing the owner id of anyone who typed the same name, and means a user who
ever exposes the port is fully compromised by a single mistake.

**A username and password.** Familiar, and it needs a password store, a hashing
choice, a reset path and a lockout policy — all to establish something the
device key already establishes cryptographically, for a system whose entire
authorisation model is already built on that key.

**Let the first request define the owner, with no code.** Trust-on-first-use.
Rejected because "first" is whoever reaches the port first, which on a
misconfigured bind is not the person at the keyboard. The code costs one line
of setup and removes the race.

**Derive the owner id from a user-chosen name.** Friendlier in logs. Rejected:
two installs would collide, and an owner id is a key in a database that already
holds somebody's memory. The key id is unique by construction and the dashboard
can show a label.

## Consequences

- **A local install no longer needs an OAuth app**, which removes the largest
  single piece of setup between a clone and a working harness.
- **`ALLOW_MOCK_IDENTITY` is a new thing to forget.** Scripts set it; a CI job
  that does not will fail at sign-in with a message saying so. That is the
  intended failure.
- **Two kinds of owner now exist** in the same database: `google:` and
  `local:`. Nothing distinguishes them downstream, which is deliberate — a
  local owner's memory is the same memory — but it does mean a hosted
  deployment should not enable local enrolment, and the setting is separate for
  that reason.
- **Trust tier is `None` for a local owner.** Nothing reads trust tier today,
  so nothing changes; when something does, this is the case to think about.
- **The enrolment code is a file on disk.** Lose it before enrolling and you
  delete it and restart the gateway; lose it after, and it does not matter.
