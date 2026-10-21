---
title: "ADR 0026: Verify the attestation, and say what verified"
description: "Every sealed thing this system produces carries an attestation document, and until now nothing has ever looked at one."
---

**Status:** accepted
**Date:** 2026-10-21

## Context

Every sealed thing this system produces carries an attestation document, and
until now nothing has ever looked at one.

`get_attestation` (`enclave/src/services/attestation.rs`) is called on five
paths: `/identity/verify`, `/oauth/exchange`, `/memory/seal/encrypt`,
`/attest`, and the action broker. Under `nitro` it is a real NSM call. The
document is hex-encoded, returned through the gateway, carried into
`graphs/ingestion.py:355`, and written to the node. Nothing — not the gateway,
not the orchestrator, not the device, not the dashboard — has ever parsed one.

So the string is decoration. An operator who replaced the enclave endpoint with
an ordinary HTTP service that permits everything and returns
`"MOCK_ATTESTATION_"` would produce a system that behaves identically and
passes every test in this repository. That makes ADR 0022's brokered actions and
ADR 0024's assemble-and-reseal unfalsifiable: both say "the TEE did this", and
neither claim is checkable.

It is also the cheapest remaining item in the confidentiality program, and a
precondition for the others meaning anything. Moving `evaluate` into the enclave
(step 4) buys nothing if nobody can tell the enclave from a host process
pretending to be one.

## Decision

**Parse the document, verify the chain, bind it to a key, and return what
verified rather than whether it verified.**

### Three outcomes, not a boolean

```rust
pub enum Trust {
    Mock,          // a mock stub, and the policy allowed mocks
    SignedByAws,   // chain verifies to the pinned Nitro root
    Pinned,        // ...and PCR0 matches an expected measurement
}
```

A boolean is the bug. "This document was signed by the AWS Nitro PKI" and "this
document was signed by *our enclave image*" are different facts, and the gap
between them is exactly the attack an operator can mount: any Nitro enclave
anywhere produces a document that verifies to the AWS root, including one
running an image the operator wrote this morning. Only PCR0 — the measurement of
the image — distinguishes them.

Collapsing the two into `true` would mean the system reports the strong claim
while holding the weak evidence. So the verifier returns which one it
established, and a caller that needs `Pinned` says so and is refused otherwise.

### Mock documents verify only when the policy says mocks are allowed

The `MOCK_ATTESTATION_` prefix exists so a mock can never be mistaken for the
real thing downstream. That was a comment; this makes it a check. `allow_mock`
is off unless configuration turns it on, a mock never returns anything above
`Trust::Mock`, and a real document is never accepted by the mock path.

### The root certificate is configuration; its fingerprint is a constant

AWS publishes the root at
`https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip` with a
published SHA-256 fingerprint,
`64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.

The fingerprint is a constant in the source. The certificate itself is supplied
by the operator and refused unless it hashes to that constant.

The alternative — embedding the DER in the binary — looks stronger and is
weaker, because nobody reviewing the diff can tell correct certificate bytes
from incorrect ones. A pinned digest against an operator-supplied file is
checkable by reading one line of code against one line of AWS documentation, and
it fails closed: a wrong certificate is a startup error rather than a chain that
verifies to the wrong root.

### It must bind the document to a key, or it is theatre

A verified document says "some enclave attests to this public key at this
time". It does not say the key was the one that sealed the thing in front of
you. So `verify` returns the `public_key` the document commits to, and the
caller checks it against the key it is about to use. A verification that does
not do that step establishes nothing about the data it was supposed to be
about.

Freshness is checked for the same reason: the document is a statement about the
past, and a replayed one from a since-decommissioned enclave verifies
perfectly.

### One verifier, mirrored Rust and Python, the way `evaluate` is

`shared/src/attestation.rs` in Rust and `orchestrator/attestation.py` in Python,
with the same inputs and the same refusals, which is precisely the arrangement
ADR 0017's `evaluate` already lives under. Two implementations is a cost paid
deliberately: the orchestrator is Python and calling the host to ask whether to
trust the host is circular.

**The Rust verifier is behind a non-default feature and the enclave does not
enable it.** `services/actions.rs` says an attestation is only worth what the
image it measures is small enough to audit, and the enclave has no reason to
verify its own document. CBOR, X.509 and P-384 would be weight inside the
measured image bought for nothing.

### Where verification means something, written down

Three places check, and they do not mean the same thing:

| | What a failure catches |
|---|---|
| **The device** (`device/`) | The real one. The device is not the operator, holds its own key, and refuses to open a sealed answer whose attestation does not verify. |
| **The owner's browser** | The other real one. ADR 0023 already puts the owner's key there. |
| **The orchestrator and gateway** | Misconfiguration. Both run on the host, so an operator who wanted to skip the check would skip it. |

That last row is the one worth being honest about, because a host-side check is
the easiest thing to mistake for a security boundary. It is a configuration
check: it catches an orchestrator pointed at something that is not an enclave,
and it catches the mock creeping into a build that should not have it. It
catches nothing a hostile operator does. It is still worth having — most
failures are mistakes, not attacks — and it is not what makes the claim true.

## Alternatives rejected

**Verify in the gateway only.** One place, Rust, no mirror. Rejected because the
gateway is the host: it is the component an operator substituting a fake enclave
would substitute. Verification that lives entirely inside the thing being
verified is a loop.

**Verify in the enclave.** The enclave could check its own document before
returning it. That tests the NSM driver and nothing else, and costs the
verification stack inside the measured image.

**Accept any document signed by the AWS root.** Simpler, and it is what a
`bool` verifier naturally becomes. It admits any Nitro enclave, which includes
one the operator built, which is the attack.

**Wait for PCR0 pinning before verifying anything.** The expected measurement
comes from a build on real hardware, which has not happened (`.eif` on EC2 is
still the gap under everything). Rejected because `SignedByAws` is not nothing
— it already excludes a plain HTTP service pretending to be an enclave, which is
today's actual exposure — and because a verifier with a `Pinned` outcome nobody
can reach yet is still a verifier the day the measurement exists.

**Verify, and store the verdict instead of the document.** Tempting, because the
document is large. Rejected: a stored verdict is a host-side assertion about a
host-side check, and the whole point is that the device gets to decide for
itself. The document stays; the verdict is computed by whoever needs it.

## Consequences

- **`Pinned` is unreachable until there is a real build.** Nothing today can
  produce an expected PCR0, so the best obtainable outcome in production will be
  `SignedByAws` until `.eif` runs on EC2. The verifier reports that distinction
  rather than hiding it, and `docs/status.mdx` carries it.
- **Mock mode now has to be configured, not assumed.** A local run that stops
  working because `allow_mock` is off is the check doing its job, and
  `run_local.sh` sets it.
- **The operator has to install a certificate.** A real deployment needs the
  root PEM on disk and a config pointing at it. Deployment cost, deliberately
  taken: the digest pin is what makes it checkable.
- **Two verifiers can drift.** The same risk `evaluate` carries, and handled the
  same way: shared test vectors, and the refusal reasons enumerated identically
  in both.
- **It does not make the host trustworthy.** Worth repeating as a consequence
  because it is how this gets oversold. What this closes is "nothing has ever
  looked at one". What it does not close is that the orchestrator holds
  plaintext; that is steps 4 and 5.
