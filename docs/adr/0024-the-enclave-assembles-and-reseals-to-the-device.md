---
title: "ADR 0024: The enclave assembles, and re-seals to the asking device"
description: "Decrypting inside the TEE buys nothing if the plaintext is handed to a host process that relays it."
---

**Status:** accepted
**Date:** 2026-10-14

## Context

Kleos is being sold on one sentence:

> We see the shape of your memory and the vectors we rank with.
> We never see what it says, and we never hold your credentials.

The second half is true. [ADR 0022](/adr/0022-sensitive-actions-are-brokered-in-the-tee)
got credentials out of reach, and the enclave has held the OAuth client secret
since the beginning.

**The first half is false today**, and not for the reason it looks like. The
obvious suspect is that [ADR 0010](/adr/0010-encrypt-the-resolved-record-at-rest)
left embeddings in the clear, and embeddings are approximately invertible to
text. True, and second-order. The first-order problem is that **plaintext passes
through a host process on every read and every write**:

| | where | what it sees |
|---|---|---|
| read | `storage/content.py:170` | every sealed field of every node a query returns |
| read | `storage/bodies.py:129` | the raw body behind a disclosed claim |
| write | `extraction/llm.py` | the person's raw text, on its way to a model |
| write | `resolution/resolver.py:221` | **already-stored** claims, unsealed to compare against |

The last one is the one that is easy to miss and the worst of the four. Sealing
at rest protects the database, not the running process — and the resolver
unseals *existing* memory on every ingestion, so an operator watching one write
sees far more than what was written.

Sealing the embeddings would not have touched any of this.

## Decision

**The enclave unseals, filters, assembles — and re-encrypts the result to the
asking device before it leaves.**

```
d1 asks ──→ host: ranks on embeddings and structure, both in the clear
              │   picks top-k candidates, reads none of them
              ↓
           enclave: unseals those
                    filters by permission on real content
                    assembles
                    re-seals the result to d1's key
              ↓
           host: relays an opaque blob
              ↓
           d1: unseals locally, hands plaintext to its agent
```

### Why the re-encryption is the decision

"Decrypt inside the enclave" sounds like the whole answer and is not. If the
enclave hands plaintext back to the orchestrator and the orchestrator relays it
over MCP, the host sees it in transit. The decryption has moved and the exposure
has not. The re-encryption is what makes the move mean anything; everything else
here is plumbing around it.

### The recipient is derived, never supplied

The device the result is sealed to is **taken from the verified grant**, not from
a field in the request. The gateway already knows which registered key signed the
grant, so it looks up that device's encryption key and passes it in.

A caller-supplied recipient would be a hole large enough to drive the whole
system through: anyone holding a leaked grant could ask for the answer sealed to
a key they control. Same rule as `owner_id`, which every route already takes from
a verified grant and never from a request.

### Two keys per device

Ed25519 is a signature scheme and cannot be encrypted to. Converting an Ed25519
key to X25519 is possible, fiddly, and widely advised against.

So a device registers **two** keys: Ed25519 to sign grants, X25519 to receive
sealed results. `device_register`, the `kleos_device_keys` row and the
dashboard's key generation each grow one field. Revocation stays per device and
covers both, which keeps the [one-key-per-agent](/adr/0023-the-owners-key-lives-in-the-browser)
convention working unchanged.

### What stays visible, on purpose

Stated rather than buried, because the positioning rests on exactly this line:

- **Structure** — entities, edges, claim status, timestamps, ACLs. The host
  traverses and pre-filters on these; without them in the clear there is no graph
  database, only a blob store.
- **Embeddings.** Ranking runs on the host. Approximately invertible, so this is
  a real disclosure and is written down as one.

Sealing the embeddings and moving vector search inside the enclave was considered
and **declined**: it costs Neo4j's vector index and bounds how large one owner's
graph can be. Revisit when a customer requires it, not before.

## Alternatives rejected

**Decrypt on the device.** Cryptographically the strongest — the enclave
assembles nothing either, and the host relays sealed refs. Rejected for a product
reason rather than a security one: the harness could not then read content, so it
could not build the briefing. "Device 2 decided X because Y" requires something
to read Y and rank it against what device 1 is about to do, and that briefing is
the product.

**Move the whole orchestrator into the enclave.** Reaches the same property and
costs vastly more: LangGraph, LlamaIndex and a model client inside a measured
image, against the README's own argument that an attestation is only worth what
it measures. A1 gets the same confidentiality for a routine small enough to audit.

**Seal embeddings instead.** Addresses the second-order leak while leaving all
four plaintext touchpoints open. Fixes the symptom that is easiest to name.

## Consequences

- The operator sees structure, vectors and ciphertext. Not content.
- **No LLM moves into the enclave for this.** The read path calls no model —
  `assemble` retrieves, ranks, permission-checks and formats — so A1 is unseal,
  filter, assemble, re-seal. Small, bounded by top-k, auditable. The TCB grows
  in two separate jumps and this is the cheap one.
- **It pins an open decision.** The roadmap carries "whether `assemble`
  synthesises or formats". It must stay formatting: synthesis would put a model
  call *inside* the enclave, since that is where the plaintext is, turning a small
  routine into one containing an LLM client. Synthesis is the agent's job anyway —
  it has a model, and citations it can check beat prose it has to trust.
- **The write path is not fixed by this.** Extraction and resolution still handle
  plaintext on the host, and the resolver's unsealing of *stored* claims is the
  sharper of the two. Both need the same treatment before the sentence is true for
  writes; this ADR covers reads.
- **The device needs somewhere to unseal.** That is the MCP client, which exists
  now that the tools are served over HTTP — the same component, one more job.
  Without the hosted transport there was nowhere to put this.
- **Host-side unsealing leaves the read path.** `ContentCrypto.unseal_node` and
  `load_body` stop being called there. Keeping them as a fallback would mean one
  configuration flag away from the exposure returning silently.
- **A leaked grant is still a leaked grant.** It names a device, so the answer
  comes back sealed to *that* device's key — which narrows a stolen token from
  "readable by the thief" to "readable by the device it was issued for", but does
  not make one safe. Short TTLs and key revocation remain the controls.
- **None of it is attested until the `.eif` runs on real hardware.** In mock mode
  the seal is a reversible XOR and attestation documents are prefixed
  `MOCK_ATTESTATION_`. Until EC2, this is a correct design with nothing behind it,
  exactly as the action broker is today.
