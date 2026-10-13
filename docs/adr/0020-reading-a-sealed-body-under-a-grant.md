---
title: "ADR 0020: Reading a sealed body under a grant"
description: "A sealed body was durable and unreadable, behind a ref that read as recoverable."
---

**Status:** accepted
**Date:** 2026-10-13

## Context

A sealed body was durable and unreadable, behind a ref that advertised a `key_id`
and a `byte_len` and read as recoverable.

The path existed in two halves. `LocalQuiltStore.get` was implemented,
owner-partitioned and guarded against path traversal; the gateway proxied the
enclave's decrypt. Nothing converted a stored `EncryptedContentRef` into a
`BlobRef`, so `get` had **zero call sites**. The documentation said the gateway
did not expose decrypt, which was false, and the true statement -- "nothing
assembles the path" -- was nowhere.

Underneath it was a second problem nobody had hit. Sealing happens during
ingestion, which holds an owner session; unsealing happens during a *read*, which
holds a grant and nothing else. With `ENCRYPT_CONTENT_AT_REST` on, **every query
against sealed content failed** inside the gateway client with "no owner
session". The setting was unusable, and the only reason it had gone unnoticed is
that it defaults off, because the smoke script and the eval run without a gateway.

## Decision

**Assemble the path, and let a read unseal under the grant it already has.**

### The converter, and where `backend` comes from

`ref_from_encrypted_content(ref, backend)`. The only missing field is `backend`,
and it comes from the configured store rather than from the ref. Deliberately not
a field on `EncryptedContentRef`: that would trip schema parity, change the
enclave's measurement, and alter the shape `Scope` is being kept in for an
on-chain grant object -- all for a *deployment* fact. Where this deployment put
the bytes is not a property of the body.

### The gateway verifies the grant

`POST /memory/seal/unseal`. Three ways to authorise an agent's unseal, and two
are worse:

- **The orchestrator holds a standing owner session.** A store-wide decrypt
  capability held by a process outside the trust boundary and under the
  operator's control, which undoes the entire grant design to save a route.
- **The agent supplies an owner session.** Impossible by construction: handing an
  agent one collapses the grant model into a login.
- **Verify the grant here.** Chosen. `verify_grant` already binds
  `scope.owner_id` to the signing device key, so the owner is at least as
  unspoofable as behind a session -- more so, since owner sessions are host-signed
  and grants are not.

The added logic is **one boolean on an already-verified struct**, not a second
`permits()`. That matters because "no second implementation of retrieval or
ranking in Rust" is a rule this repo keeps: this is a capability check of the kind
`routes/memory.rs` already does for every route, and the per-object permission
check stays in the orchestrator where the graph is.

### `may_unseal` is its own axis

Seeing a resolved claim and reading the raw transcript it came from are different
disclosures, and the body is the one the enclave exists for. `evaluate_unseal`
layers on top of the read check rather than folding into it, so an object the
grant cannot see comes back with the *read* check's reason and `may_unseal` is
never a way around it. Both directions are asserted.

It runs after the ordinary permission check, for objects already about to be
disclosed: the decrypt budget is the disclosure budget (ADR 0010).

### Two failures that must stay apart

`load_body` returns rather than raises -- a missing blob is an ordinary fact about
an old ingest and must not fail a read that was otherwise permitted, which is
`ToolResult`'s argument.

| | |
| --- | --- |
| `not_stored` | the bytes are genuinely absent |
| `backend_not_wired` | the bytes exist and *this* deployment cannot reach them |

The second is a Walrus-configured deployment reading a body sealed to local disk.
ADR 0002 and 0008 refuse a silent fall back to the orchestrator's disk, so
reporting that as "no body" would make a confidentiality design look like an
empty record. A test asserts the two can never be conflated, and that the Walrus
stub raises rather than returning `None` -- which is what makes them
distinguishable at all.

## Alternatives

Covered inline above: the standing owner session, the agent-held session, and
putting `backend` on the schema.

## Consequences

- `ENCRYPT_CONTENT_AT_REST=true` is usable for the first time. `ContentCrypto`
  gets `for_grant`, returning a new instance rather than setting a field, because
  one `Runtime` serves concurrent reads and a token parked on the shared object
  would be read by whichever request got there next.
- A sealed body can be read back. Proven against `BLOB_STORE_DIR` only.
- **In mock mode the seal is a reversible XOR**, so the test that reads a body
  back proves the plumbing and not confidentiality. "Only the enclave can read it"
  stays unwritten until an EIF runs on real hardware.
- The route does not unseal a sealed OAuth refresh token and cannot: those live in
  a different store with no decrypt at all, for the reason `store/mod.rs` gives.
