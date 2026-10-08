---
title: "ADR 0002: Persist sealed ciphertext in a content-addressed blob store"
description: "`EncryptedContentRef` has carried a `blob_id: Option<String>` since the schema was written, documented as 'the eventual Walrus blob; until Walrus is wired the ciphertext is carried"
---

**Status:** accepted
**Date:** 2026-10-01

## Context

`EncryptedContentRef` has carried a `blob_id: Option<String>` since the schema
was written, documented as "the eventual Walrus blob; until Walrus is wired the
ciphertext is carried by the orchestrator and `blob_id` is `None`."

"Carried by the orchestrator" was doing a lot of work in that sentence. Traced
end to end, the ingestion graph:

1. `encrypt` sealed a sensitive body inside the enclave and put the ciphertext
   into LangGraph state as base64,
2. `write` stored the *ref* on the Neo4j event and set `event.body = None`,
3. and the run ended, taking the only copy of the ciphertext with it — it
   existed solely in the in-process `MemorySaver` checkpoint.

So ingesting a sensitive record **destroyed its body**, and the stored object
did not say so: it carried a ref with a `key_id`, a `scheme` and a `byte_len`,
which reads as "recoverable, go ask the enclave". Nothing was recoverable.
`CHATGPT_SENSITIVE` defaults to true, so this was the normal path for every
ChatGPT transcript, not an edge case.

The README's wording was honest about the mechanism and still managed to
understate the consequence, which is worth noting: "the ciphertext is carried
by the ingestion graph" and "sealing a record deletes it" are the same fact.

## Decision

Add a `BlobStore` interface with `put(owner_id, ciphertext) -> blob_id` and
`get(owner_id, blob_id) -> bytes | None`, and populate `blob_id` from the first
write. No schema change: this fills the field that was declared for exactly
this purpose.

Two implementations. `LocalBlobStore` writes one file per blob under a
per-owner directory, and is what runs today. `WalrusBlobStore` keeps the
existing stub's signature and raises.

Three properties the interface exists to enforce:

- **Content-addressed.** The id is `blake2b-256` of the *ciphertext*. This is
  the shape Walrus already has, so Walrus becomes a second implementation
  rather than a migration. It also makes re-ingesting unchanged material
  idempotent instead of unbounded, which matters because a backfill overlaps
  previous backfills by design.
- **Hashed from the ciphertext, never the plaintext.** This code never sees a
  plaintext, and an id derived from one would leak equality of raw content to
  anyone who can read ids.
- **Owner-partitioned.** `get` takes an owner id and will not return another
  owner's bytes even when handed a correct id. Ids are public and derived from
  content, so two owners storing identical bytes get identical ids; the
  partition is what stops that being a disclosure. This is a *separate* check
  from `permits()`: that one governs objects, this one governs bytes, and
  collapsing them would mean one bug reaches both.

Writes are atomic — temp file in the same directory, `fsync`, `os.replace` —
so a crash cannot leave a short file sitting at an id that claims to address
content it does not hold. A silently truncated blob would be discovered only by
whoever eventually tried to decrypt it.

Failure is a skip, never a downgrade. If the blob write fails, the event is not
written at all, exactly as when the seal itself fails. There is no fallback that
stores the body in the clear, and none that stores a ref whose bytes are
missing — a dangling ref is worse than a missing event, because it reads as
recoverable.

`get_blob_store` picks Walrus when `WALRUS_PUBLISHER_URL` is set and local
otherwise, with no "try Walrus and fall back". A deployment that believes it is
writing to Walrus and is actually writing to the orchestrator's disk has a
confidentiality bug, not a performance one.

## Alternatives

- **Add `ciphertext_b64` to `EncryptedContentRef`.** Smallest diff, and wrong:
  a reference that carries its own payload is not a reference. It would also
  put the bytes inside the Neo4j `payload` blob, inflating every read of an
  event by its full body, and would need the same field mirrored into
  `shared/src/memory.rs` and the parity test for a transitional hack.
- **Store the ciphertext as a Neo4j property on the event.** No new component.
  But Neo4j is explicitly *not* the system of record here — it is the
  queryable index, conceptually rebuildable from source — and putting the only
  copy of sensitive content in it contradicts that directly. It also makes
  every graph backup a backup of all sealed content, with no way to separate
  the two.
- **Wire real Walrus now.** The honest destination, and far too large: it needs
  a publisher reachable through the enclave's VSOCK tunnel, real Seal with a
  key-server committee, and an on-chain owner policy object. The data loss is
  happening today and should not wait behind three unfinished systems.
- **Leave it, and document the loss louder.** Tempting given that sealed bodies
  cannot be *read* back yet either (see below). Rejected because the two gaps
  are not symmetric: an unbuilt read path is a missing feature, while
  discarding the bytes is unrecoverable, and every day of ingestion in between
  destroys data that cannot be regenerated from a source that may itself have
  rotated away.

## Consequences

- Sensitive bodies survive ingestion. `blob_id` is populated, and a test
  asserts the stored bytes are exactly what the enclave returned.
- **There is still no read path.** Recovering a body means `POST /seal/decrypt`
  on the enclave, which the gateway deliberately does not expose
  (`gateway/src/store/mod.rs`). So the bytes are durable and unreadable. That
  is the correct order to build these in — persisting first means the decrypt
  route, when it lands, has something to decrypt — but it means roadmap step 2 owes a
  gateway route before sealed content is usable, and until then the honest
  description is "retained, not yet retrievable".
- The local blob directory holds the *only* copy of a sensitive body. It is
  ciphertext, so it is not a confidentiality risk, but it is now a durability
  one: `BLOB_STORE_DIR` belongs on backed-up storage. Said plainly in the
  config comment and the README.
- Content addressing means a body that changes at the source produces a second
  blob and the first is never collected. Acceptable for now; a sweep for blobs
  no ref names is straightforward whenever it matters, and deletion is a roadmap step
  3 concern (the plan's "deletion propagates to retrieval and derived claims").
