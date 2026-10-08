---
title: "ADR 0008: Store sealed bodies as Quilt patches, and write no tags"
description: "ADR 0002 gave sealed bodies a content-addressed blob store with 'the shape Walrus has', so that Walrus would be a second implementation rather than a migration."
---

**Status:** accepted
**Date:** 2026-10-02

## Context

ADR 0002 gave sealed bodies a content-addressed blob store with "the shape
Walrus has", so that Walrus would be a second implementation rather than a
migration. That shape was one blob per body, which is the wrong shape.

A sealed record body is a ChatGPT transcript, an email, a calendar entry —
kilobytes, and thousands of them per backfill. Walrus charges erasure-coding
overhead per blob, and at that size the overhead dominates the payload. Walrus
Quilt exists for exactly this case: batch up to ~660 small files into one
container, cutting overhead by roughly 106x at 100KB and 420x at 10KB, plus the
gas of one write instead of hundreds. At our object size, one-blob-per-record is
a bill proportional to how carefully someone uses their own memory.

Quilt also matters for *reads*, which is the part that makes it safe here: each
patch is independently addressable and readable without fetching the rest. Batch
storage that forced a whole-container download would have meant answering a query
about one permitted event by pulling 659 bodies the grant may not cover.

## Decision

**The blob store interface is batch-first.** `put_batch(owner_id, ciphertexts)
-> list[BlobRef]`, order-preserving; `put` is the one-element case, kept because
callers read better for it. Ingestion writes every sealed body in a run as one
batch, before the per-candidate loop. Batches over `MAX_PATCHES_PER_QUILT` (660)
split across containers rather than being rejected: the caller is a backfill and
has no useful way to honour the limit itself.

**Two identifiers on the ref.** `EncryptedContentRef.blob_id` names what the
store holds (a Quilt, or a standalone blob) and the new `patch_id` locates the
body inside it. `patch_id` is `None` for a non-batching store. Mirrored in
`shared/src/memory.rs` and guarded by the parity test.

**No Walrus-native tags. Ever.** Quilt supports immutable, Walrus-native
per-patch metadata — tags, whose purpose is picking an item out of a batch
without reading it. That is a genuinely useful feature and it is the one we must
decline. The tags are plaintext, public, and immutable: a tag describing what a
sealed transcript is *about* would permanently publish a searchable index over
the shape of someone's private life, next to the ciphertext that was the entire
point of sealing it. Immutability means it could never be retracted. Our own
index maps event → Quilt → patch under an `ObjectAcl`, so nothing is lost:
retrieval stays permissioned and revocable, and the public store learns only that
some bytes exist. See ADR 0009 for the metadata that would otherwise have gone
there.

**Containers are per owner.** The container id mixes in the owner id, so two
owners storing byte-identical content get the same *patch* id (content
addressing) and different *containers*. Co-locating two people's bodies in one
Quilt would be a correlation leak independent of encryption — patches in a Quilt
are stored and fetched together, so a shared container is public evidence that
those bytes belong together.

**The whole batch succeeds or fails.** No partial-Quilt recovery path while the
only writer is a backfill that can be re-run, and re-running is cheap because
patch ids are content addresses, so the second attempt rewrites nothing.

## Alternatives

- **Keep one blob per body.** Simplest, and already written. Rejected on cost:
  two orders of magnitude of overhead at our object size, which is not a tuning
  difference but the difference between a viable store and an unusable one.
- **Batch by time window (a Quilt per day) rather than per run.** Better
  amortisation for a trickle of new records, and it needs mutable containers or
  a compaction pass, neither of which Walrus offers. Revisit if incremental
  sync — rather than backfill — becomes the dominant write pattern.
- **Use Quilt tags for retrieval and skip our own index.** The feature as
  designed, and it would remove a mapping we now maintain. Rejected outright:
  it publishes exactly what the enclave exists to protect.
- **Overload `blob_id` with a composite `"quilt/patch"` string.** One less
  schema field, and a parser in every reader. A reference with two parts should
  have two fields.

## Consequences

- Sealed bodies get the cost profile the store was designed for, and a read
  still touches one patch.
- `patch_id` is a schema change, so both language mirrors and the parity test
  moved together. The parity test itself had a latent bug this change exposed:
  it stripped Rust test modules *after* concatenating both source files, so the
  first `#[cfg(test)]` anywhere truncated everything following it. Fixed to strip
  per file.
- Walrus remains a stub, now with the right signature and an explicit written
  policy about tags, so whoever implements it inherits the decision rather than
  rediscovering the temptation.
- A batch that fails leaves the whole run's sensitive events unwritten rather
  than some of them. Louder, and correct: the alternative is a store where some
  refs resolve and nobody knows which.
- The local store writes a `quilt.json` manifest of patch ids so a container is
  enumerable without a separate index. It carries ids only — a manifest that
  described content would reintroduce the problem the tag decision avoids.
