# ADR 0010: Encrypt the resolved record's text at rest

**Status:** accepted
**Date:** 2026-10-02

## Context

The confidentiality model said, honestly, that raw bodies and OAuth tokens are
ciphertext while the **derived** memory is written to Neo4j in the clear — and
that this is "a real gap, not a technicality: for many purposes the resolved
record is the more sensitive artifact."

It is worse than a gap in the abstract. The thing left open is the thing the
product is *for*: who you talked to, what you decided, when it changed, what you
owe whom. ADR 0009 made it sharper still by adding an affective register, because
`tone: grief, intensity: 0.9` beside entity names and timestamps is a more
intimate record than the events it annotates.

The README framed closing this as three options — hub-local extraction, an
attested inference endpoint, or narrowing the claim — all expensive or lossy, all
deferred to roadmap step 4. That framing conflates two separable things:

- **extraction reads plaintext**, which it must, to produce a record at all;
- **the record sits in plaintext**, which it need not.

Only the second is continuous. An adversary with database access, a stolen
backup, or a read replica reads everything, forever. An adversary who has to
catch a specific ingest job in flight has a far narrower window. Closing the
second alone is most of the exposure for a fraction of the work, and it does not
foreclose any of the three options for the first.

## Decision

Seal the content fields of every stored object inside the enclave before they
reach Neo4j, and unseal only what a read is about to disclose. Staged:

**Stage 1 (this ADR).** Content fields sealed; embeddings left in the clear.
**Stage 2 (next).** Embeddings sealed too, with vector scoring moved inside the
enclave — which also gives the enclave a durable role beyond credential custody.
**Stage 3.** Move extraction itself, by whichever of the three options is cheapest
by then.

### What is sealed

`Event.summary`, `Event.body`, `Claim.statement`, `Entity.name`, `Entity.aliases`,
and `Citation.quote`. Declared in one registry in `storage/content.py`, so adding
a schema field means deciding which list it belongs in.

Left in the clear: ids, owner ids, timestamps, labels, edge types, ACL fields,
claim status, commitment dates and entity references, embeddings.

That split was chosen so the reads keep working, and the result is better than
expected: **three of the four read paths are purely structural.** The supersession
history, the citation chain and the neighbourhood walk traverse edges, statuses
and timestamps, and need no sealed byte to do their walk. Only `/query` needs
content, and with embeddings in the clear even its ranking is unchanged. The one
casualty is the full-text index, which nothing queried — dropped rather than left
in place, because an index over ciphertext is a broken index that still looks like
a feature.

### The key never leaves the enclave

The tempting shortcut is envelope encryption: ask the enclave for a data key,
hold it for the run, encrypt locally. One round trip instead of hundreds — and a
key that decrypts the whole store, sitting in a process the operator controls, at
which point the ciphertext is decoration.

So every seal and unseal is a crossing into the TEE. This is what finally gives
`POST /seal/decrypt` a caller: it has existed on the enclave since Phase 2 and the
gateway deliberately did not expose it. The note in `store/mod.rs` — "there is
deliberately no decrypt here" — still holds for the **sealed refresh token store**,
where unsealing would hand the host standing mailbox access. Record content is a
different asset: the orchestrator produced it, from plaintext it already had, and
needs it back to answer a query.

The cost lands where it is affordable. Ingestion is a background job. A read
unseals only the objects that already passed the permission check, which is at
most `top_k` — so **the decrypt budget is the disclosure budget**, and a declined
read decrypts nothing at all. A test counts the crossings to hold that.

### Shape details that matter

- A sealed field stays a `str` — `KSEAL1:<key_id>:<base64>` — so nothing
  downstream changes shape, and it is self-labelling in the same spirit as
  `MOCK_SEAL_V1:`: if one reaches a log or a UI it reads as obviously encrypted
  rather than as corrupt text. The key id travels with the field because only the
  enclave can use it.
- Sealing is **idempotent per field**, so a retry after a partial failure cannot
  double-seal into something two unseal passes would be needed to read.
- `n.text`, the second copy of the content that existed for the dropped index, is
  sealed too. Sealing the payload and leaving that in the clear would have been a
  thorough-looking change that protected nothing.
- **Embeddings are computed from plaintext, before sealing.** This is the one
  ordering that is a correctness condition rather than a preference: an embedding
  of ciphertext is noise, and retrieval would go quietly useless while every
  structural test kept passing.
- **The resolver is handed an unsealer.** It compares a candidate's statement
  against stored ones; stored statements are sealed, so without this every topic
  would differ, no supersession would ever be detected, and the batch would still
  report success. The quietest possible failure, and the one a test now covers.
- Off by default (`ENCRYPT_CONTENT_AT_REST`), because the smoke script and the
  eval harness run with no gateway. There is no automatic fallback: with it on and
  the gateway unreachable, ingestion fails rather than silently writing plaintext.

## What this does and does not deliver

It upgrades confidentiality claim 1 — from the storage provider — to cover the
resolved record and not just raw bodies. A stolen backup, a read replica or a DBA
with SELECT now yields structure: how many objects, how they link, when things
happened, how sensitive each is. That is not nothing, and it is far less than
sentences.

It does **not** deliver claim 3, confidentiality from the operator. An operator
who can execute code in the orchestrator can call the decrypt route for anything,
and during ingestion plaintext passes through that process anyway. Stage 3 is the
only thing that changes this, and the README should keep saying so.

## Alternatives

- **Envelope encryption with a host-held data key.** Rejected above: it protects
  against exactly nobody who matters.
- **Seal the whole `payload` blob instead of named fields.** One crossing per
  object rather than per field, and conceptually cleaner. It requires every read
  that hydrates a model to unseal first — including the permission check, since
  `denied_agents` lives in the payload — which means flattening more ACL fields
  and restructuring all four read paths to check before hydrating. The right
  design greenfield; a much larger blast radius here, for a constant-factor win.
- **Searchable encryption, so text search survives.** Research-grade, and the
  leakage profiles of practical schemes are not obviously better than what
  structure-in-the-clear already concedes.
- **Wait and do stages 1–3 together at roadmap step 4.** What the README implied.
  Rejected because every day until then writes plaintext that cannot be
  retroactively protected, and because stage 1 needs none of step 4's decisions.

## Consequences

- Content encryption is one setting away, and `ENCRYPT_CONTENT_AT_REST=true` is
  what a deployment holding real memory sets. The default stays off until the
  smoke script and the eval can run against a gateway.
- Ingestion gains one enclave crossing per content field. Acceptable for a
  background job, and the first thing to batch if it bites — the enclave side is
  a loop over an existing primitive, so a batch route adds no new logic to the
  TCB.
- Text search is gone until stage 2. Nothing used it.
- The operator-facing gap is now precisely describable rather than broad: it is
  live process access during ingestion and query, not standing database access.
  That is the sentence the README should carry.
