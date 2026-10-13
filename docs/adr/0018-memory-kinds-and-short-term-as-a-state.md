---
title: "ADR 0018: Memory kinds as a closed vocabulary, and short-term as a state"
description: "Long-term memory was one pile, and an agent could be granted all of it or none of it."
---

**Status:** accepted
**Date:** 2026-10-13

## Context

Long-term memory was one pile, and an agent could be granted all of it or none of
it. "You may read how I do things, not what I did" is a sentence a person would
say, and `permits()` had no way to express it.

A harness also needs somewhere to put what an agent is working from *now* -- the
turns so far, what a tool returned, a scratchpad -- and that is a different kind
of thing from a decision, in a way that matters for whether it is retrievable.

## Decision

**Three kinds on `Claim`, closed. Short-term is a state, not a fourth kind.**

```
MemoryKind = Episodic | Procedural | Tacit
```

### A field on `Claim`, not three node types

The Commitment argument, unchanged: a procedure can be superseded ("we deploy
with X now, not Y"), contradicted and reconciled, and the resolver already
implements exactly that machinery. Three parallel node types would duplicate the
resolver, the promoted columns, the ACL flattening, `:Memory` membership, four
read paths and the permission node -- four things to keep in step with one.

### Closed, for the `AffectTone` reason

A free-text field built for filtering is where an extractor eventually writes a
sentence, and this one is promoted to an indexed column and read by a grant
filter. `Tacit` carries a `sensitivity_floor` of `Confidential`: a tacit claim is
an inference *about* a person rather than something they said, assembled by
watching them, so naming it has to cost reach. Labelling can only ever narrow.

### `Option`, with one explicit exception to deny-by-default

`Claim.memory_kind` is optional and **not** defaulted to `Episodic`, because
every claim written before the field existed genuinely has no kind and inventing
one is a lie an indexed column then serves and a grant filter then enforces.

Which forces the exception, on the object side only:

```
acl.memory_kind == None      -> passes any kind scope
acl.memory_kind == Some(k)   -> requires k in scope.memory_kinds (empty denies)
```

The scope side stays strict. The object side cannot be: the strict reading would
retroactively hide every claim in every existing database behind a field nothing
set. Backfilling `Episodic` instead would assert a kind nothing derived, which is
what ADR 0015 refuses in the merge case -- an uncertain case fails towards the
recoverable outcome, and a wrong label on a million claims is not recoverable.

It is an exception for **absence**, never for mismatch: a claim labelled `Tacit`
is never visible to a scope that did not ask for tacit memory. It has its own
named test in both languages, and it is listed in the README's invariants, because
an undocumented exception to the invariant that file puts first is how that
invariant stops being true.

### Short-term is a different state

Stored, searchable and loaded are three states:

| state | what it means | enforced by |
| --- | --- | --- |
| stored | sealed, written as a Quilt patch, no embedding | the absence of an `upsert` |
| searchable | in the vector index, reachable by traversal | the `:Memory` label plus an embedding |
| loaded | what one inference sees, assembled per call | the read log is its only durable trace |

A fourth enum value would put session scratchpads in the same vector index as
consolidated facts, which is precisely the distinction the split exists to draw,
and would make `Scope.memory_kinds` able to grant "short-term" as though that
were a readable category.

## Alternatives

- **`:Episode` / `:Procedure` / `:Tacit` node types.** Rejected above.
- **A free-text `kind` string.** Rejected above.
- **Backfill `Episodic` onto every stored claim** so the permission rule can stay
  strict. Rejected: it asserts something nothing derived, onto data that cannot
  be un-asserted.
- **`ShortTerm` as a fourth kind.** Rejected: it is a state.

## Consequences

- An agent can be granted procedures and not episodes, and a test holds it.
- `memory_kind` is promoted to an indexed Neo4j column, so "which procedures exist
  about X" is one index seek rather than a scan that hydrates every payload.
- **Memory kinds are a permission axis and not a retrieval axis.** The eval's
  procedure question scores 0% under *every* system, both resolved paths
  included: nothing in the query path asks for a procedure or prefers one, so a
  procedural question competes with lexically similar facts about the same
  project and loses. Fixing it means kind-aware ranking, which is a change to
  retrieval rather than to this schema, and it is not done.
- The deny-by-default exception is real and is the only one. It is stated in the
  code, in the README's invariants, and here.
