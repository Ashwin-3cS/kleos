---
title: "ADR 0019: Every state change is a record, not an overwrite"
description: "'B replaced A' was visible in the graph, and why was not recoverable from anything."
---

**Status:** accepted
**Date:** 2026-10-13

## Context

"B replaced A" was visible in the graph. *Why* was not recoverable from anything,
and the gap was not a missing feature so much as four `if` statements that
decided and forgot.

The resolver's reasons -- newer `asserted_at_ms` wins, equal timestamps
contradict, a late arrival is born superseded, a weaker source may not supersede
-- lived entirely in control flow and were discarded the moment the branch
returned. `_mutate_claim` loaded a payload, mutated the model and wrote it back,
**discarding the prior value**. Nothing recorded an actor, because nothing had
one to record.

With several agents writing, that is the question an owner asks first.

## Decision

**An append-only `:Mutation` record, modelled on the read log.**

Three shapes were available and the first two are insufficient rather than wrong:

- **An actor on `Provenance`.** Created once with the object, so it answers "who
  wrote this" and structurally cannot answer "who later changed its status" --
  the second writer would have to overwrite the first's, which is the failure
  mode rather than the fix. It exists too, for the question it does answer.
- **Properties on `SUPERSEDES` and `CONTRADICTS`.** Attractive because the edge
  *is* the state change. Insufficient three ways: a status change with no edge
  has nowhere to go; `MERGE` lets a re-link overwrite the first writer; and
  `edges_among` feeds the neighbourhood read, which discloses edge *types* only,
  so edge properties there would be a new disclosure surface in the one read that
  drops rather than withholds. They are written anyway as a denormalisation, `ON
  CREATE` only, so a history read can name an actor without a second query while
  the log stays the authority.
- **An append-only record.** Chosen. Nothing overwrites a prior actor.

### What an entry carries

`object_id`, `kind`, `field`, `before`, `after`, the actor triple, `grant_fp`,
`reason`, and `rule`.

`before` is read back from the store rather than reconstructed from what the
caller believed was there -- `_mutate_claim` parses the payload anyway, so a
snapshot costs one parse and makes it a fact.

`rule` is a **closed set of names**, each one a branch that already existed and
already threw its reason away. An unknown value raises: a typo would read as a
real reason forever, and a genuinely new branch belongs in `RULES` beside the
others.

`reason` is prose and capped at 500 characters, like `ReadEntry.subject` and for
a second reason: an uncapped reason field is where a model dumps its entire chain
of thought, and what is wanted is the consolidated statement of why.

### Attribution cannot be omitted

`set_claim_status` and `set_fulfillment` take `actor`, `reason` and `rule` as
keyword-only arguments with **no defaults**, so an unattributed change does not
resolve. The same shape as `link` refusing an unscoped write rather than warning
about one: the caller cannot forget, because there is nothing to forget.

### Creation is recorded, and that is the important half

The mock corpus's supersessions are entirely within one batch: the resolver marks
the earlier claim superseded before anything is written, so it is stored
*already* superseded and there is no transition for `set_claim_status` to notice.
Recording only transitions logged nothing at all for an ordinary ingest.

Claims only. An entity or an event is an ingested fact arriving, while a claim is
an assertion the record now makes, and logging all three would bury the decisions
under the material they were derived from. `upsert` reports whether it created the
node, so an entity mentioned in five records is not recorded five times -- the
same overcount `IngestionResult` already refuses to make.

## Alternatives

- **Keep a previous-payload column on the node.** One step of history, overwritten
  by the next change, and no actor.
- **Reconstruct history from the supersession edges.** They are the only history
  that exists today, and they record what changed rather than why or by whom.
- **Log to a file or a fourth datastore.** The read log's argument applies: an
  audit record of a graph change is most useful where the graph is, and a fourth
  store for a few hundred bytes per write is not worth the backup story.

## Consequences

- `:Mutation` carries **no `:Memory` label**, so the system's record of its own
  changes can never be retrieved as memory. It is the third such label, and one
  parametrised test now covers all of them.
- This database now has **two** things that cannot be regenerated from source
  material: the read log and the mutation log. Agent sessions are a third in
  practice.
- `POST /memory/mutations` is owner-authenticated, with no MCP tool and no
  grant-authorised path: read wholesale it would tell one agent what every other
  agent has been writing to the same memory. A briefing surfaces mutations only
  for objects the asking agent was just permitted to see.
- The resolver's `Resolution` now carries its decisions out, which is what made
  `reconciled_into` writable (ADR 0021's neighbour, implemented alongside).
