# ADR 0009: Affect as a closed vocabulary that raises the sensitivity floor

**Status:** accepted
**Date:** 2026-10-02

## Context

A memory layer that knows *what kind* of thing a stored body is can answer
questions the graph otherwise cannot: what was I anxious about last spring, which
conversations about this project were the hard ones, when did the tone of this
working relationship change. Timestamps and entity links do not carry that; a
plain vector index carries it only accidentally, through whatever words happened
to appear.

So we want a mapping from a stored body to its register. The question is where it
lives and what it is allowed to contain, and both answers are forced by the fact
that this is the most sensitive metadata in the system. "This transcript is about
grief" is a more intimate disclosure than most of the transcript.

Two near-misses were on the table, and both are the obvious thing to do.

**Free-text tags.** The natural shape: let the extractor describe the content.
This fails on a specific, predictable path. A field built for filtering gets
indexed, logged, included in debug output, and read without opening the body —
and an LLM extractor handed a free-text metadata field will eventually write
`"anxious about the biopsy results"` into it. At that moment the single most
sensitive sentence in the record is sitting in the one place designed to be read
cheaply and often. No review process prevents this reliably; the type system can.

**Walrus Quilt patch tags.** Quilt offers immutable, Walrus-native per-patch
metadata precisely so an item can be selected without being downloaded, which is
exactly the operation we want. It is also plaintext, public, and permanent. A tag
reading `tone: grief` beside a sealed body would publish a searchable affective
index over someone's life, next to the ciphertext that was the point of sealing
it, with no way to retract it. See ADR 0008.

## Decision

**A closed vocabulary.** `AffectTone` is a ten-variant enum —
neutral, joy, relief, affection, frustration, anger, anxiety, sadness, shame,
grief — in both language mirrors, rejected on deserialization if unknown. It
cannot carry content. That is the entire argument for a closed enum here, and it
is the opposite of the decision made for `SourceId`, which is deliberately open
because the enclave must not need a rebuild to learn a new connector. The
difference: an unknown source id can be safely *denied*, while an unknown affect
label is a field whose sensitivity we cannot reason about.

**A facet, not a node type.** `Affect` is an optional field on `Event`, beside
`encrypted_content`, for the same reason `Commitment` is a facet on `Claim`: it
describes something already stored, and a parallel node type would duplicate the
provenance and ACL machinery that governs it.

**No free-text field of any kind.** `tone`, `intensity` (0..1), `confidence`, and
`detected_by` (the extractor id, same contract as `Provenance.derived_by` — an
affect label is a derived claim and a reader is entitled to know what derived
it). A Rust test asserts structurally that the only strings a serialized `Affect`
contains are `tone` and `detected_by`, so a future field that opens the door
fails the build rather than passing review.

**Affect raises the sensitivity floor and never lowers it.** Each tone maps to a
minimum `Sensitivity`: the ordinary registers to `Personal`, affection, anxiety
and sadness to `Confidential`, shame and grief to `Restricted`. `raise_to_floor`
takes the stricter of the declared sensitivity and the floor, and is called where
an ACL is built — never where it is checked, so `permits` stays pure over
`(scope, acl)` and does not grow a second notion of what an object's sensitivity
is.

This is the property that makes the label defensible: **tagging a body narrows
who may read it.** A connector declares sensitivity from the source it came from
and cannot know that one conversation in an export was about a death. The affect
label is how that gets corrected, which means the metadata protects the content
it describes rather than exposing it. A tested invariant holds the direction — no
tone may map below `Personal`, because a tone that did would make tagging a way to
*widen* access.

## Alternatives

- **Free-text tags.** Rejected above. The failure is not hypothetical; it is the
  default behaviour of the component that would populate the field.
- **Valence and arousal instead of a category.** The standard affective model, and
  genuinely more expressive. Rejected because two floats cannot be mapped to a
  sensitivity floor without a threshold nobody can defend, and because "which
  conversations were about grief" is a categorical question. `intensity` keeps
  the part of the model that was load-bearing.
- **Store affect only on the encrypted ref.** Closer to how the request was
  framed ("this blob id has this kind of emotional data"). Rejected because it
  would mean only *sealed* bodies can carry affect, when an unsealed one has the
  same register. Keeping it on the event preserves the mapping — the event holds
  both the ref and the affect — and generalises.
- **Do not store affect at all.** The most conservative answer, and the one to
  fall back to if the floor mechanism ever has to be removed. The reason not to:
  the questions it answers are the ones a person actually asks of their own
  memory, and refusing the whole category to avoid a field design problem is a
  worse trade than solving the field design.

## Consequences

- There is now a queryable affective index over a person's memory, which is a
  capability and a liability in the same object. The liability is bounded by the
  closed vocabulary, by the floor, and by `permits` applying to it like anything
  else. It is not bounded from the **operator**, who reads Neo4j in the clear —
  and affect metadata makes that existing gap materially worse, because "grief,
  intensity 0.9" beside entity names and timestamps is a more intimate record
  than the events it annotates. This sharpens the case for deciding where
  extraction runs sooner rather than at roadmap step 4.
- Nothing populates `affect` yet. The schema, the floor and the invariants are
  in; the extractor that sets it, the promoted Neo4j properties that make it
  indexable, and the read that uses it are not. A facet no writer sets is inert,
  which is the right order — the vocabulary and the floor had to be settled
  before anything could write to them.
- A tenth enum variant is a lot of variants to justify, and the vocabulary will
  be wrong at the edges. Extending it is a schema change in two languages plus a
  floor decision, which is deliberately more friction than adding a string.
