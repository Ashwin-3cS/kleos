---
title: "ADR 0025: Reasoning across sessions, and why its output is a claim"
description: "The harness reasons twice, and both times narrowly."
---

**Status:** accepted
**Date:** 2026-10-20

## Context

The harness reasons twice, and both times narrowly.

**At write time, pairwise.** The resolver compares one new statement against
stored claims about the same subject and decides supersession, contradiction or
reconciliation. It is deliberately subject-scoped and claim-at-a-time: making it
corpus-wide would mean every ingestion reads the whole graph.

**At session close, blind.** `consolidate_session` reads one session's blocks
(`graphs/decide.py:379`) and hands them to a consolidator whose signature is the
whole story — `consolidate(blocks)` (`extraction/consolidate.py:201`). No stored
memory, no other sessions, no other devices. It asks what *this* session
concluded, and it cannot ask anything else.

Nothing reasons over the accumulated whole. Four sessions across two devices can
all be about project Lantern, and the harness will have formed a view of each
one separately and of none of them together. A conclusion that only exists in
the pattern across them — "every datastore decision on this project has been
reversed within a week", "two agents are working from incompatible assumptions
about the same artifact" — has nowhere to come from, because no component ever
looks at more than one session at a time.

The briefing (ADR 0021) does not close this. It composes reads at request time
and renders a line per thing worth knowing. It retrieves and formats; it does
not conclude.

This matters because the product claim in the README is several agents and
devices sharing one mutable graph that *aggregates what each of them learns*.
Aggregation is the one verb nothing implements.

## Decision

**A reasoning pass that spans sessions, and whose output is a claim.**

```
several sessions, several devices, one subject
   │
   ↓  pass reads the stored claims and the sessions' blocks
   │
   ↓  concludes what none of them stated individually
   │
   ↓  writes it as a Claim, through the resolver, under a grant,
      recorded as a :Mutation naming the harness as the actor
```

### The output is a claim, not a block

This is the decision. The alternative — storing reasoned prose for agents to
fetch — fails on one property: **a block cannot be superseded.**

Every correction mechanism in this system operates on claims. Supersession,
contradiction, reconciliation, status, `asserted_at_ms`, the device that
asserted it, the rule that fired, the read log that records its disclosure.
Prose has none of them. Store a paragraph and you have something in memory that
can go stale and that the machinery built to fix exactly that cannot touch. The
Lantern decision reverses tomorrow; every claim updates, and the paragraph still
says what it said, with an authenticated device id attached.

The codebase has already refused two smaller versions of this. `RuleBasedConsolidator`:
*"a regex cannot tell what a session concluded, and one that guessed would write
invented claims into a real person's memory under an authenticated device id."*
And `_declared_claim`: *"relying on a model to notice would make the one path
with an explicit declaration the least reliable one in the service."* Both are
about not letting a guess enter memory wearing an identity. A prose block is
that, with less structure to check it against.

Claims also compose with what exists rather than beside it. A cross-session
conclusion that is a claim gets compared against stored memory by the resolver
on the way in, shows up in `why_did_this_shift`, and is quoted by the briefing
with its reason — all of it for free, because it is the same kind of thing
everything else already is.

### It writes through the same door as every other write

`may_write` on the grant, the resolver, a `:Mutation`, canonicalisation,
sealing. ADR 0017 made an agent's write go through a capability check; a
reasoning pass that wrote directly would be the first write path in the service
without one, and the one hardest to notice because nobody asked for it.

### Its authority is `reference`, never `delegate`

A cross-session conclusion is derived by the harness. No device said it and no
person decided it, so under ADR 0016 it has no device identity to stand behind
and under ADR 0017 it is not entitled to replace one. It may contradict a stored
claim — visibly, with both sides kept — and it may never supersede the owner's
own decision or an agent's stated one.

This is the load-bearing constraint on the whole feature. A machine-derived
inference that could supersede would let the harness quietly overwrite what
somebody decided, which is the opposite of the thing being sold.

### The actor is the harness, and it says so

Attribution gets a new kind of actor. `identity_basis` must not read
`device_key` for it: nothing authenticated it, because nothing could. The
briefing's advisories name the device and state whether that identity is
authenticated precisely so a reader is never left assuming a label means
something, and a derived conclusion has to be legible as derived.

### It reads stored memory, so it belongs inside the boundary

The pass reads already-stored claims across sessions. That is the same exposure
as `resolution/resolver.py:221`, which ADR 0024 identified as the sharpest of
the four plaintext touchpoints and the easiest to miss: sealing at rest protects
the database, not the running process.

So this depends on step 5 — extraction and resolution into the enclave — and the
model call goes out from inside, over the TLS tunnel `services/http.rs` already
runs for four upstreams, with the hostname a compile-time constant so a
host-supplied endpoint cannot redirect it. **The model does not run in the
enclave.** It is one more `Upstream`, a loopback alias and a forwarder line.

What that tunnel does not buy: the provider still sees the prompt. TLS from
inside the enclave protects it from the operator, not from whoever answers. A
self-hosted model is the only version where "we never see what it says" survives
a reader who hears it as "nobody does".

### It runs on a threshold or a request, never continuously

A pass per appended block would reason about nothing and bill for it. A pass on
a timer would do the same, less often. The trigger is **N new sessions touching
a subject, or an explicit call** — and the cost is per-pass and unbounded by
top-k, unlike `assemble`, so it needs a budget rather than an assumption.

### Concluding nothing is a correct outcome

Claim ids are content-addressed over the statement, so the same conclusion twice
is the same claim and repeated passes are idempotent on identical text. Beyond
that, a pass that finds no cross-session pattern must write nothing and report
that as success — the same stance `RuleBasedConsolidator` takes. A pass that
always produces something is a pass that invents.

## Alternatives rejected

**Materialise the briefing.** Pre-compute what `brief_before_acting` composes
and serve it from storage. Safe — every line traces to a claim id — and it was
the leading option. Rejected on three counts: it buys latency and cost, not
capability, and nothing measured says the briefing is slow; a cached block that
goes stale reads authoritative with attribution attached, which is the worst bug
class available in a system whose product is *what is true now*; and correct
invalidation needs a dependency graph from claims to the blocks that mention
them, which is more work than the thing it speeds up. Revisit when there is a
measurement, not before.

**Synthesise prose context blocks.** What was asked for first. Rejected for the
reasons under "The output is a claim": it cannot be superseded, the codebase has
twice refused weaker forms of it, and it reverses ADR 0024's pin that `assemble`
formats rather than synthesises. The requesting agent has its own model and its
own context window; citations it can check beat prose it has to trust.

**Make the resolver corpus-wide.** It already compares against stored memory, so
widening it looks cheap. It is not: the resolver runs on every ingestion, and a
corpus-wide comparison there would put a whole-graph read on the write path of
every record. The pairwise, subject-scoped shape is what keeps ingestion linear.

**Reason on the device instead.** The agent has a model and the plaintext, so it
could do this itself. Rejected because it cannot see the other devices' sessions
— that is the entire point — and a device that could would be a device holding
the whole graph.

## Consequences

- **A new actor appears in the attribution record**, and it is not a device.
  Every surface that renders an actor has to say "derived by the harness" without
  implying anything authenticated it.
- **It is gated on step 5.** Run before that, it reads unsealed stored claims in
  a host process, which is precisely the exposure the confidentiality program
  exists to close. Building it earlier against mock sealing is fine; shipping it
  is not.
- **Cost is unbounded by top-k.** Every other model call in the service is one
  record or one session. This one is "several sessions on a subject" and needs a
  budget, a trigger threshold, and a way for an owner to see what it spent.
- **Quality is unmeasured.** ADR 0006 and 0007 exist because the central bet had
  to be measured before anything was built on it. The same applies here, and more
  sharply: this pass writes claims nobody asked for. The eval harness covers it
  before it writes anything real.
- **It does not reopen ADR 0024.** `assemble` still formats. Reasoning happens on
  the write side, produces claims, and the read path keeps calling no model.
- **`consolidate(blocks)` stays.** Per-session consolidation is not replaced by
  this; it is what produces the claims the pass then reasons across. Two passes
  with different questions, the same way `extract_page` and the activity prompt
  are two prompts rather than one.
- **The provider sees the plaintext.** Named here because the tunnel makes it
  easy to forget: the enclave's TLS protects the prompt from the operator and
  from nobody else.
