---
title: "ADR 0007: Measure disclosure, not only recall"
description: "mem0 is the closest thing to prior art for this project, and its evaluation page is the clearest statement of what the field currently considers 'a good memory layer'."
---

**Status:** accepted
**Date:** 2026-10-02

## Context

mem0 is the closest thing to prior art for this project, and its evaluation page
is the clearest statement of what the field currently considers "a good memory
layer". Worth reading closely before extending our own harness, because it is a
serious benchmark suite and we should borrow what is good in it rather than
inventing a parallel vocabulary.

**What mem0 measures.** Three benchmarks — LoCoMo (~300 questions over 10
conversations: single-hop, multi-hop, open-domain, temporal), LongMemEval (500
questions over 6 categories including knowledge updates and preference
following), and BEAM at 1M and 10M token scales. Answers are scored by an LLM
judge with a stated ±1 point confidence interval from judge inconsistency. Two
numbers per benchmark: accuracy, and mean tokens per query.

| benchmark | accuracy | mean tokens/query |
|---|---|---|
| LoCoMo | 92.5% | 6,956 |
| LongMemEval | 94.4% | 6,787 |
| BEAM 1M | 64.1% | 6,719 |
| BEAM 10M | 48.6% | 6,914 |

Their headline framing is **token efficiency**: sub-7,000 tokens per query
against the 25,000+ a full-context approach spends.

**What mem0 stores.** Three layers — a vector database (memory text,
embeddings, timestamps, categories), a graph/entity store (entities and linked
memory ids), and SQL for history and message windows. Extraction is
**ADD-only**: new facts coexist with old ones rather than overwriting them.

That last detail is the important one. "Coexist rather than overwrite" is the
same instinct Kleos has — an old belief should not be destroyed by a new one —
but it stops one step short. Two facts that coexist with no link and no status
leave "which of these is true now?" to whatever model reads them later. Kleos
adds the link and the status: a superseded claim is stored *as superseded*,
pointing at what replaced it. Our own eval already measures what that is worth,
and it is the single largest gap between the resolved path and plain retrieval
(unmarked-stale 0% vs 50%).

So the two projects are optimising different things, and neither metric set
catches the other's failure:

- mem0 asks **did the system answer correctly, and how cheaply**. It does not
  report whether an answer presented a superseded fact as current — an LLM judge
  marking an answer "correct" cannot see that the retrieved context contained
  three contradictory versions and the model guessed well.
- Kleos asks **was the answer right about what is still true, and did anything
  leave that should not have**. We do not report tokens, and we have no
  comparable public-benchmark number at all.

## Decision

Keep our labelled, deterministic, record-level harness as the gate, and extend
it along the axis that is actually ours. Three changes, in priority order; this
ADR commits to the direction and the first is the one that matters.

**1. A disclosure metric, which nobody benchmarks.** The harness currently
measures what the right grant *retrieves*. It does not measure what a wrong
grant *gets*. For a privacy-first memory layer that is the metric: for every
question, run it again under a grant that should see nothing, or that should see
a strict subset, and assert the disclosed set is exactly the permitted set.
Expected value is zero leaked objects, and the point is not discovering a
surprise — it is that the number exists, is reported, and fails the build when it
moves. Recall measures usefulness; this measures the claim the product is sold
on, and it is cheap because the corpus and the grants already exist.

**2. Tokens egressed per answer, reframed.** mem0 is right that context size is
the number to watch, and wrong — for our purposes — about why. Their framing is
cost and latency. Ours is that **every token sent to an external model is a
disclosure**, and the privacy gateway's minimal-context builder (roadmap step 2)
is the component that bounds it. So we adopt the measurement and change its
units: not dollars per query, but how much of a person's memory left the
boundary to answer one question. A system that answers at 7,000 tokens leaks
less than one that answers at 25,000, whatever either costs. That makes mem0's
headline number directly comparable to ours while meaning something different.

**3. An ADD-only baseline, replacing plain RAG as the thing to beat.** Our
current baseline is chunk-and-cosine, which is the obvious thing and a fair
opponent, but it is no longer the strongest one. A baseline that extracts facts
and lets old and new coexist without supersession links is both closer to the
state of the art and a sharper test: it isolates *the link and the status* rather
than *extraction itself*. We expect it to beat plain RAG on recall and to score
just as badly on unmarked staleness, which if true is the clearest statement of
what Kleos adds.

**Not adopting the LLM judge.** ADR 0006 already rejected one, and reading
mem0's stated ±1 point interval from judge inconsistency confirms it. A judge is
the right tool for scoring free-prose answers at scale, and the wrong tool for a
gate whose job is to print "stop and rethink": a judge that can drift a point in
either direction cannot be trusted to hold a threshold, and a harness that can
be accidentally lenient about its own product's central claim is worse than no
harness. Our answers reduce to sets of source records, which is exactly the shape
that does not need a judge.

**Running LoCoMo and LongMemEval is worth doing, later and separately.** They are
public, they are what the field compares on, and we currently have no external
number. But they test conversational recall, not currency and not disclosure, so
they would tell us whether retrieval is competitive — not whether the thing we
are building works. They belong after a real embedder exists, because running
them on hashed-token vectors would produce a number that embarrasses the design
for a reason that has nothing to do with the design.

## Alternatives

- **Adopt mem0's benchmark suite wholesale and report accuracy and tokens.**
  Immediately comparable, and it would make the project legible to anyone who
  has read their page. Rejected as the *primary* gate because it measures none
  of what differentiates this: not currency, not disclosure, not provenance.
  Optimising for it would be optimising to look like mem0.
- **Report accuracy via an LLM judge for comparability, alongside our own
  metrics.** Tempting, and may happen for the public benchmarks. Not for the
  gate, for the reason above.
- **Treat token count purely as cost and ignore it.** What we do today. Wrong
  once an external model is in the path, because at that moment context size
  stops being an efficiency number and becomes the size of the disclosure.
- **Keep plain RAG as the only baseline.** Easier, and increasingly a straw man
  as fact-extracting memory layers become the norm.

## Consequences

- The harness gains a metric whose expected value is zero. That is unusual and
  deliberate: a leak metric reading 0% every run is the evidence, and the day it
  reads anything else is the day it earns its existence.
- We will have two kinds of number — ours, deterministic and hard to game but
  private to this repo; and eventually the public benchmarks, comparable but
  measuring something narrower. Both get reported, with that distinction stated,
  because quoting only the favourable framing is how evaluation pages stop being
  worth reading.
- An ADD-only baseline means implementing a second resolution strategy purely to
  compete against, which is real work for no shipped feature. Justified only
  because what it isolates — the supersession link — is the product.
- mem0's token numbers now sit in our head as a target with the units changed.
  That is a good constraint to inherit: it means the minimal-context builder has
  a number to beat from the day it is written, rather than being tuned by taste.
