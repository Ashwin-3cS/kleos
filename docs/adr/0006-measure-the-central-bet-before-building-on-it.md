# ADR 0006: Measure the central bet before building on it

**Status:** accepted
**Date:** 2026-10-01

## Context

The whole project rests on one claim: that a **resolved, timestamped record**
(who said what, when it changed, why, what it links to) is worth more than a
pile of retrievable documents. Every design decision in the repo follows from
it — the Event/Claim split, supersession instead of overwrite, provenance as a
citation chain, graph-proximity ranking, the history reads.

It had never been measured. `PLAN.md` Phase 0 makes measuring it the exit
condition, and says explicitly: *if resolution does not help, stop and rethink
before building further.* Phases 1 through 7 add a voice layer, hardware nodes
and a privacy gateway on top of this assumption; finding out it is wrong after
that is the single most expensive mistake available.

## Decision

`orchestrator/src/orchestrator/eval/` — a labelled corpus, a question set, a
plain-RAG baseline, and a harness that prints a verdict. `python -m
orchestrator.eval`, exiting non-zero when the exit test fails so CI can gate on
it.

**A synthetic corpus, written to the mock extractor's grammar.** Fictional
people and projects: no real personal data, per the plan's working rules, and
the only kind of corpus that can live in a public repo. Written to the grammar
on purpose, because the harness measures retrieval and resolution, and a silent
extraction failure would move every metric while looking like a ranking problem.
Extraction quality is a separate measurement against a live LLM.

It is shaped around the cases that distinguish the two designs: a decision that
moved twice (Sqlite → Postgres → Neo4j) with new evidence cited at each step, a
commitment reassigned with an identical statement and deadline so the only
difference is the facet, a second project with a parallel storage decision as a
lexical distractor, and enough filler that returning `top_k` is a choice.

**A baseline that is a fair opponent.** Same records, same per-source chunker,
same embedder, same `top_k`, and it honours a time window. It even sees the raw
bodies that the resolved path seals away — *stronger* than it could legitimately
be in this product. Handicapping it would flatter the comparison, and the point
is to find out whether resolution wins on merit.

**Scored on source records, not object ids.** The baseline cannot name a claim
id, so scoring on claim ids would hand the resolved path a win by construction.

**Three systems reported, not two.** `resolved` is the query graph alone — the
like-for-like retrieval comparison. `resolved+history` adds the supersession
read on the best-ranked claim, which is what the product can actually answer
with. Reporting only the second would be the comparison this harness exists not
to make; reporting only the first would under-measure the design.

**The headline metric is unmarked staleness, not recall.** Returning a stale
record is not wrong — "what changed and why" *should* return all three storage
decisions. What is wrong is presenting superseded content as current. The rule,
fixed before the numbers were read: only an **assertion** can be stale. A claim
asserts and can be superseded; an event records something that happened at a
stated time and never stops being true.

## Result, 2026-10-01

34 records, 3 sources, 6 questions, `top_k=5`, hashed-token embeddings:

| metric | resolved | resolved+history | plain-rag |
|---|---|---|---|
| recall | 87% | **100%** | 93% |
| precision | 33% | 35% | 27% |
| cited | 100% | 100% | 0% |
| unmarked stale | 0% | **0%** | 50% |
| forbidden returned | 33% | 33% | 50% |

**Verdict: resolution helps.** Not uniformly, and the interesting part is where
it does not.

- **The win is correctness about currency, not retrieval.** Plain RAG answered
  "which database does Lantern use" by returning all three decisions, with
  nothing to say which was current — because nothing in the text of a superseded
  decision says it was superseded. That 50% → 0% is the product's thesis, and it
  is structural: no embedder would change it.
- **The query graph alone retrieves *less* than the baseline** (87% vs 93%). The
  report says so in its verdict line. Ranking is not where the value is, which
  is worth knowing before anyone spends time tuning weights.
- **Graph proximity costs precision on the distractor question.** Both Harbour
  questions return a forbidden record under every system. Proximity pulling in
  neighbours is exactly the failure mode the question was written to catch.

Three findings came out of building it, which is the argument for having built
it:

1. **A first version could not discriminate.** `top_k=8` over 16 records meant
   both systems returned half the corpus and scored ~95% recall; `recall@k`
   approaches 1 as `k` approaches `N` however bad the ranking is. The corpus
   grew to 34 records and `k` dropped to 5.
2. **The first staleness metric was wrong**, counting any object from a stale
   record. It scored the resolved path at 50% unmarked-stale while it was in
   fact marking every stale claim correctly — the penalty was entirely events,
   which assert nothing. Hence the assertion-scoped rule above.
3. **A real defect in the product.** The README promises `why_did_this_shift`
   returns "the citations present in the superseder that were absent from the
   claim it replaced — the evidence that moved the decision". The extractor
   attached a record's cross-source references to the *event* and not to the
   claim, so that read reached one hop short of the evidence: present in Neo4j,
   absent from the read built to surface it. "What changed and why" scored 60%.
   With references propagated onto the claim it scores 100%.

Finding (3) is the strongest argument for the harness. It is a documented
promise that the headline read did not keep, it had been in the repo since the
feature was written, and no test caught it because every test asserted the
mechanism rather than the outcome.

## Alternatives

- **Ship on the assumption.** What the plan explicitly forbids, and the
  expensive mistake: seven phases of voice and hardware sit on top of it.
- **Measure on a real corpus (a consenting owner's own export).** More
  convincing and the natural follow-up, but it cannot be committed, cannot be a
  regression test, and cannot be compared across machines. Phase 0's live-LLM
  item is where real data enters.
- **Use an LLM judge instead of labels.** Scales to questions whose answer is
  prose rather than a set of records. Non-deterministic, needs a key, and in a
  harness whose job is to be able to say "stop", a judge that can be
  accidentally lenient is the wrong instrument.
- **Compare against a stronger baseline (BM25 + reranker, or GraphRAG).** The
  fair long-run comparison. Deferred because the current question is whether
  resolution beats the obvious thing, and because the hashed-token embedder
  makes any absolute comparison provisional.

## Consequences

- Phase 0's exit test exists, has run, and passes. `test_eval_harness.py`
  asserts the *direction* rather than the figures, so a regression fails a test
  instead of being a number nobody re-ran.
- The numbers are **not quotable yet**. Both systems run on
  `HashedTokenEmbedder` — the right control, since embedding quality is held
  identical and the delta isolates resolution, but a poor absolute measurement.
  The report prints that warning itself. First thing to do after wiring a real
  embedder is re-run and compare deltas, not scores.
- Two findings are now open work rather than suspicions: the query graph's
  ranking underperforms plain cosine on recall, and graph proximity costs
  precision on cross-project questions. Neither is fixed here — the harness's
  job this round was to find them.
- The harness needs Neo4j but no gateway and no enclave, because the corpus has
  no sensitive records. Running the exit test costs two containers.
- The corpus is now a thing that must be maintained alongside the mock
  extractor's grammar. `test_the_corpus_ingests_cleanly` fails loudly if they
  drift, which is the cheapest available guard.
