# ADR 0003: Recency is a real half-life, and ranking is configurable

**Status:** accepted
**Date:** 2026-10-01

## Context

`retrieval/ranking.py` scored candidates as
`0.6 * semantic + 0.15 * recency + 0.25 * proximity`, with

```python
RECENCY_HALF_LIFE_MS = 30 * 86_400_000
return math.exp(-age_ms / RECENCY_HALF_LIFE_MS)
```

Two problems, one arithmetic and one conceptual.

**The constant was not a half-life.** `exp(-age / H)` reaches `1/e ≈ 0.368` at
`age = H`, not `0.5`. The name promised a 30-day half-life and the code
delivered one of about 20.8 days — 44% shorter. A reader tuning this would have
been reasoning about the wrong curve.

**Thirty days is the wrong order of magnitude for this product.** At that
constant a one-year-old item scored `1.6e-6` on recency. With a weight of 0.15
that is not a tie-break, it is a filter. And the material it filters hardest is
exactly what this system is built to surface: a decision taken a year ago that
nothing has superseded is still the current answer, and "why did this shift"
reads reach deliberately backwards in time. Recency decay that aggressive is
imported from feed ranking, where age really does imply irrelevance. In a
resolved record, `supersedes` carries that signal — not the clock.

Separately, all four numbers were module constants with no way to change them
and no way to evaluate them. Roadmap step 0 ends with an eval harness whose job is to
measure retrieval quality; it cannot tune what it cannot set.

## Decision

Fix the curve: multiply by `ln 2`, so `recency_score` returns exactly `0.5` at
one half-life. A test asserts 0.5, 0.25 and 0.125 at one, two and three
half-lives, and a second test records what the old formula returned so the
defect is documented rather than remembered.

Default the half-life to **180 days**. This is a starting point for the eval
harness to move, not a claim to have found the right number, and the comment in
the code says so.

Move the three weights and the half-life into `Settings`
(`SEMANTIC_WEIGHT`, `RECENCY_WEIGHT`, `PROXIMITY_WEIGHT`,
`RECENCY_HALF_LIFE_DAYS`), carried through the retriever as a `RankingWeights`
value object constructed once per `Runtime`.

Normalise by the weight total, so a score is always in `[0, 1]` whatever ratios
were supplied. Without this, a number reported by the eval harness stops
meaning anything the moment someone retunes the weights, and thresholds
calibrated against one configuration silently misbehave under another.

Break ties by node id. The harness compares ordered result lists, and churn
that is really dict iteration order would read as a quality regression.

## Alternatives

- **Rename the constant to `RECENCY_DECAY_MS` and keep the arithmetic.** Makes
  the code honest with one line and leaves the behaviour. Rejected because the
  behaviour was the bigger half of the problem: a 20.8-day effective half-life
  is wrong for this product whatever it is called.
- **Keep 30 days and fix only the formula.** Would change the effective
  constant from 20.8 to 30 days — still well inside the range where a
  year-old decision scores ~0.
- **Drop the recency term.** Defensible: in a record with supersession links,
  age arguably carries no independent signal. Rejected because recency is a
  genuine tie-break between two otherwise equivalent candidates, and because
  deleting a term is harder to walk back than retuning one. The eval harness
  can test `RECENCY_WEIGHT=0` directly now.
- **Learned ranking.** No labelled data, and the harness that would produce it
  does not exist yet. Revisit after step 0.

## Consequences

- Retrieval ordering changes for anything older than a few weeks: older
  material now competes on semantic similarity and graph proximity instead of
  being effectively excluded. This is the intended change and it is a behaviour
  change, so a regression in the eval numbers is a real signal and not noise.
- Scores are no longer comparable to any number recorded before this ADR.
  Nothing depended on them, and normalisation is what makes future numbers
  durable.
- Four more configuration knobs, which is four more ways to misconfigure a
  deployment. Bounded by validation in `RankingWeights.__post_init__`:
  non-negative weights, at least one non-zero, positive half-life.
- The weights are still a guess. The difference is that they are now a guess
  the eval harness can disprove, which is the only reason this ADR is in step 0
  rather than later.
