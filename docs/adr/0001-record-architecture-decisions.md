# ADR 0001: Record architecture decisions

**Status:** accepted
**Date:** 2026-10-01

## Context

Until now this repo's reasoning lived in two READMEs and in commit messages.
That worked while there was one author and one running argument, and it is
why the READMEs are unusually long: every decision had to be re-justified in
prose next to the thing it governed.

`PLAN.md` changes the shape of the problem. It runs eight phases past the
current state, and several of its decisions are explicitly deferred — where
extraction runs, whether `assemble` synthesises, what the retention policy
is. Those will be decided once, months apart, by someone who no longer
remembers the alternatives that were rejected. A README says what the system
does; it is a poor place to record what it deliberately does not do and why.

## Decision

One ADR per architectural decision, in `docs/adr/NNNN-slug.md`, numbered
sequentially and never renumbered. Each states: context, the decision,
the alternatives considered and why they lost, and the consequences —
including the bad ones.

An ADR is immutable once accepted. A later decision that reverses it gets its
own ADR and marks the earlier one `superseded by NNNN`. That is the same
discipline the memory schema itself uses for claims: a superseded decision
stays readable next to the one that replaced it, because the question "why
did this change?" is answerable only if both are still there.

The READMEs keep describing *what is true now* and stay the entry point.
ADRs carry the argument. A decision that is only visible in a commit message
is not recorded.

## Alternatives

- **Keep everything in the READMEs.** They are already 35KB and 15KB. Adding
  the deferred Phase 2–7 decisions would bury the "how do I run this"
  material that a reader actually arrives for, and prose edited in place
  loses the rejected alternatives.
- **Rely on commit messages.** They are already written decision-first in
  this repo, which is why this was tempting. But they are keyed by *when* a
  change happened, not by *what* it governs, and a decision revisited across
  three commits has no single address.
- **A single `DECISIONS.md`.** One file, append-only. Cheaper, and fine for
  a handful of entries; it degrades into an unnavigable log at the scale
  `PLAN.md` implies, and gives no stable anchor to cite from code comments.

## Consequences

- Every phase in `PLAN.md` that names an ADR now has a place to put it, and
  the plan can be checked off against files rather than memory.
- Code comments can cite `ADR NNNN` instead of restating the argument, which
  should slow the READMEs' growth.
- Cost: a decision made in a hurry and not written down is now a visible gap
  rather than an invisible one. That is the point, but it does mean the
  directory is only as useful as the discipline behind it.
