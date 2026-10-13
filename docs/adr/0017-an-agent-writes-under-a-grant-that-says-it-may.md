---
title: "ADR 0017: An agent writes under a grant that says it may"
description: "The memory had one writer: the person, through their own sources or their own typing."
---

**Status:** accepted
**Date:** 2026-10-13

## Context

The memory had one writer: the person, through their own sources or their own
typing. Agents could read it and nothing else, which was the right shape while
there was one agent and the layer was a place to put things.

It is the wrong shape for a harness. An agent that concludes something and cannot
record it leaves the next agent to rediscover it, which is the problem the harness
exists to solve. But an agent writing into a person's record raises a question
reading never did: **what happens when it disagrees with them?**

ADR 0014 answered a neighbouring version of that for fetched pages -- a page may
never supersede the person, because timestamps are the right tie-break between two
things the person said and exactly the wrong one between something they said and
something a stranger wrote. An agent is not a stranger, and not the person either.

## Decision

**One write tool, gated three ways, and precedence that belongs to the grant.**

### The gate

`permits_write(scope, intent, now_ms)` is a sibling of `permits`, not a mode on
it. A mode parameter would mean every existing call site has to say `"read"`, and
the one that forgets gets whatever the default is -- a deny-by-default violation
waiting for someone to add a fifth read path. It also cannot share the signature
honestly: a write has no `ObjectAcl` because there is no object yet, so the
asymmetry is in the type. Reads evaluate `(scope, acl)`; writes evaluate
`(scope, intent)`.

Checked before a record is built, so a refusal is a refusal rather than a run
that ingests nothing, and the deny reason is returned -- a decline that only says
"no" is indistinguishable from a bug.

### The source is not a parameter

An agent writes as `agent`, whatever it asks for. `Scope.write_sources` is a
separate set from `Scope.sources` precisely so an agent permitted to *read* the
person's typed notes cannot write a claim that claims to be one.

**One source id for the class, not one per agent.** The universe of agents is
open, so per-agent ids would put agent naming inside `SourceId` validation, make
every grant scope need rewriting when a new agent appears, and turn
`ObjectAcl.sources` -- which the resolver's precedence rule reads -- into a
cardinality problem. Instance identity lives on provenance (ADR 0016).

### Precedence is a property of the grant

`Provenance.authority` is a closed vocabulary: `Owner`, `Delegate`, `Reference`.
A grant with `may_supersede_owner` produces a delegate; without it, a reference.

Stamped at **the one point where agent input becomes a candidate**, and never
read from an extractor -- ADR 0014's rule, applied to a different writer. A claim
that could nominate its own precedence class could nominate `delegate` and
overwrite the person's own decision.

The resolver then needs to know nothing about grants: `_is_weaker` reads
authority and falls back to the source rule when it is absent, so a reference
claim contradicts the person's rather than replacing it, both sides kept, and the
person's later claim may always supersede either.

### A declared decision is not re-discovered by extraction

An agent calling `record_decision` has already said the sentence is a decision.
The rule-based extractor matches a fixture grammar and finds nothing in "project
Lantern will use Neo4j", so relying on extraction meant mock mode stored the
decision as an event with **no claim** -- a write reporting success and
remembering nothing a query can answer with, and the one path with an explicit
declaration would have been the least reliable in the service.

So the statement is taken as given and nothing else is: subjects come from the
entities extraction found, citations from the event it built, and resolution,
canonicalisation, sealing and the write are the ordinary path -- which is what
keeps a declared claim resolvable against the person's own decisions. Only its
punctuation is normalised, because a stored claim has to be what was actually
asserted.

## Alternatives

- **No agent writes; only `POST /remember`.** Preserves the read-only invariant
  absolutely, and means "device 1 decided this and here is why" exists only if a
  human retyped it.
- **A separate `:AgentDecision` subgraph, promoted by the owner.** Safest: a
  compromised agent cannot pollute the record. Rejected because cross-agent
  supersession detection would then have to work across two graphs, which is two
  chances to diverge -- ADR 0013's argument against a second ingestion path.
- **Let the agent choose its own source or precedence.** Both are the same
  mistake in different clothes: a writer that can describe itself can describe
  itself as the person.

## Consequences

- An agent's claim can supersede the owner's, and only when the owner signed a
  grant saying so. Everything else contradicts, visibly.
- **A sensitive decision cannot be recorded at all.** Sealing needs an owner
  session and an agent holds a grant, so it is refused up front rather than
  skipped inside the graph where it would read as a partial success.
- Two defects found by testing rather than by reasoning: the tacit sensitivity
  floor reached the gate and not the stored object, so a tacit claim was checked
  at `confidential` and written at `personal`; and `sensitive=True` half-succeeded
  into `errors`. Both are fixed and both have tests.
- **Paraphrase accumulation is not solved.** A reworded restatement of an agent's
  own claim gets a new id, matches on topic, and resolves as a supersession of a
  reworded version of itself. ADR 0015's mitigation applies -- fail towards the
  duplicate, record it, let the eval measure it -- and the missing primitive is
  the same one: per-object deletion, which this system still does not have.
