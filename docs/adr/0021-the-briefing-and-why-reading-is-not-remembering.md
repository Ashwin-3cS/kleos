---
title: "ADR 0021: The briefing, and why reading is not remembering"
description: "A shared memory does not help the second agent, because it does not know there is a question to ask."
---

**Status:** accepted
**Date:** 2026-10-13

## Context

A shared memory does not help the second agent, because it does not know there is
a question to ask. Device 1 decides something and records it; device 2 is about to
act on the same subject and has no reason to query for it.

Every read the service had was a *question*: a query, a claim id, a seed. None of
them fit "I am about to do something -- what should I know?"

## Decision

**A read that takes an intent, composes the existing reads, and renders a line.**

```
brief_before_acting(intent, grant_token, session_id, top_k, include_body)
```

### It composes rather than retrieves

`run_query` for what is relevant, `why_did_this_shift` for how a decision got
there, `mutations.for_objects` for who moved it.

Not thrift. Each of those has a permission check inside it and a read-log entry
after it, and a briefing that retrieved for itself would be a fifth read path to
keep correct -- and the first one whose disclosure was not recorded the same way
as the others. One extra entry records the composite, which is what lets an owner
see what the agent was *about to do* rather than only which objects it was shown.

### It renders, because the sentence is the product

`advisories` is one line per thing worth knowing, ready to drop into a context
window without parsing anything. Every line names the **device** and says whether
that identity is authenticated, so a reader is never left assuming a label means
something.

The structure stays available above it for anything that wants it.

### It composes no neighbourhood

That read has no MCP tool on purpose: an adjacency list answers no question an
agent has, and handing one over is a cheap structure-enumeration primitive --
seed, walk, re-seed. A briefing returning adjacency would hand back exactly that
under a friendlier name. Where structure matters here it is a count, never ids.

### A conflict outside the grant is withheld, not dropped

The history reads' contract, for their reason: the agent named a subject, so the
conflict's existence is already implied by the question, and an agent told "no
conflicts" acts while an agent told "a conflict exists you may not read" asks.

The residual is that "a conflict exists" is itself information -- but it is the
same information `why_did_this_shift` already discloses to the same grant, so this
adds no channel it did not have.

### Being briefed is not deciding

The only trace is a read-log entry. If a briefing were itself memory, agent B
reading about agent A's decision would create a claim that agent C's briefing
would surface, which would create another -- a record whose growth is a function
of **how often it is read** rather than of what happened. Within a week the graph
is mostly the system's commentary on itself, and the resolver is comparing
agent-about-agent material against the person's real decisions in the same subject
neighbourhood.

What prevents it is one mechanism, used uniformly: `:AgentRead`, `:AgentSession`,
`:SessionBlock`, `:Mutation` and `:AgentAction` all stay off the `:Memory` label.

## Alternatives

- **A push model: notify agents when something they care about changes.** Needs a
  subscription model, a delivery channel MCP does not have, and a notion of what
  an agent "cares about" that nothing can supply.
- **Let the agent ask the right query itself.** That is the existing surface, and
  it fails for the reason in Context: the agent does not know to ask.
- **Make the briefing a stored object**, so it can be cited later. Rejected above:
  it is the feedback loop.

## Consequences

- The feature works end to end over a real MCP client, and that is the assertion
  `scripts/mcp_smoke.py` exists for.
- **A briefing is only as selective as the ranking underneath it.** Retrieval
  returns its best `top_k` rather than gating on relevance, so an agent briefing
  on an unrelated intent is still told about the decisions that exist. That is the
  right failure direction -- too much context rather than a missed conflict -- but
  it is a property of the ranking, and in mock mode the embeddings are hashed
  tokens and barely selective at all.
- Four defects in what an agent *reads* were found only by driving a real client:
  a refusal that did not survive the transport, a placeholder quoted instead of
  the agent's reason, an advisory describing a relabel rather than the decision,
  and the same advisory emitted several times. All four are fixed and all four
  have regression tests.
