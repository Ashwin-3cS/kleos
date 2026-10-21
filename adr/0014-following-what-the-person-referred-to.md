---
title: "ADR 0014: Following what the person referred to"
description: "*'I learnt RAG from this URL'* contains two things: an assertion about the person, and a pointer to something they read."
---

**Status:** accepted
**Date:** 2026-10-02

## Context

*"I learnt RAG from this URL"* contains two things: an assertion about the person,
and a pointer to something they read. ADR 0013 gave the first a home. The second was
stored as characters in a body and followed by nothing.

Doing something about it crosses a line the service had not crossed. Until now every
byte in memory came from somewhere the person controls: their mailbox, their export,
their own typing. Fetching a page means putting **content a stranger wrote** into a
person's memory, through an LLM that will faithfully extract whatever that content
asserts. A page that says *"the user has decided to use Postgres"* is a prompt
injection with a plausible delivery mechanism, and the target is not a chat
transcript — it is the record the person relies on.

So this is as much a decision about what a fetched page is *allowed to do* as about
how to fetch one.

## Decision

A tool layer, a conditional edge in the ingestion graph, and three rules.

### The tool layer mirrors the connector registry

`ToolSpec` and `ToolRegistry` are deliberately shaped like `ConnectorSpec` and
`ConnectorRegistry`: declare a spec beside the implementation, validate the id, reject
duplicates loudly, allow a per-run `copy()`, narrow a deployment with `ENABLED_TOOLS`
the way `ENABLED_SOURCES` already narrows one. A second plugin pattern with different
semantics would be a second thing to keep correct for no gain.

Two differences that are decisions rather than copying:

- **Every tool returns a `ToolResult` rather than raising.** A tool failing is an
  ordinary outcome — a page is gone, a host is down — and whatever drives tools has to
  record the attempt either way. Raising would make "tried and failed"
  indistinguishable from "never tried", which is the distinction a trace needs to
  keep.
- **`writes_memory` and `reaches_network` are declared per tool.** "Which tools can
  write" and "which reach outward" are the questions an audit asks first, and they
  should be answerable from the registry rather than by reading code. Both tools here
  declare `writes_memory=False`: they *produce* candidates, and the ingestion graph
  decides what is written.

### `fetch_url`, and why each guard exists

This is the first thing in the service that aims at a target someone else chose.

- **Resolve first, then judge the addresses.** A blocklist on the *name* is worthless:
  the attacker controls their own DNS. Verified — `127.0.0.1.nip.io` is an ordinary
  public name that resolves to loopback, and only a post-resolution check catches it.
  Every address a name answers with is checked, not the first, because which one gets
  connected to is not ours to decide.
- **Link-local is called out separately** because `169.254.169.254` is the cloud
  instance metadata service, where an SSRF is credential theft rather than an
  information leak.
- **Every redirect hop is validated**, with `follow_redirects=False` and a manual loop.
  Nobody submits a private URL; they submit a public one that 302s to a private one,
  and a guard that validates only the first URL validates nothing.
- **The body is capped while streaming.** `Content-Length` is a claim, not a fact.
- **Content types are allow-listed**, because the failure of a deny-list is silent.
- **Ports are restricted to 80 and 443.** Most of the value of a port rule: the
  interesting internal targets — 6379, 5432, 9200 — are all on non-standard ports.
- **HTML to text with the stdlib.** `HTMLParser`, forty lines, no BeautifulSoup. A
  dependency earns its place by doing something harder than that.

Two things not done, recorded so they are decisions rather than oversights:

- **DNS rebinding is not solved.** Between resolving a name and connecting, DNS can
  change. Pinning the connection to the validated address means driving the socket and
  setting SNI by hand, which is a large change for a user-initiated fetch. The
  practical attack it leaves is reaching an internal host on a machine where the
  attacker already chose the URL; the easier versions are covered.
- **robots.txt is not consulted.** This fetches one page a person has just said they
  read, on their explicit instruction. It is not a crawler: no traversal, no
  scheduling, no bulk. If it ever discovers its own URLs that calculation changes and
  robots must be honoured.

### `extract_page` uses a different prompt, not a different model

Pointing the activity prompt at a reference page produces nonsense of a specific kind:
the model reports that "the author decided that RAG will use a vector store" — a claim
attributed to nobody, about a decision nobody made, now in a person's memory as though
they had made it. So the page prompt asks for what the page is *about* and what it
asserts, with no actor and no commitments, and says outright that a page cannot owe
anyone anything.

**A read budget, because the first live run failed outright.** A Wikipedia article is
~24,000 characters of text and the provider returned `413 Payload Too Large`. Reference
pages front-load their definitions, so the opening is where "what is this" lives. The
stored event body is truncated to the same budget, so what is kept is exactly what the
extractor saw, and `truncated_from_chars` records that it was part of a page.

### The first conditional edge in this codebase

`enrich` sits between `extract` and `resolve` — the page's claims have to be in the
candidate set *before* the resolver runs, so they are compared against stored memory by
the same machinery and under the same precedence rule as everything else.

Conditional because most records contain no URL, and a node that runs unconditionally
to discover it has nothing to do is a node that will eventually be made to do something
anyway. **Off by default** (`ENRICH_FROM_URLS=false`): reaching the open web on
someone's behalf should be a deliberate choice, not something a fresh checkout does.
Bounded by `ENRICH_MAX_PAGES`, because a note with forty links is a reading list, and an
unbounded fetch loop driven by text someone else may have written is the shape of an
amplification attack.

### The three rules

Not configurable. Each exists because of a specific way this goes wrong.

**1. A web-derived claim can never supersede a user-derived one.** This is the whole
mitigation for prompt injection. A page saying "the user has decided to use Postgres"
extracts as a claim about Postgres, lands in the same subject neighbourhood as the
person's real decision, and — being newer — wins on timestamp. Timestamps are the right
tie-break between two things the person said and exactly the wrong one between
something they said and something a stranger wrote. Blocked in the resolver by source
precedence, so it holds for every path in. Deliberately asymmetric: the person's later
claim *may* supersede a web-derived one, because learning that a page was wrong is
normal. Blocked, not dropped — recorded as a contradiction, so the disagreement stays
visible with neither side overwriting the other.

**2. Fetched material is its own source at public sensitivity.** `sources=["web"]`, not
the referring utterance's source. If a page's claims carried `["text"]`, then "read my
notes" would silently include everything any page those notes linked to asserted — and
`permits()` would be right to allow it, because the object would be claiming to be a
note. Public sensitivity is accurate rather than a weakening, and it is what lets a
scope exist for an agent that may read what you read without reading anything about
you.

**3. Provenance records the tool.** `derived_by` becomes
`fetch_url+llm-extractor@<model>`, so a claim read off a page is distinguishable from
one the person made. Without it the two are identical in a stored record, which is rule
1's failure one layer down.

Verified in the real graph: 4 objects at `text`/`personal`, 28 at `web`/`public`, CITES
edges linking the page's claims to the utterance, and a `text`-only grant seeing 4 of
32 objects.

## Alternatives

- **Fetch inside the extractor.** Fewer moving parts, and it buries an outbound network
  call inside something whose job is to parse one record — and gives the tool layer no
  place to exist.
- **Follow URLs found on fetched pages too.** One line, and it turns a bounded
  user-initiated fetch into a crawler, with the budget as the only thing between it and
  the open web.
- **Let the model decide whether a page is trustworthy.** Rejected outright: it would
  put the mitigation for prompt injection inside the thing being injected.
- **A separate `web` graph rather than a node in the ingestion graph.** The page's
  claims would then not be resolved against the person's memory, which is the entire
  reason to extract them.
- **Trust the extractor to set the source and sensitivity.** It is handed a record and
  faithfully carries whatever that record claimed, so the place to be certain is the one
  point where tool output becomes a candidate. Forced there instead.

## Consequences

- An utterance containing a URL now produces reference knowledge linked to it by
  `CITES`, which the existing context-chain read already walks — so "what did I learn
  this from" works with no new read.
- **A fetched page produces a lot of objects**: one Wikipedia article gave 12 entities
  and 15 claims against the utterance's 2 and 1. The budget bounds pages, not objects
  per page. Whether that is enrichment or flooding is a retrieval question, and the
  eval is what should answer it.
- Two bugs found by running it, both recorded in tests. The title-truncation bug: a
  title is the first ninety characters of the body, the truncation cut a URL in half,
  the fragment was *also* a real page, and it fetched both silently — so URLs are now
  scanned from the body only. And `<title>` lives inside `<head>`, which the text
  extractor skips, so the skip check short-circuited before the title check and every
  page title came back empty.
- Enrichment is off by default, so none of this runs unless asked for. That makes it
  easy to forget it exists; the `GET /sources` listing showing `web` is the only hint.
