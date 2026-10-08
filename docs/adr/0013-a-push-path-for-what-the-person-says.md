---
title: "ADR 0013: A push path for what the person says"
description: "Every source in this service is a **pull**."
---

**Status:** accepted
**Date:** 2026-10-02

## Context

Every source in this service is a **pull**. A connector is handed an owner id and a
watermark and goes to fetch what happened: `fetch(owner_id, since_ms)`. That is the
right shape for a mailbox, a repository or an export, and it is why `POST /ingest`
enqueues a job — connecting a source means pulling a large history in bursts.

It is the wrong shape for someone saying *"I learnt RAG from this URL"*. There is
nothing to go and fetch. The record already exists, and it exists because a person
decided to say it. Until now there was nowhere for that to go: no HTTP route
accepted content, and the only way into memory was to be a source that could be
polled.

That gap is load-bearing rather than cosmetic. Voice and typed notes are the primary
input for what this is becoming, and an architecture where the only way in is a
connector would have meant either a fake connector that reads a spool file, or a
second ingestion path beside the real one.

## Decision

`POST /remember` — `{owner_id, text, source, occurred_at_ms?, sensitive?,
session_token?}` — builds a `RawRecord` and runs it through **the existing ingestion
graph**, with the record pushed in rather than pulled.

### `text` and `voice` are sources, registered like any other

They get a `ConnectorSpec` with a display name and a chunker, because everything
downstream needs them to: the source id is what every `ObjectAcl` carries and what
every grant scope is written against. What they do *not* get is a working `fetch` —
`PushOnlyConnector.fetch` raises, pointing at this route.

Raising rather than returning `[]` is the same honesty the Google and GitHub stubs
practise. A connector that returned an empty list would make `POST /ingest --source
text` look like a successful no-op forever.

They also deliberately have **no `mock_factory`**. A fixture here would make
`ORCHESTRATOR_MODE=mock` return invented utterances, and a source representing "what
the person actually said" is the one place that must never happen.

**Two sources rather than one with a flag.** `text` and `voice` differ in exactly the
way a `SourceId` is for. "Read what I wrote down, not what I said out loud in my
kitchen" is a real distinction someone would want, and `permits()` can express it for
free only if the ids differ. A single source with a metadata flag would put that
distinction somewhere the permission check cannot see.

### One graph, not two

`fetch` gains three lines: if records came in with the invocation, use them. Nothing
else changes. Extraction, resolution, sealing and the write are identical, because a
thing the person said is a record like any other once it exists — and a separate
graph would be two paths that have to be kept resolving the same way, with the
difference only showing up as a supersession that one finds and the other misses.

A test holds that: two utterances stating successive decisions about the same thing
must produce a supersession, exactly as pulled records do.

### Synchronous, unlike `/ingest`

A backfill returns a job id because it is the wrong lifetime for a request. Someone
who has just said one sentence is in the opposite situation: they want to know it
landed, and handing them a job id to poll would be the wrong answer to "did you get
that". Returns the counts and the `external_id`.

### Details that are decisions

- **`external_id` is a content address** over owner, source, text and timestamp. A
  retried request writes nothing new; the same sentence tomorrow is a second record,
  because it is.
- **`url` stays `None` even when the text contains one.** `SourceRef.url` means
  *where this record lives*, and an utterance lives nowhere. A URL inside it is
  something the person *referred to* — a different relationship, which gets its own
  event when it is fetched (ADR 0014).
- **The checkpoint thread is keyed by the record**, not by owner and source. Two
  utterances sharing a thread would have the second resume the first's state.
- **`sensitive` is per request, not per source.** A spoken note is usually more
  intimate than a typed one, but that is a property of the content rather than the
  channel, and sealing requires a session because the gateway takes the owner from
  it. Refused up front when `sensitive` is set without one, rather than failing
  inside the graph where it would surface as a skipped record.

## Alternatives

- **A connector that reads a spool directory**, like the ChatGPT export does. It
  would need no new route, and it would mean the system only notices what you said
  on the next poll, with a file as the interface to a sentence.
- **A second graph for direct input.** Tempting because the push path is simpler —
  one record, no watermark. Rejected: the value is entirely in resolution against
  existing memory, and two graphs doing that is two chances to diverge.
- **Add `records` to `POST /ingest` instead of a new route.** Fewer routes, and it
  conflates two different lifetimes: `/ingest` answers with a job id and `/remember`
  must answer with what happened.
- **One `direct` source with a `channel` metadata field.** Rejected above: it hides
  the text/voice distinction from `permits()`.
- **Accept audio and transcribe here.** Speech-to-text belongs before this boundary.
  The route takes text and does not care whether a keyboard or a microphone produced
  it, which also means a better transcriber can be swapped in without touching
  memory.

## Consequences

- There is finally a way to tell the system something, and it is the shortest path in
  the codebase from a sentence to a resolved claim. Verified end to end: *"I learnt
  RAG from \<url\>. Decided that project Kleos will use hybrid retrieval rather than
  pure vector search."* produced two entities (`Kleos` as a project, `RAG` as a
  topic), the utterance as an event, and the decision as a claim, all at
  `text`/`personal`.
- **The URL in that sentence was stored and not followed.** Everything needed to
  fetch it is in the body; nothing fetches. That is ADR 0014 and it is the next
  thing.
- `POST /ingest --source text` now fails loudly rather than silently doing nothing.
  Correct, and it is a behaviour change for anyone who tried it.
- The extractor produced a claim for the decision and none for "I learnt RAG",
  which is arguably right — the prompt asks for durable assertions, not
  restatements — and arguably loses something, since what the person has learned is
  a fact about them. Left as observed rather than tuned, because the eval is what
  should settle it.
- Nothing rate-limits this route. An owner session is not required unless sealing,
  so for now it is as open as the orchestrator is, which is localhost. It needs a
  limit before the orchestrator is reachable from anywhere else.
