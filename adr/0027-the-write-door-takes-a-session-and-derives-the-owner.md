---
title: "ADR 0027: The write door takes a session, and derives the owner"
description: "`POST /ingest` and `POST /remember` are the only routes in this service that write to memory without authenticating anything."
---

**Status:** accepted
**Date:** 2026-10-21

## Context

`POST /ingest` and `POST /remember` are the only routes in this service that
write to memory without authenticating anything, and they take **`owner_id`
from the request body**.

So on a reachable address, anybody can write into anybody's memory by naming
them. Not "read what they should not" — *write*, into the record the briefing
quotes and the resolver reasons over, with the owner's own provenance on it.
`/remember` is synchronous and unmetered, so the same caller can do it in a
loop.

`GET /ingest/{job_id}` has the matching hole on the read side: a job id is
enough to see its result, and job ids come off the enqueue response.

The asymmetry is what makes this odd rather than merely unfinished. Every agent
read is gated on an owner-signed grant with a capability check (ADR 0017), the
read log takes an owner session and refuses a grant by name (ADR 0005), and the
sealed path derives the recipient rather than accepting one (ADR 0024). The two
oldest routes in the service predate all of it and were never brought forward.

Today it is survivable because deployment is `127.0.0.1`. The moment there is a
URL it is the first thing anyone finds.

## Decision

**Both routes require an owner session, and the owner comes from it.**

```
POST /remember { session_token, text, ... }
   │
   ├─ gateway introspects the session  →  owner_id
   │
   └─ `owner_id` is not a field a caller can send: it is derived
```

### `owner_id` leaves the request body entirely

Not "validated against the session" — removed. ADR 0024 settled the shape of
this for the sealed path: *the recipient is derived, never supplied*, because a
field a caller can set is a field a caller can set wrongly, and the check that
compares two things is the check someone later deletes as redundant.

The models **forbid unknown fields**, so a caller still sending `owner_id` gets
a 422 naming it rather than a 201 that quietly ignored the owner they asked
for. Silently ignoring it is safe and reads as if it worked, which is the worse
failure.

### A session, not a grant

An agent has `record_decision` under a grant that says `may_write`, with its
own provenance, authority capped by the grant, and a `:Mutation` naming the
device. That path exists and is checked.

`/remember` is the *person* talking. A record written here is attributed to the
owner, not to a device, so authorising it with a grant would hand any
write-capable agent the ability to write **as the owner** — the one thing ADR
0017's precedence classes exist to prevent. `require_owner` already refuses a
grant token loudly, with a test; these two routes join the four that use it.

### A missing job is a 404 even when it exists

`GET /ingest/{job_id}` takes the session as `Authorization: Bearer`, and a job
belonging to another owner answers **404, not 403**. 403 would confirm the job
exists, which turns a sequence of job ids into an oracle for *who else uses
this deployment and how often*. The distinction costs nothing and the wrong
choice is unrecoverable once clients depend on it.

The credential is a header here and a body field on the other routes. That is
inconsistent on purpose: this route is a `GET` with the id in the path, and a
token in a query string lands in access logs, proxy logs and browser history.

### `/remember` is metered

A synchronous write path with no ceiling is a way to fill somebody's memory and
a way to spend their extraction budget. A fixed window per owner per route, in
Redis because the queue is already there and two API processes sharing nothing
would each enforce a limit and together enforce neither.

Refusals are **429 with `Retry-After`**. The limit is per owner rather than per
IP: the credential is what identifies the writer, and an IP limit on an
authenticated route punishes whoever shares the NAT.

Deliberately not a token bucket. The burst behaviour nobody has measured is not
worth the state, and the window is honest about being approximate — a caller
can get 2N in two adjacent windows, which does not matter for a ceiling meant
to stop loops rather than shape traffic.

## Alternatives rejected

**Validate `owner_id` against the session.** Keeps the field, refuses a
mismatch. Rejected under ADR 0024's reasoning: the field is then still in the
API, every client sends it, and the comparison is the line a later change drops
as redundant. Removing it cannot be forgotten.

**Authenticate with the gateway in front.** A reverse proxy could require a
session for these paths. Rejected because the owner has to be *derived* from
the credential and used as the write's owner, which is work inside the handler,
not in front of it — and because an orchestrator that is safe only when
correctly proxied is an orchestrator that is unsafe.

**Accept either a session or a write-capable grant.** Convenient for an agent
that wants to push a note. Rejected: the record would be attributed to the
owner, and "an agent may write as the person" is the precedence boundary this
system is built on. An agent that wants to record something has
`record_decision`.

**Rate-limit in the gateway.** It already fronts the Rust side. Rejected
because the orchestrator is reachable on its own port and is the thing being
protected; a limit that only applies via another service is a limit with a
bypass.

**Per-IP limits.** Cheaper, and needs no credential. Rejected: on an
authenticated route the owner is the right subject, and an IP ceiling is both
evadable and unfair to shared egress.

## Consequences

- **Breaking, and loudly.** `owner_id` in the body is now a 422 and
  `session_token` is required. `orchestrator_smoke.sh` and the docs change with
  it. A silent-compatibility path was available and not taken, because the
  silent version of this change is one where a caller believes it chose an owner.
- **A gateway round trip per write.** `require_owner` is an HTTP call to
  `/auth/session/introspect`; the orchestrator holds no signing key, so it
  cannot do otherwise. `/ingest` enqueues, so the cost lands on the request and
  not the backfill, and `/remember` was already making enclave calls when
  sealing.
- **`/remember` without a gateway is now impossible**, including for anything
  that used it as a quick way in. The eval harness does not use these routes —
  it drives `run_ingestion` directly — so it is unaffected, which is also a
  reminder that the harness bypasses this door entirely.
- **The limit is one more thing to tune.** Set too low it refuses a legitimate
  burst, such as a voice client flushing a backlog. Defaults are deliberately
  generous and the refusal says what the limit was.
- **This does not make the orchestrator safe to expose.** It closes the open
  door. The service still has no TLS of its own, no per-grant revocation, no
  quotas and no per-object deletion, and `/ingest/{job_id}` still returns a
  job's full result to its owner with no redaction.
