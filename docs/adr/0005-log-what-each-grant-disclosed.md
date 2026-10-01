# ADR 0005: Log what each grant actually disclosed

**Status:** accepted
**Date:** 2026-10-01

## Context

The product's claim is "you can see exactly what an agent can see". The
explorer delivers the *can*: paste a grant token, get the permission-filtered
subgraph, with a banner when anything was hidden. Nothing delivered the *did*.

That gap matters more here than it would elsewhere, because of a limitation
stated plainly in the README: **a grant cannot be revoked before it expires**,
except per-object via `ObjectAcl.denied_agents`. There is no revocation list.
The mitigation is short TTLs. So an owner who becomes suspicious of a grant
has no lever at all — and, until now, no information either. They could not
answer "what has this agent actually read?", which is the question that decides
whether the missing lever matters.

The neighbourhood read makes this sharper. It is open-ended by construction:
supply a seed and a hop count, get a subgraph. The drop-not-placehold decision
(ADR-less, documented in `graphs/neighbourhood.py`) narrows what one call
discloses, and explicitly notes the residual risk — "re-seed on a returned id
and keep walking". Nothing recorded that walk, so the one attack the design
acknowledges it cannot prevent was also the one it could not detect.

## Decision

An append-only read log. One entry per read, written by the assembler of each
of the four read paths (`query`, `shift`, `context`, `neighbourhood`) through a
single shared `record_read` helper.

**Record what was returned, not what was asked.** A log of requests answers
"what did this agent want", which is not the question. Entries carry the ids
that were actually assembled into the response.

**Written in the assembler, not the permission node.** The permission node
decides what *may* be disclosed; the assembler decides what *is*. Logging the
former would record intent. One helper rather than four inline copies, because
four near-identical copies inside four assemblers is how an audit log ends up
covering three of the four reads.

**Log denials, and misses, too.** One declined query is a misconfigured grant.
Two hundred of them walking the id space is an agent mapping a memory it cannot
read, and that is visible only if denials are recorded. Likewise a read of an id
that does not exist: indistinguishable from a typo in isolation, diagnostic in
bulk.

**Fingerprint the grant; never store it.** A grant token is a bearer
credential, and an audit log holding live credentials is a vulnerability
wearing an accountability costume. The fingerprint is a keyed blake2b, which is
enough to group every read made under one grant and to match an entry against a
token the owner still holds, and useless to anyone who steals the log. Keyed
and domain-separated so it cannot be correlated with a hash of the same token
computed elsewhere.

**Fail closed.** If the entry cannot be written, the read raises instead of
returning data. A disclosure that cannot be recorded is one the owner can never
audit, and this is the component whose entire claim is that they can. The cost
is nil in practice: every read already needed the same database to retrieve
anything at all.

**Owner-readable only.** No MCP tool, no grant-authorised route. An agent that
could read the log would see which objects *other* agents were shown — a
disclosure channel around the permission check rather than a record of it. This
is the same reasoning that kept the neighbourhood read off MCP.

**Stored in Neo4j, under `:AgentRead`, deliberately without the `:Memory`
label.** The vector index and every traversal in `neo4j_store` are keyed on
`:Memory`, so staying off that label is what keeps entries out of retrieval,
out of neighbourhood walks, and out of anything an agent can reach. A test
asserts the label is absent and that entry ids never appear in a query's
citations.

`wipe_owner` leaves the log alone; clearing it is a separate `wipe_read_log`.
Re-ingesting does not un-disclose what an agent was already shown.

## Alternatives

- **A fourth datastore (Postgres, or JSONL files).** Cleanest separation, and
  Postgres is already in the stack. Rejected because the orchestrator is
  deliberately given *no* credentials for that database — it holds sealed OAuth
  refresh tokens — so this would mean a second Postgres or a second schema with
  its own user, for a few hundred bytes per read. JSONL is durable and simple
  but needs a scan for "what did this grant read", which is the only query
  anyone asks.
- **Log in the permission node.** Earlier, and catches a read that fails
  between check and assembly. Rejected: it records what passed the check, not
  what was returned, and those differ wherever an assembler filters further
  (the neighbourhood read drops denied nodes *and* every edge touching them).
- **Best-effort logging.** Avoids a read failing because of an audit write.
  Rejected: an audit log that silently drops entries under load is worse than
  none, because it is trusted. Fail-closed costs nothing given the read already
  depends on this database.
- **Store the grant token.** Would let an owner match an entry to a token
  without computing anything, and would make the log a credential store.
- **Log the full response.** Answers "what exactly did they see". Rejected: it
  duplicates the memory graph into an append-only store that grows without
  bound and is not permission-checked on read. Ids plus a timestamp let the
  owner reconstruct it against the graph.

## Consequences

- An owner can see, per grant: how many reads, how much was disclosed, how
  often it was declined, which read kinds, first and last use. Grouped by grant
  rather than by agent, because the grant is the capability — one agent id
  holding two grants is two authorisations, and deciding to stop issuing one
  needs them apart.
- The repeated-reseeding attack the neighbourhood design acknowledges is now
  detectable after the fact. Still not *prevented*: nothing rate-limits it, and
  the log is read by a human who thinks to look. Roadmap step 6 owns rate limits and
  the revocation list; this is the evidence layer beneath them.
- The read log is the first thing in Neo4j that is **not** rebuildable from
  source material, which contradicts the "queryable index, not system of
  record" framing for that database. Accepted knowingly, and it means
  `:AgentRead` has to be inside whatever backup policy a deployment runs. Said
  in the docstring and the README.
- Every read now performs one extra write. Measured at ~1ms against local
  Neo4j; irrelevant beside the vector search it follows, and worth re-checking
  when step 1's one-second voice budget lands.
- `subject` stores a truncated question (500 chars). It is the one field that
  holds user-authored text, so it is capped: a log is not a transcript store,
  and step 3's retention policy will have to cover it.
