# orchestrator

The Python orchestration service: everything agentic in memorai -- ingestion
pipelines, entity/decision resolution, retrieval, answer assembly -- runs
here, **outside** the enclave. It calls the Rust gateway for the few
operations that must be attested or owner-authorised, and never itself
becomes part of the trust boundary.

Not part of the cargo workspace; it is a separate Python package that lives
in the same repo so the memory schema can be kept in lockstep with
`shared/src/memory.rs` (see `tests/test_schema_parity.py`, which parses the
Rust source and fails if the two drift).

## What runs where

```
orchestrator (this service)                    rust core
---------------------------                    ---------
ingestion graph   fetch                        gateway
                  extract                        POST /auth/session        -> enclave verifies identity
                  resolve                        POST /memory/seal/encrypt -> enclave seals raw content
                  encrypt  ------------------->   POST /memory/scope/grant
                  write     (Neo4j)               POST /memory/scope/introspect
query graph       authorize ----------------->
                  retrieve  (Neo4j + LlamaIndex)
                  permission-check
                  assemble / decline
```

The only point in the pipeline that crosses the trust boundary is the
ingestion graph's `encrypt` node. If the gateway is unreachable, the
sensitive record is **not** written -- there is no fallback that stores a
sensitive body in the clear.

## LangGraph and LlamaIndex

- **LangGraph** owns control flow. Both graphs are `StateGraph`s with a
  checkpointer, not single-turn chains: ingestion is bursty, each node is
  individually retryable, and a run can resume mid-pipeline after a
  restart instead of re-pulling and re-extracting a whole backfill. The
  approval gate that later phases need before certain writes is a node
  insertion, not a rewrite.
- **LlamaIndex** owns retrieval. `retrieval/index.py` exposes a real
  `BaseRetriever`, so anything in LlamaIndex that consumes one works over
  memorai memory. It is not a plain vector retriever: hybrid scoring
  (semantic + recency + graph proximity, `retrieval/ranking.py`) runs
  inside `_retrieve`, because proximity needs the graph store rather than
  just the vector index. Chunking is *dispatched* from here but declared by
  each connector (`chunk_for_source` looks the chunker up in the connector
  registry), since how a record splits is a property of the source's shape.

## Storage

Neo4j holds entities, events, claims, their edges, and their embeddings in
Neo4j's native vector index. Every node carries three labels' worth of
information: its specific label (`:Entity` / `:Event` / `:Claim`), a shared
`:Memory` label so one vector index covers all three in a single ranking
pass, and a `payload` JSON blob so objects round-trip back into pydantic
without a lossy column mapping. ACL fields are additionally flattened onto
the node for filtering.

Neo4j is the queryable index, not the system of record: it is conceptually
rebuildable from source material. Raw content belongs in Walrus under the
owner's keys, which is not wired yet (see **Stubs** below).

Edges: `(:Event)-[:MENTIONS]->(:Entity)`, `(:Claim)-[:ABOUT]->(:Entity)`,
`(:Claim|:Event)-[:CITES]->(:Event)`, `(:Claim)-[:SUPERSEDES]->(:Claim)`,
`(:Claim)-[:CONTRADICTS]->(:Claim)`.

## Permissions

`permissions.py` mirrors `shared/src/permissions.rs` exactly. An agent
presents a **grant token** minted by the gateway against an owner session;
the query graph's `authorize` node introspects it and enforces what comes
back. A caller-supplied scope is never trusted.

A `Scope` names the sources, entity kinds, time window, maximum sensitivity
and expiry it covers. Each stored object carries an `ObjectAcl` with the
denormalised facts needed to decide from `(scope, acl)` alone, with no
further lookups -- which is what will make the same evaluation possible
on-chain later. The check is **deny by default**: an empty `sources` or
`entity_kinds` list grants nothing.

Retrieval is deliberately permission-*blind*, and the check is its own graph
node between retrieval and assembly. That makes it structurally impossible
for the assembler to see an unchecked candidate, and it makes a denial
visible as a denial (with reasons) rather than as an empty result set.

## Connectors

`connectors/registry.py` maps a source id to a `ConnectorSpec`, which is
where a connector declares everything the rest of the service needs to know
about it: its id, display name, whether it needs OAuth and with which
scopes, how its records chunk for retrieval, and optionally a fixture
stand-in for mock mode. Adding a source is one module plus one
registration -- no change to `enums.py`, to `retrieval/`, to the graphs, or
to anything in Rust. `tests/test_connector_registry.py` registers a
connector that exists only in that test file and ingests from it end to
end, which is the property that test exists to hold.

Source *ids* stay open strings (`enums.SourceId`, mirroring
`SourceId::parse` in `shared/src/memory.rs`): the enclave treats them as
opaque, so adding a connector never changes the measurement an attestation
commits to. The registry is the host-side list of sources this build knows
how to *fetch*, which is a different question and deliberately lives
outside the trust boundary.

Mock mode is per source, not global: a connector gets fixture data only if
its spec declares a `mock_factory`. `mock` is itself a fixture source; the
Google and GitHub stubs raise `NotImplementedError` in both modes. This
replaced a short-circuit that returned the mock fixtures for *every* source
in mock mode, which made a half-built connector look like it worked.

`ENABLED_SOURCES` optionally narrows which registered sources a deployment
will ingest from; empty (the default) means all of them. `GET /sources`
lists the registry with that flag applied, and `POST /ingest` rejects an
unknown or disabled source with a 400 rather than failing inside the graph.

## Mock mode

`ORCHESTRATOR_MODE=mock` (the default) needs no API keys and no cloud
services, mirroring the enclave's `mock` feature:

- `connectors/mock.py` -- the `mock` source: a fixed set of fixture records, shaped to exercise
  entity overlap across records, a decision that supersedes an earlier one,
  and one record flagged sensitive so the enclave seal round trip is
  actually taken.
- `extraction/mock.py` -- deterministic rule-based extraction, no LLM.
- `retrieval/embeddings.py` -- hashed-token unit vectors: stable across
  processes, not semantic, no key required.

Neo4j and Redis are real services even in mock mode.

## Running it

```bash
cd orchestrator
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
cp .env.example .env

docker compose up -d                      # neo4j :7688, redis :6380
.venv/bin/pytest                          # 39 tests; skips if neo4j is down
.venv/bin/ruff check .
```

The full Phase 2 path needs the Rust stack running too:

```bash
cd .. && ./scripts/run_local.sh --with-orchestrator
./scripts/orchestrator_smoke.sh           # identity -> ingest -> query -> decline
```

To run the service by hand instead:

```bash
.venv/bin/python -m orchestrator.api            # FastAPI on :8090
.venv/bin/python -m orchestrator.jobs.worker    # RQ worker
.venv/bin/python -m orchestrator.mcp_server     # MCP server over stdio
```

### API

| Route | Shape | Purpose |
|-------|-------|---------|
| `GET /health` | sync | status of Neo4j, Redis and the gateway |
| `POST /ingest` | **enqueued** (202, job id) | run the ingestion graph for one source |
| `GET /ingest/{job_id}` | sync | job status and result |
| `POST /query` | sync | run the query graph against a grant token |

Ingestion is enqueued from day one because connecting a source means
backfilling a large history in bursts, which is the wrong lifetime for an
HTTP request. Queries stay synchronous -- an agent asking a question wants
an answer, not a job id.

## Stubs

These have real signatures and typed returns; they raise
`NotImplementedError` with the reason rather than failing silently.

- `connectors/google.py`, `connectors/github.py` -- need a stored per-owner
  token with data scopes. Phase 1 OAuth proves identity only; it does not
  request Gmail/Calendar/repo scopes.
- `retrieval/embeddings.py::VoyageEmbedder` -- live embeddings need an API
  key and an `EMBEDDING_DIM` matching that model, which must also match the
  Neo4j vector index.
- Walrus reads/writes -- sealed ciphertext is currently carried by the
  ingestion graph and `EncryptedContentRef.blob_id` stays `None`.
- `extraction/llm.py` is *not* a stub: it is wired and works the moment
  `ANTHROPIC_API_KEY` is set and `ORCHESTRATOR_MODE=live`. It has not been
  run against the live API from this repo.
