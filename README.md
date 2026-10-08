# Kleos

A personal memory layer for humans and AI agents. A person's sources are
resolved into a structured, timestamped record -- who decided what, when it
changed, why, what it links to, who owes whom -- rather than a pile of
searchable documents. The sensitive parts are encrypted inside a TEE (AWS Nitro
Enclave) attested via NSM, so the operator holds ciphertext. Authorized agents
query it over MCP under scoped grants, and every read is logged. Identity comes
from stacked OAuth signals verified **inside the enclave**, not from a
government ID.

The bet is that the value is the **resolved record**. That bet is now measured
rather than assumed: `python -m orchestrator.eval` compares this design against
a plain RAG baseline over a labelled corpus, and plain RAG answers "which
database did we pick" with all three past decisions and nothing to say which one
holds. See "Step 0" below for the numbers, including the two places the resolved
path does *worse*.

What is here is the memory and permissions core of something larger: a
voice-first personal assistant, with Kleos as the layer that remembers and
decides who may read what. "Where this is going" is the target architecture and
the order it has to be built in. `docs/adr/` carries the decisions -- one per
file, immutable once accepted, a reversal getting its own ADR rather than an
edit.

**What exists:** the enclave and gateway, the resolved memory schema, the
Python orchestration service (ingestion and query graphs, Neo4j-backed hybrid
retrieval, query-time permissions), the history and neighbourhood reads, a
read-only graph explorer, an agent read log, an MCP server, and one real
connector (ChatGPT, via the user's own data export).

**What does not:** no web app, no SDK, no smart contracts. Google and GitHub
have consent and a sealed refresh-token store but no `fetch` yet. `nitro` mode
has never run on real Nitro hardware. Real Seal and Walrus are stubs. See
"Still stubs" for the full list, and "The confidentiality model" for what the
encryption claim does and does not cover.

> **On the name.** The product is Kleos, and so are the identifiers now. It was
> `memorai` -- binary names, the `.eif`, the Neo4j constraint and index names, two
> Postgres tables, the local container names, the RQ queue, the Postgres role.
> That rename was a migration rather than a search and replace, and it is one:
>
> - **Neo4j** identifies a constraint or index by name, so creating the new name
>   does not retire the old one -- it builds a second index over the same property
>   and keeps maintaining it on every write. `storage/migrations.py` creates the
>   new names, then drops the old ones explicitly, in that order, so an
>   interrupted upgrade leaves a duplicate rather than nothing. The vector index
>   goes last, because it is the one every read goes through.
> - **Postgres** would have been worse. `CREATE TABLE IF NOT EXISTS` under the new
>   name against a database holding the old one creates an *empty* table, and
>   every sealed refresh token and registered device key stays in the original,
>   unreferenced -- the gateway would behave as though nobody had ever consented
>   and no device had ever been registered. So the migration renames in place
>   first, including the implicit indexes behind the primary key and the unique
>   constraint, which `ALTER TABLE ... RENAME` leaves behind and which would
>   otherwise make an upgraded database differ from a fresh one. Verified both
>   ways against real Postgres, twice over for idempotence, with the rows counted
>   before and after.
> - **One identifier deliberately still says `memorai`:** the domain separator in
>   the mock seal's key derivation (`enclave/src/services/seal.rs`). It is an
>   input to a key, not a name. Changing it is a key rotation wearing a rename's
>   clothes -- existing ciphertext would stay on disk with a `key_id` that no
>   longer matches, and every unseal would fail as though the blob belonged to
>   another owner. A real rotation gets a v2 and a path that reads both.
> - **Local containers** cannot be renamed by this repo at all: the Neo4j password
>   lives inside its own data directory and the Postgres role was fixed when the
>   volume was initialised. `scripts/services.sh` detects a pre-rename set and
>   prints the in-place migration -- `docker rename` plus two credential changes,
>   losing no data -- with deleting the volumes offered second.

The only asset carried over from the abandoned prior product
(`suiverify`, a decentralized KYC platform) is the Nitro Enclave build/deploy
template at `suiverify/nautilus-attestation-backend/` -- its NSM attestation
logic and socat-based VSOCK bridging pattern. That project is read-only
reference material and is not part of this repo.

## Architecture

```
gateway (Axum, host, TCP)
  - OAuth redirect flow: authorize URL (PKCE + signed state) + callback
  - Persists per-owner SEALED refresh tokens (ciphertext only) in Postgres
  - Mints/introspects scoped agent grants; introspects owner sessions
  - Three signing keys derived from one root: session, grant, oauth_state
  - Proxies all sensitive work to the enclave over VSOCK
        |
        v
enclave (Axum, inside Nitro Enclave)        <- core trust boundary
  - Verifies OAuth tokens itself, against the provider, inside the TEE
  - Exchanges OAuth authorization codes itself, and seals the refresh
    token before it leaves; holds the only copy of the client secret
  - Computes trust tier from stacked signals
  - NSM attestation over the result
  - Seal-encrypts raw sensitive content before it leaves the TEE
        |
        v
storage: Postgres (sealed refresh tokens), blob store (sealed bodies)
         -- Walrus is the eventual blob store; same interface, still a stub
```

Alongside, and outside the trust boundary:

```
orchestrator/ (Python: LangGraph + LlamaIndex)
  - ingestion graph: fetch -> extract -> [enrich] -> canonicalise -> resolve
                     -> encrypt -> write
  - query graph:     authorize -> retrieve -> permission-check -> assemble/decline
  - history reads:   authorize -> walk -> permission-check -> assemble
  - calls the gateway only to seal raw content, resolve agent grants,
    and resolve an owner session for the read log
        |
        v
Neo4j: entities, events, claims, their edges, one vector index over all
       three (:Memory), and the agent read log (:AgentRead -- deliberately
       NOT :Memory, so it can never be retrieved as memory)
Redis: RQ ingestion jobs
```

Every read is permission-checked in its own graph node *after* a
permission-blind walk, and every read is logged with the grant that made it.
Those two are the product: what an agent can see, and what it did see.

### Where this is going

The memory core above is one layer of a voice-first assistant: small hardware
nodes in each room that listen and answer, a local-first hub that coordinates
them, and a privacy gateway that is the only thing allowed to talk to an
external model. Privacy as a structural property rather than a promise means
the boundaries below are where the design lives, not the features.

```
room node (Pi / ESP32-S3)            one per room
  - hardware mute switch that physically cuts the mic; status LED
  - on-device wake word + VAD: nothing leaves the device before the wake word
        |  mTLS, per-device identity
        v
hub (mini PC, local-first)           <- the coordination layer
  - runs the orchestrator locally; small local model for extraction + intents
  - streamed STT -> model -> streamed TTS, budget ~1s to first audio
  - speaker identification: each utterance attributed to an owner,
    unknown speakers are guests and are never ingested
  - session handoff between rooms, and to a phone/desktop client
        |                                   |
        |  scoped grant over MCP            |  encrypted sync, user-held keys
        v                                   v
KLEOS (this repo)                     enclave-backed cloud
  - resolved memory, query-time permissions, the read log
  - transcripts become events; audio is never stored
        |
        v
privacy gateway                      <- the only path to an external model
  - PII redaction / pseudonymisation out, reversed on the way back
  - minimal-context builder: never send whole memory
  - zero-retention, no-training provider terms; swappable providers
  - local_only mode that makes no external call at all
  - every outbound payload logged and shown to the user
```

Two things in that diagram are the whole point. The **mute switch is
hardware**, because a software mute is a promise and a cut wire is a property.
And the **privacy gateway is a chokepoint**, because "we only send the minimum"
is checkable only if there is exactly one place that can send anything.

Built in dependency order. Each step's exit test is a measurement, not a
passing suite, and a step that fails its exit test stops the next one:

| | step | exit test |
|---|---|---|
| **0** | Harden the core; measure whether a resolved record beats plain retrieval | a number comparing the two — **done**, see "Step 0" below |
| **1** | Voice prototype, cloud-first: one room, one node | 20-turn conversation with p50/p95 latency per stage; mute switch verified to stop capture |
| **2** | Privacy gateway, and the assistant answering from memory | correct cited answer; outbound log shows only redacted minimal context; `local_only` makes zero external calls |
| **3** | Voice becomes memory: speaker ID, transcript connector, consolidation | eval does not regress; guest speech provably never stored; deleting a memory removes it from retrieval *and* derived claims |
| **4** | Local-first hub, and the extraction decision | common requests work offline; the local-vs-frontier extraction gap is measured and the choice recorded in an ADR |
| **5** | Multi-room, multi-user, real sources (Google, GitHub) | two-person household leak test; real Gmail data flows end to end with the host never holding a refresh token |
| **6** | Actions and agent safety: tool risk tiers, revocation list | red-team suite passes; every action traceable; revoking a grant takes effect immediately |
| **7** | Production hardening and closed beta | security review findings resolved or accepted in writing; beta metrics meet the targets |

Robots and other actuators are not a separate step: they are tools in step 6's
registry, each with its own risk tier and grant. Nothing above should need
redesign to add one.

Four decisions are deliberately open, and each gets an ADR when it is made:
**where extraction runs** (step 4 — the tension below under "the
confidentiality model"), **whether `assemble` synthesises or formats** (step 2),
**the retention policy for transcripts and derived memory** (step 3), and
**whether to adopt on-chain components at all** (step 7, only if beta users
demonstrably need them).

### Invariants

These hold across every step above. A change that weakens one is a change to
the architecture, not an implementation detail:

- `permits()` stays pure, total and deny-by-default; a multi-source ACL
  requires *all* its sources in scope.
- Retrieval stays permission-blind, and the permission check stays its own
  graph node between retrieval and assembly.
- Traversals stay owner-constrained at every node on the path, not just at the
  endpoints.
- The withhold-vs-drop asymmetry between the history reads and the
  neighbourhood read stays intact (see "Seeing the record" below).
- Raw audio is never stored by default, and no real personal data goes into
  fixtures, logs or commits.
- The README says what is mocked, stubbed, or never run on real hardware.

**Why verification happens in the enclave and not the gateway:** the NSM
attestation only means something if the thing it's attesting actually
happened inside the TEE. If the gateway verified the OAuth token and just
told the enclave "trust me, this checked out," the attestation would cover
nothing of value. So `enclave/src/routes/identity.rs` calls Google/GitHub's
verification endpoints itself, and only then produces the attestation.

The same reasoning is why the OAuth **code exchange** is in the enclave
(`enclave/src/routes/oauth.rs`). A refresh token is not an ordinary app
secret; it is standing, renewable access to the user's mailbox. If the host
performed the exchange, the operator would hold that access no matter what
was attested afterwards. See "The confidentiality model" below.

**The identity path** (see `scripts/smoke_test.sh`):
1. Client hits `POST /identity/verify` on the gateway with a raw OAuth token.
   This is the direct path, for a token obtained elsewhere; the real consent
   flow is `GET /auth/authorize` → `GET /auth/callback`, which exchanges the
   code in the enclave and issues an owner session.
2. Gateway forwards the token to the enclave over its VSOCK-bridged TCP
   client (`gateway/src/vsock/client.rs`).
3. Enclave calls the provider's verification endpoint itself, through an
   outbound VSOCK tunnel (`enclave/src/services/oauth/{google,github}.rs`).
4. Enclave computes a trust tier from the signals present: Google alone = 1,
   + GitHub = 2, + wallet = 3, + domain = 4. Wallet and domain are still stubs
   that reject explicitly rather than pretending to work.
5. Enclave produces an NSM attestation document over the result.
6. Gateway returns `{ identity, attestation }` as JSON, unmodified.

Nothing is persisted by that path, and nothing on-chain happens anywhere yet.
What *is* persisted is the sealed refresh token from the consent flow, and
sealed record bodies from ingestion -- both ciphertext the host has no key for.

## No Rust VSOCK crate

There is no VSOCK crate anywhere in this codebase, by design (mirroring the
proven `nautilus-attestation-backend` pattern). All VSOCK<->TCP bridging is
done at the shell level with `socat`:

- Inbound: `enclave/run.sh` runs
  `socat VSOCK-LISTEN:4000,reuseaddr,fork TCP:localhost:4000 &`, so the
  enclave's Rust binary just binds plain TCP (`enclave/src/vsock/listener.rs`)
  -- completely ordinary Axum/tokio code.
- Outbound: the enclave dials the **real hostname over HTTPS**
  (`https://oauth2.googleapis.com/token`). Inside the enclave, `/etc/hosts`
  maps that hostname to a loopback alias where socat listens on :443 and
  forwards over VSOCK; `scripts/parent_forwarder.sh` on the host connects
  that VSOCK port to the real `host:443` and pipes the bytes.
- On the host, `parent_forwarder.sh` also bridges the gateway's inbound TCP
  calls into the enclave's VSOCK port 4000.

**TLS terminates inside the enclave**, not on the host. The host moves an
opaque encrypted stream, and the certificate is validated in the TEE against
the real hostname. This matters: the host forwarder is the operator, and
letting it terminate TLS would hand it every client secret and refresh token
in plaintext, which is exactly what doing the code exchange in the enclave
is meant to prevent.

For the same reason the upstream hostnames are compile-time constants in
`enclave/src/services/http.rs` rather than configuration. The enclave's
environment is supplied by the host, so a host-settable endpoint would let
the operator repoint the client secret at a server it controls.

> Historical note: until this was fixed, the enclave dialled
> `http://127.0.0.1:<port>` — plaintext HTTP — into a tunnel that landed on
> port 443. A TLS listener cannot answer a plaintext request, so **no
> outbound enclave call could ever have succeeded in `nitro` mode**. It went
> unnoticed because `nitro` mode had never been run on real hardware and
> `mock` mode short-circuits before the network.

## VSOCK ports

Each entry below carries a TLS stream terminated inside the enclave. The
table is mirrored by the `Upstream` constants in
`enclave/src/services/http.rs`, `enclave/run.sh`, and
`scripts/parent_forwarder.sh`; all four must agree.

| Port | Direction        | Loopback alias | Upstream                        |
|------|-------------------|----------------|----------------------------------|
| 4000 | Gateway -> Enclave | --            | Main API                         |
| 5000 | Enclave -> Host    | --            | Log forwarding                   |
| 8002 | Enclave -> Host    | 127.0.0.2     | `www.googleapis.com` (tokeninfo) |
| 8003 | Enclave -> Host    | 127.0.0.3     | `api.github.com` (user API)      |
| 8004 | Enclave -> Host    | --            | Walrus publisher/aggregator      |
| 8005 | Enclave -> Host    | --            | Walrus Memory relayer            |
| 8006 | Enclave -> Host    | 127.0.0.4     | `oauth2.googleapis.com` (token)  |
| 8007 | Enclave -> Host    | 127.0.0.5     | `github.com` (token)             |

## Local development (mock mode)

Nitro enclaves only run on EC2. Locally, the `enclave` crate builds with its
default `mock` feature: the enclave binds `127.0.0.1:4000` directly (no
socat, no VSOCK) and its OAuth providers short-circuit token verification
instead of dialing a tunnel that doesn't exist locally -- pass a token of
the form `mock_google_<subject>` / `mock_github_<login>` and the provider
deterministically returns that identity. The attestation document returned
in mock mode is prefixed `MOCK_ATTESTATION_` so it can never be mistaken for
a real one.

```bash
cargo build                     # workspace, mock feature (default)
./scripts/run_local.sh          # starts enclave + gateway in mock mode
./scripts/smoke_test.sh         # mock tokens + the mock OAuth connect flow
kill $(cat .local/enclave.pid) $(cat .local/gateway.pid)
```

The orchestrator has the same discipline: `ORCHESTRATOR_MODE=mock` (default)
needs no API keys -- fixture connector, rule-based extractor, deterministic
hashed-token embeddings. Neo4j and Redis are real services even in mock
mode.

`scripts/services.sh` starts them. It exists because `docker compose` is a CLI
plugin that is not always installed where `docker` is, and without it
`docker compose up -d` fails with `unknown shorthand flag: 'd'`, which reads
like a typo rather than a missing component. `orchestrator/docker-compose.yml`
is still the source of truth for the definitions; the script runs the same
three containers on the same ports with plain `docker run`, takes
`CONTAINER_CLI=podman`, and waits for each port before returning -- the suite
*skips* rather than fails when Neo4j is unreachable, so starting pytest too
early looked exactly like everything passing.

### Full stack, end to end

```bash
./scripts/services.sh up                 # neo4j :7688, redis :6380, postgres :5435
cd orchestrator
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp .env.example .env
.venv/bin/pytest                         # the suite; prints its own count
.venv/bin/python -m orchestrator.eval    # the step 0 exit test
cd ..

./scripts/run_local.sh --with-orchestrator   # enclave + gateway + neo4j + redis
./scripts/orchestrator_smoke.sh              # the end-to-end proof, below
```

`scripts/orchestrator_smoke.sh` walks the whole path and is the thing to run to
see the memory layer work against the real Rust stack:

1. `POST /auth/session` with `mock_google_alice` -- the enclave verifies the
   identity and attests it; the gateway issues an owner session JWT.
2. `POST /ingest` on the orchestrator enqueues an RQ job and returns a job id.
3. The worker runs the ingestion graph: the mock connector yields 7 fixture
   records, the rule-based extractor produces entities, events and claims
   (some of them commitments), the resolver links the superseding decisions
   and the reassigned commitment, the one sensitive record's body is sealed
   **inside the enclave** (the gateway round trip) and its ciphertext written
   to the blob store so the ref it stores actually points at something, and
   everything else goes to Neo4j with provenance and ACL fields. The reported
   counts are what landed, not what was considered.
4. `kleos-device sign` on the owner's device signs a scoped grant for
   `agent-demo`; the gateway verifies it and cannot have produced it (ADR 0011).
5. `POST /query` runs the query graph, which introspects the grant, retrieves
   with hybrid ranking, permission-checks each candidate, and answers with
   citations -- including marking the two superseded claims as superseded.
6. The same question under a scope covering only GitHub/organizations
   declines explicitly: `"8 candidate memory object(s) matched, but none are
   within the requesting agent's scope (source not in scope)"`.
7. `POST /memory/shift` walks that answer's claim back through its
   supersessions and prints, for each one, how long the decision stood and
   which citations are new in the claim that replaced it; `POST
   /memory/context` walks the citation chain around the same claim. Under
   the narrow scope the shift read declines the same way the query does.
8. Every one of those reads has appended an entry to the agent read log, so
   `POST /memory/reads` under the **owner session** (not a grant) shows what
   each grant was actually shown, grouped by grant.
9. `POST /memory/neighbourhood` returns the nodes and typed edges around
   that claim, and the same call under a grant that cannot read confidential
   material comes back with objects and edges missing and a count saying so.
   `GET /explorer` serves the page that draws it, including the read-log panel.

## EC2 / Nitro deploy path

```bash
cargo build --release --no-default-features --features nitro -p enclave
./scripts/build_enclave.sh      # stagex/docker build -> enclave/out/*.eif
./scripts/deploy.sh             # ships .eif + gateway binary to DEPLOY_HOST
# on the parent instance:
nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path kleos-enclave.eif --enclave-cid 16
./parent_forwarder.sh &
ENCLAVE_MODE=nitro ./kleos-gateway
```

`enclave/Dockerfile` is a stagex-based multi-stage build (adapted from
`suiverify/nautilus-attestation-backend/Containerfile`) producing a
reproducible `.eif` via `eif_build`. It needs the stagex image cache and a
network-reachable cargo registry (for the pinned
`aws-nitro-enclaves-nsm-api` git dependency); the `.eif` build itself has
not been run yet (docker is available on the dev machine, but the stagex
images are not cached there). It is structurally
verified: `cargo build --release --no-default-features --features nitro -p enclave`
was run standalone and **compiles cleanly**, including resolving the
`aws-nitro-enclaves-nsm-api` git dependency.

## Repo layout

```
enclave/      Axum server that runs inside the Nitro Enclave (or locally in mock mode)
gateway/      Axum server that runs on the host, proxies to the enclave
shared/       Types shared by both: identity, the memory schema, permissions, VSOCK envelopes
orchestrator/ Python orchestration service (LangGraph + LlamaIndex); not in the cargo workspace
              graphs/     ingestion, query, history, neighbourhood
              storage/    Neo4j, the sealed-blob store, the agent read log
              eval/       the labelled corpus and the RAG comparison
              static/     the graph explorer, one file, no build step
              also owns docker-compose.yml for neo4j/redis/postgres
docs/adr/     one architecture decision per file, immutable once accepted
scripts/      build/run/deploy/smoke-test plumbing, plus services.sh
```

`shared/src/memory.rs` and `shared/src/permissions.rs` are the real schema
now, and `orchestrator/src/orchestrator/{schema,permissions}.py` mirror them
field for field on the wire.
`orchestrator/tests/test_schema_parity.py` parses the Rust source and fails
if the two ever drift.

`enclave/src/services/memory.rs` is **gone**: it implied the enclave ingests,
which it does not and should not. Ingestion lives entirely in
`orchestrator/`. What the enclave gained instead is `POST /seal/{encrypt,
decrypt}` -- the one memory-layer operation that genuinely belongs in the TEE.

## The memory layer

The enclave/gateway/shared core is deliberately narrow and has stayed that way:
VSOCK-over-socat, the mock/nitro split, and a trust boundary that grew by
exactly two routes (`/seal/{encrypt,decrypt}` and `/oauth/exchange`) since the
scaffold. Everything in this section is additive to it and runs outside it.

**Product shape.** A user connects sources; their activity is resolved into a
structured, timestamped memory, sealed inside the TEE at the points where it
touches sensitive raw content, and stored under keys the host does not have.
Authorized agents query it with scoped permissions over MCP, and the owner can
see both what a grant *can* read and what it *has* read. The bet is that the
value is a **resolved, timestamped record** -- who said what, when it changed,
why, what it links to -- not a pile of retrievable raw documents. "Step 0" below
has the measurement.

### Decisions made

Three questions were open once the scaffold existed. They are now settled:

- **Storage: a dedicated graph database, Neo4j.** Entities, events, claims
  and their edges live in Neo4j, with embeddings in its native vector index.
  Graph-proximity ranking is an explicit requirement of the retrieval layer,
  and doing it over a relational store with a vector extension means
  reimplementing traversal. Walrus remains the eventual encrypted-blob store
  for raw content; Neo4j is the queryable index and is conceptually
  rebuildable from source.
- **Transport: an async job queue from day one, on RQ.** Connecting a source
  means backfilling a large history in bursts, which is the wrong lifetime
  for an HTTP request. RQ over Celery because it is Redis-only and has
  fewer moving parts. Queries stay synchronous -- an agent asking a question
  wants an answer, not a job id.
- **Location: a new top-level `orchestrator/` in this repo.** Keeping it
  here is what makes it practical to hold the Python memory schema in
  lockstep with `shared/src/memory.rs`; a parity test parses the Rust source
  and fails on drift. It is Python, and deliberately not part of the cargo
  workspace.

### The memory schema

`shared/src/memory.rs`:

- **Entity** -- a person, project, artifact, organization or topic
  referenced across sources.
- **Event** -- an atomic ingested fact, carrying a `SourceRef`. `SourceRef`
  keeps `occurred_at_ms` and `ingested_at_ms` separate, which is what lets
  the record answer "what did I know, and when did I know it". Events are
  never rewritten; corrections arrive as new events.
- **Claim** -- the decisions/claims layer. A later claim `supersedes` an
  earlier one and the earlier one stays stored with status `superseded`,
  linked, rather than being overwritten; unresolved conflicts are linked via
  `contradicts`, and `reconciled_into` points at the claim that eventually
  resolves them.
- **Commitment** -- an optional *facet* on `Claim`, present when the claim
  asserts that someone owes something: `owed_by_entity_id`,
  `owed_to_entity_id` (optional -- plenty of commitments are to oneself),
  `due_at_ms` (optional -- plenty have no deadline), `fulfillment` and
  `settled_at_ms`. Stored as `(:Claim)-[:OWED_BY|:OWED_TO]->(:Entity)`.
- **Provenance** -- a citation chain back to originating source events, not
  just a confidence float. Confidence is carried, but it is advisory.

### Reading the record: why a decision shifted

The substrate for "why did this change" was already there -- `supersedes`,
`contradicts`, `reconciled_into`, `asserted_at_ms`, the `SUPERSEDES` and
`CONTRADICTS` edges the ingestion graph writes, and `Provenance.citations`
pointing back at the source events. What was missing was a *read* that makes
it legible, so `graphs/history.py` adds two, and adds no node type:

- **`why_did_this_shift(runtime, claim_id, grant_token)`** -- the ordered
  supersession run containing that claim, and for each `SUPERSEDES` link:
  the superseding claim, the superseded one, the interval between them, and
  **the citations present in the superseder that were absent from the claim
  it replaced**. That last set is the point. "B replaced A" is visible in
  the graph already; what is worth reading is the evidence that appeared and
  moved the decision. Unresolved `CONTRADICTS` links and `reconciled_into`
  targets come back alongside, because an open conflict is part of the
  story. The walk over `SUPERSEDES` is undirected, so handing it the current
  claim, the original, or something mid-chain all answer the same question.
- **`context_chain(runtime, object_id, grant_token, hops)`** -- what an
  object was derived from and what was derived from it, walked over `CITES`.
  `CITES` is `Event -> Event` keyed by event id rather than by source, so
  the chain crosses connectors wherever the underlying material does. There
  is deliberately **no `Thread` node type**: everything these reads need is
  expressible as traversal over edges ingestion already writes, and a
  speculative node type would be a second thing to keep correct.

Both are exposed on the orchestrator API (`POST /memory/shift`,
`POST /memory/context`) and over MCP (`why_this_shifted`,
`memory_context_chain`).

### Seeing the record: the graph neighbourhood, and the explorer

`graphs/neighbourhood.py` adds the first read shaped as **nodes and edges**
rather than answer text: `POST /memory/neighbourhood` takes seed ids, a
grant token and a hop count, and returns everything within that many hops --
nodes with their label, display text, timestamp, sources and (for claims)
status and whether they carry a commitment, plus edges carrying their stored
type (`MENTIONS`, `ABOUT`, `CITES`, `SUPERSEDES`, `CONTRADICTS`, `OWED_BY`,
`OWED_TO`). It composes the walk out of `neighbour_ids` and `get_many` and
is permission-checked with the same blind-walk-then-check structure as
everything else.

Its one deliberate divergence from the history reads: **a denied object is
dropped, not withheld as a placeholder.** A supersession history is asked
for by naming a claim, so the chain's existence is already implied and
dropping a step would misreport it. A neighbourhood walk is open-ended, and
there the structure *is* the answer -- placeholders would let an agent
holding a grant that reads nothing map adjacency, degree and clustering
across a person's memory, then re-seed on a placeholder id and keep going.
So denied nodes leave, every edge with a denied endpoint leaves with them,
and the response reports only aggregates: how many objects were walked, how
many are hidden, how many edges went with them, and the deny reasons. The
picture is known to be partial without disclosing where the holes are.
There is no MCP tool for it: it is a visualization payload, and handing
agents a structure-enumeration primitive would give back exactly what that
decision withholds.

`GET /explorer` serves a single self-contained HTML page (no build step, no
npm, no CDN) that draws it: a grant token, a seed id or a question to pick
one from, nodes coloured by label, detail on click, light and dark. It
renders **only what the pasted grant can see**, and whenever the grant hid
anything it says so in a banner above the drawing, with the counts and the
reasons -- because "you can see exactly what an agent can see" is the
product, and a filtered subgraph drawn as if it were the whole graph would
be the one lie the tool must not tell.

**They are permission-checked with the same structure as the query graph**:
traverse blind, then a separate node runs `permits(scope, acl, now_ms)` per
walked claim, so the assembler cannot see an unchecked one. This matters
more here than for a plain query -- a decision superseded *because of
evidence from a source outside the agent's grant* is both the interesting
case and the leak.

A link the grant does not cover is **withheld, not dropped and not a
truncation point**: the claim comes back as `{id, withheld, reason}` with no
statement, no timestamps and no citations, and the step it sits in reports
neither its interval nor its new citations. Dropping it would silently
misstate the record -- a two-step history rendered as one step, with no way
for the agent to tell -- and truncating the walk there would additionally
hide permitted claims further along for no reason. The ids stay because they
are opaque and the query graph already returns denied candidate ids with
reasons; when *nothing* in the chain is permitted, the read declines with
reasons rather than returning an empty chain.

**Why a commitment is a facet and not a node type.** "Alice will ship the
migration by Friday" is a claim in every respect that matters: it can be
superseded ("actually Bob will"), contradicted, and reconciled. The resolver
already implements exactly that machinery over claims, and a parallel
`Commitment` node type would need all of it duplicated -- a second resolver
to keep in step with the first.

What a commitment does need is a **second status axis**, because conflating
the two is how the concept rots:

- `ClaimStatus` is *epistemic*: active / superseded / contradicted /
  reconciled. Is this still our best understanding of who owes what?
- `FulfillmentStatus` is a *lifecycle*: open / fulfilled / dropped. Did the
  thing actually happen?

They move independently. A commitment can be `active` and `fulfilled` (the
promise was kept and we still believe it), or `superseded` and `open`
(reassigned to someone else, and still outstanding). "Past due" is
deliberately not a third value: it is `open` plus a `due_at_ms` in the past,
so no writer has to keep it true.

Commitments are also the first thing to need memory that is queryable
*without* loading it: `Claim.status` and the commitment fields are promoted
out of the `payload` blob into indexed Neo4j properties
(`claim_status`, `commitment_fulfillment`, `commitment_due_at_ms`,
`commitment_owed_by`, `commitment_owed_to`), so "which commitments are open
and past due?" is one indexed Cypher query --
`Neo4jStore.open_commitments()` -- rather than a scan that filters in
Python. A commitment carries an `ObjectAcl` like any other claim and is
subject to the identical query-time permission check; there is no bypass.
- **EncryptedContentRef** -- what is stored in place of a raw body that was
  sealed inside the enclave.

### Permissions

`shared/src/permissions.rs`, mirrored by `orchestrator/.../permissions.py`.

An agent presents a **grant token** minted by the gateway against an
authenticated owner session. The grant carries a `Scope`: which sources,
which entity kinds, which time window, which maximum sensitivity, and an
expiry. Every stored object carries an `ObjectAcl` with the denormalised
facts needed to decide from `(scope, acl)` alone, with no further lookups --
which is what will make the identical evaluation possible on-chain later.

`permits(scope, acl, now_ms) -> bool` is pure and total, and **denies by
default**: an empty `sources` or `entity_kinds` list grants nothing rather
than everything.

The check happens at **query time**, not ingest time, in the query graph's
own node between retrieval and assembly. Retrieval is deliberately
permission-blind, so it is structurally impossible for the assembler to see
an unchecked candidate, and a denial surfaces as a denial with reasons
rather than as an empty result set.

Session tokens, agent grants and OAuth state are all signed with the same
secret, so each states its own `typ` and is rejected when presented as
another. That used to hold only because the three claim shapes happened to
be disjoint and serde rejects a missing field -- an accident of the structs
rather than a defence, which one `#[serde(default)]` would have undone.

Session tokens, agent grants and OAuth state no longer share a signing key
either: the gateway derives three independent keys from one root secret with
HMAC-SHA256 over a versioned label (ADR 0004). One root rather than three
secrets, because three env vars let an operator paste the same value into all
of them and never know. In `nitro` mode the gateway refuses to start on the
public development default.

One sharp edge remains before grants are load-bearing:

- **A grant cannot be revoked before it expires**, except per-object via
  `ObjectAcl.denied_agents`. There is no revocation list. Keep grant TTLs
  short until there is one. What exists now is the *evidence* layer underneath
  one: every read is logged, so an owner can at least see what a grant it
  cannot withdraw has actually been used for.

### The confidentiality model

"Encrypted, and the user owns it" is three different claims against three
different adversaries. They are not equally true, and the honest version is
below.

**1. Confidential from the storage provider.** Delivered. Raw sensitive
source content is sealed inside the enclave before it is written anywhere
(`orchestrator`'s ingestion graph calls `POST /memory/seal/encrypt`, which
the gateway proxies to the enclave), and OAuth refresh tokens are sealed
inside the enclave before the gateway persists them. Whoever runs the disk
holds ciphertext.

The ciphertext is now actually *kept*, which it was not until recently: the
ingestion graph carried it in memory, wrote a reference with
`blob_id = None`, and dropped the bytes when the run ended -- so sealing a
record destroyed it, behind a stored ref that advertised a `key_id` and a
`byte_len` and read as recoverable. Sealed bodies go to a content-addressed,
owner-partitioned blob store and `blob_id` is populated (ADR 0002). The
*route* back exists -- the gateway proxies `POST /memory/seal/decrypt` to the
enclave under an owner session -- but nothing assembles the path from a stored
`EncryptedContentRef` to those bytes, so sealed bodies are durable and not yet
retrievable.

*Caveat, stated plainly:* in mock mode "sealed" means `MOCK_SEAL_V1:`, a
reversible keystream XOR (`enclave/src/services/seal.rs`). It is
obfuscation, not encryption, and it is labelled as such in the scheme id,
the blob prefix and every response field that carries it. Real Seal needs a
key-server committee and an on-chain owner policy object and is still a
stub. What is real today is the **custody path**: the plaintext exists only
inside the enclave, so when Seal lands the invariant already holds and
nothing outside the TEE has to change.

**2. Confidential from other users and other agents.** Delivered, via
query-time permissions. Every stored object carries an `ObjectAcl`; every
query carries a grant token that resolves to an authoritative `Scope`;
`permits(scope, acl, now_ms)` is pure, total and denies by default, and it
runs between retrieval and assembly so the assembler structurally cannot
see an unchecked candidate. Since there is no revocation list, what backs this
up is the read log: an owner cannot withdraw a live grant, but can see exactly
what it has been shown (ADR 0005). The sharp edge listed under **Permissions**
above -- no revocation list -- is what stands between this and being fully
load-bearing.

**3. Confidential from the operator.** This is where precision matters.

- **Raw source content: yes.** The operator never holds a plaintext OAuth
  refresh token. The authorization code is exchanged inside the enclave,
  the refresh token is sealed before the response crosses back over VSOCK,
  and the gateway persists ciphertext it has no key for. The access token
  obtained during the exchange is used inside the enclave to identify the
  account and is then dropped -- it is never returned to the host at all,
  because a host holding an access token can read the mailbox for its
  lifetime. Only the enclave has the OAuth client secret, so the host
  cannot repeat the exchange itself either. The same holds for sealed
  record bodies.

- **Derived memory: no.** Extraction runs in the Python orchestrator,
  outside the enclave, and in `live` mode it sends record text to an
  external LLM. Entities, events, claims, their text, and their embeddings
  are written to Neo4j **in the clear**. An operator with database access
  reads the resolved memory -- who you talked to, what you decided, when it
  changed -- even though they cannot read the underlying mailbox. That is a
  real gap, not a technicality: for many purposes the resolved record is
  the more sensitive artifact.

  This is a deliberate trade, not an oversight. Moving extraction into the
  enclave would mean putting an LLM call and the ingestion pipeline inside
  the thing being attested, which destroys the auditability that makes the
  attestation worth anything. Closing it properly needs a different answer
  (client-side extraction, or an attested model endpoint), and until that
  exists the product should not claim the operator cannot read your memory.
  It can. What it cannot read is your mailbox.

**Where a plaintext refresh token exists, step by step.** This is the
invariant the connect flow is built around, and it is checkable:

| Step | Plaintext refresh token present? |
|------|----------------------------------|
| `GET /auth/authorize` builds the consent URL | no token exists yet |
| Provider redirects to `/auth/callback?code=...` | no -- a code is not a token |
| Gateway validates state, forwards the code to the enclave | no |
| **Enclave calls the provider's token endpoint** | **yes -- inside the TEE, and only here** |
| Enclave verifies the account with the access token | yes (in-TEE) |
| Enclave seals the refresh token, drops the access token | leaves the TEE as ciphertext |
| Gateway decodes base64, writes bytes to Postgres | no |
| Orchestrator, Neo4j, logs, API responses | no -- and no code path exposes it |

`gateway/tests/oauth_flow_tests.rs` runs a real enclave router in-process,
drives the real callback, and searches the bytes that actually landed in
the store for the mock plaintext. `gateway/tests/postgres_store_tests.rs`
does the same against real Postgres.

**Known gaps in the connect flow**, so nobody is surprised:

- Pending PKCE verifiers live in gateway process memory, so a restart
  invalidates in-flight consents and a multi-instance gateway needs shared
  state. This is why the verifier is not stuffed into the state token
  instead: anyone who could observe the redirect could then complete the
  flow.
- `nitro` mode has still never been run on real Nitro hardware. The
  plaintext-HTTP-into-a-TLS-port bug described under "No Rust VSOCK crate"
  is fixed and unit-tested, and the tunnel/hostname/alias tables agree
  across Rust, `run.sh` and `parent_forwarder.sh` — but agreeing in review
  is not the same as having handshaked with Google, and nothing here is
  proven until an EIF actually runs on EC2.
- `SEALED_TOKEN_STORE_URL` unset means an in-memory store. Correct for mock
  mode; it silently forgets tokens on restart, so set it for anything real.

### The Rust/Python split

The enclave's surface grew by two things: `POST /seal/{encrypt,decrypt}`
and `POST /oauth/exchange`. The attestation is only meaningful if what it
measures is small enough to audit, so nothing agentic -- no LLM calls, no
retrieval, no ingestion logic -- went in there. Code exchange qualifies on
the same test as sealing: it is small, it is the point at which a
long-lived credential comes into existence, and there is nowhere else it
can happen without breaking the confidentiality claim.

The gateway's surface is deliberately only three things: proxying
enclave-touching operations, owner-authenticated permission gating, and
receiving the OAuth redirect (which it cannot avoid -- a browser cannot
reach the enclave).

| Route | Purpose |
|-------|---------|
| `GET /auth/authorize` | build the provider consent URL (PKCE + signed, expiring state) |
| `GET /auth/callback` | validate state, have the enclave exchange the code, persist the sealed refresh token, issue the owner session |
| `POST /auth/session` | verify identity via the enclave, issue an owner session JWT |
| `POST /auth/session/introspect` | resolve an owner session to its owner id |
| `POST /memory/seal/encrypt` | seal raw content in the enclave, under the session's owner |
| `POST /memory/seal/decrypt` | unseal **record content** (never a refresh token) for an owner about to be shown it |
| `POST /auth/device/register` | register a device public key for the authenticated owner |
| `GET /auth/device/keys` | list the owner's registered device keys, including revoked ones |
| `POST /auth/device/revoke` | revoke one device key, and with it every grant it signed |
| `POST /memory/scope/introspect` | resolve a grant token to the authoritative scope |

There is no mint route. ADR 0011 moved grant signing to the owner's own device
(`kleos-device sign`), so the gateway can verify a grant and cannot produce one.

`/auth/session/introspect` is the mirror of `/memory/scope/introspect` and
exists for the same reason: the orchestrator holds no signing key, so anything
it must authenticate it has to ask the gateway about. It was added for the read
log, which is the first **owner**-authenticated thing the orchestrator serves --
every other read it does is authorised by an agent grant, and an owner's record
of what agents read must not be readable by an agent.

There is no second implementation of retrieval or ranking in Rust, on
purpose. `GET /memory/timeline` is gone -- it was a placeholder for
retrieval, which is Python's.

The orchestrator calls the gateway for the `/auth/session*` and `/memory/*`
routes and nothing else -- never the OAuth routes, and it is given no
credentials for the sealed-token store.
Its ingestion graph's `encrypt` node is the only point in the pipeline that
crosses the trust boundary, and if the gateway is unreachable the sensitive
record is not written -- there is no fallback that stores a sensitive body
in the clear.

See `orchestrator/README.md` for the graphs, the Neo4j node/edge shape, the
LangGraph/LlamaIndex division of labour, and the API.

### Still stubs

Typed, with real signatures, failing explicitly rather than silently:

- **Walrus** reads/writes. Sealed ciphertext now goes to a local
  content-addressed blob store and `EncryptedContentRef.blob_id` is populated
  (ADR 0002); `WalrusQuiltStore` has the same interface and raises. It does not
  fall back to local disk when configured, because a deployment that believes it
  writes to Walrus and actually writes to the orchestrator's disk has a
  confidentiality bug rather than a performance one.
  **There is still no read path.** Not for want of a route: the gateway proxies
  `POST /memory/seal/decrypt` to the enclave under an owner session, and
  `LocalQuiltStore.get` is implemented and owner-partitioned. What is missing is
  the middle -- nothing converts a stored `EncryptedContentRef` into a `BlobRef`,
  and nothing calls `get`.
- **Real Seal encryption.** `enclave/src/services/seal.rs` has a working
  mock implementation -- a deliberately fake, reversible keystream XOR whose
  output is prefixed `MOCK_SEAL_V1:` and whose scheme id says so, exactly
  like `MOCK_ATTESTATION_`. It is obfuscation, not encryption. The `nitro`
  build's Seal path is a documented stub: real Seal needs a key-server
  committee and an on-chain owner policy object.
- **The real Google/GitHub connectors** -- note that `chatgpt` is *not* in
  this list: it ingests real data today, because a ChatGPT export is a file
  and needs no API. Consent, code exchange and the
  sealed per-owner refresh-token store now exist (Google
  `gmail.readonly` + `calendar.readonly`, GitHub `read:user` + `repo`), but
  nothing yet *uses* a stored token to fetch data. `GoogleConnector` and
  `GitHubConnector` raise `NotImplementedError` -- in mock mode too, since
  mock fixtures are declared per connector rather than substituted for
  every source. They are registered in `connectors/registry.py` with their
  real metadata (display name, OAuth scopes, chunking), so what is missing
  is the `fetch` body and a way to get credentials.

  That second half is an open design question, not plumbing. The gateway's
  `POST /memory/seal/decrypt` unseals **record content** and deliberately not a
  **sealed refresh token** -- a different asset, and the one whose plaintext
  would hand the host standing access to a mailbox -- so there is still no path
  by which Python can obtain a usable token. Handing the
  orchestrator the unsealed refresh token would break the invariant the whole
  connect flow is built around; fetching inside the enclave would put Gmail
  pagination in the TCB. The likely answer is the third: the enclave unseals
  the refresh token, mints a short-lived access token and returns only that,
  so exposure is one token lifetime and the host still cannot renew -- it has
  neither the refresh token nor the client secret. Roadmap step 5, ADR first.
- **Live LLM/embedding calls.** `extraction/llm.py` is wired and works with
  an `ANTHROPIC_API_KEY` and `ORCHESTRATOR_MODE=live`, but has not been run
  against the live API. `VoyageEmbedder` is a stub.
- **Anything on-chain.** Grants are signed JWTs today; the `Scope` struct is
  shaped to become an on-chain grant object verbatim.
- **Wallet/domain identity signals** -- unchanged since the scaffold. (OAuth
  code exchange is no longer one: see "The confidentiality model".)
- **The MCP server** (`orchestrator/src/orchestrator/mcp_server.py`) exposes
  three read tools over stdio -- `query_memory`, `why_this_shifted`,
  `memory_context_chain`. Implemented, and still never driven from a real MCP
  client, which is the first thing roadmap step 2 fixes. There is deliberately
  no tool that writes memory, none that reads without a grant token, no
  neighbourhood tool (see "Seeing the record") and no read-log tool (see
  "Permissions").

## Step 0: hardening, and testing the central bet

Step 0 of "Where this is going" does two things: fix what was known to be
wrong, and find out whether the thing the whole project assumes is actually
true.

### What the eval found

Everything here follows from one claim -- that a **resolved, timestamped
record** beats a pile of retrievable documents. It had never been measured.
`orchestrator/src/orchestrator/eval/` now measures it: a labelled synthetic
corpus, a plain-RAG baseline held equal on everything but resolution, and a
harness that prints a verdict and exits non-zero if the bet does not pay.

```bash
cd orchestrator && .venv/bin/python -m orchestrator.eval
```

34 records, 6 labelled questions, `top_k=5`:

| metric | resolved | resolved+history | plain-rag |
|---|---|---|---|
| recall | 87% | **100%** | 93% |
| cited | 100% | 100% | 0% |
| unmarked stale assertions | 0% | **0%** | 50% |
| forbidden records returned | 33% | 33% | 50% |

Resolution helps, and the useful part is *where it does not*:

- **The win is correctness about what is current, not retrieval.** Plain RAG
  answers "which database does Lantern use" with all three decisions and nothing
  to say which one holds, because nothing in the text of a superseded decision
  says it was superseded. That is structural; no embedder fixes it.
- **The query graph alone retrieves less than the baseline** (87% vs 93%). The
  gain comes from the supersession read and from marking superseded claims, not
  from ranking. Worth knowing before anyone tunes weights.
- **Graph proximity costs precision across projects.** Both Harbour questions
  return a record that is a wrong answer, under every system.

The numbers are **not quotable**: both systems run on hashed-token embeddings,
which is the right control (embedding quality held identical, so the delta
isolates resolution) and a poor absolute measurement. The report says so itself.
Re-run and compare deltas once a real embedder is in.

Building the harness also found a defect in the product. The README promised
`why_did_this_shift` returns "the citations present in the superseder that were
absent from the claim it replaced -- the evidence that moved the decision", but
cross-source references were attached to the *event* and not the claim, so the
read reached one hop short of evidence that was in Neo4j all along. "What
changed and why" scored 60%; with references propagated onto the claim, 100%.
No test caught it because every test asserted the mechanism rather than the
outcome. See ADR 0006.

### What was fixed

- **Sealing a record no longer destroys it.** `EncryptedContentRef.blob_id` was
  always `None` and the ciphertext lived only in the LangGraph checkpoint, so a
  sensitive body was gone when the run ended -- while the stored ref advertised
  a `key_id` and a `byte_len` that read as recoverable. Ciphertext now goes to a
  content-addressed, owner-partitioned blob store. ADR 0002.
- **Every agent read is logged** -- which grant, which agent, which objects,
  when -- and surfaced in the explorer under an owner session. ADR 0005.
- **Edge writes are owner-scoped**, like every traversal already was.
- **Ingestion reports what it wrote**, not what it considered. A run that
  skipped an unsealable event used to report it as stored.
- **Recency is a real half-life** (and 180 days, not 30: in a resolved record an
  old decision stands until something supersedes it). Ranking weights are
  configurable so the harness can move them. ADR 0003.
- **Three signing keys derived from one root** instead of one key for sessions,
  grants and OAuth state. ADR 0004.
- **`scripts/services.sh`** for environments with no `docker compose` plugin.

### Step 0 still open

- **Live LLM extraction and a real embedding model**, on a consenting owner's
  own export. Needs an API key. Until then the eval's absolute numbers mean
  little and `extraction/llm.py` has never run against the live API.
- **Build the `.eif` and run it on EC2.** Needs EC2. `nitro` mode has still
  never executed on real hardware, which is the load-bearing gap under every
  confidentiality claim here.

## Env vars

See `.env.example` at the repo root for the whole stack, and
`orchestrator/.env.example` for the orchestrator's authoritative list.

## Deviations from the nautilus reference

- Uses `fastcrypto`'s `Ed25519KeyPair`, same as the nautilus reference --
  matches Sui's crypto stack for later phases (on-chain signing, Sui SDK
  interop).
- Cargo feature renamed `aws` -> `nitro` per the new project's naming.
- Dropped Sui, government-API, and DigiLocker-specific code paths entirely;
  replaced with the OAuth-provider + Walrus/Walrus-Memory port plan above.
  Redis is back, but on the Python side only (RQ ingestion jobs) -- nothing in
  the enclave or gateway talks to it.
