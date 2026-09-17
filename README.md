# memorai (placeholder name)

A decentralized personal memory layer for humans and AI agents. Every
individual's digital life is ingested inside a TEE (AWS Nitro Enclave),
attested via NSM, and (in later phases) encrypted with Seal and stored on
Walrus. The user owns it; authorized AI agents query it with scoped
permissions. No government ID -- identity comes from stacked OAuth signals
(Google, GitHub, wallet signature) verified **inside the enclave**.

Phase 1 built the infrastructure scaffold: the enclave, the gateway, and the
deploy plumbing, proven end to end via CLI with a mock OAuth
identity-verification flow. **Phase 2** adds the memory layer itself -- the
resolved schema, a Python orchestration service running the ingestion and
query graphs, Neo4j-backed retrieval, and query-time permissions -- all
outside the enclave, which stays exactly as narrow as Phase 1 left it. There
is still no web app, no SDK and no smart contracts.

The only asset carried over from the abandoned prior product
(`suiverify`, a decentralized KYC platform) is the Nitro Enclave build/deploy
template at `suiverify/nautilus-attestation-backend/` -- its NSM attestation
logic and socat-based VSOCK bridging pattern. That project is read-only
reference material and is not part of this repo.

## Architecture

```
gateway (Axum, host, TCP)
  - OAuth redirect flow (code exchange still a stub) + session JWT
  - Mints/introspects scoped agent grants; proxies seal requests
  - Proxies all sensitive work to the enclave over VSOCK
        |
        v
enclave (Axum, inside Nitro Enclave)        <- core trust boundary
  - Verifies OAuth tokens itself, against the provider, inside the TEE
  - Computes trust tier from stacked signals
  - NSM attestation over the result
  - Seal-encrypts raw sensitive content before it leaves the TEE
        |
        v
storage: Neo4j (queryable index) -- Walrus for encrypted raw blobs, not wired yet
```

Alongside, and outside the trust boundary:

```
orchestrator/ (Python: LangGraph + LlamaIndex)
  - ingestion graph: fetch -> extract -> resolve -> encrypt -> write
  - query graph:     authorize -> retrieve -> permission-check -> assemble/decline
  - calls the gateway only to seal raw content and to resolve agent grants
        |
        v
Neo4j (entities, events, claims, edges, native vector index) + Redis (RQ jobs)
```

**Why verification happens in the enclave and not the gateway:** the NSM
attestation only means something if the thing it's attesting actually
happened inside the TEE. If the gateway verified the OAuth token and just
told the enclave "trust me, this checked out," the attestation would cover
nothing of value. So `enclave/src/routes/identity.rs` calls Google/GitHub's
verification endpoints itself, and only then produces the attestation.

**Phase 1 end-to-end flow** (see `scripts/smoke_test.sh`):
1. Client hits `POST /identity/verify` on the gateway with a raw OAuth token
   (obtained manually -- curl, or a one-off script; real code exchange is
   Phase 2, see `gateway/src/routes/auth.rs`).
2. Gateway forwards the token to the enclave over its VSOCK-bridged TCP
   client (`gateway/src/vsock/client.rs`).
3. Enclave calls the provider's verification endpoint itself, through an
   outbound VSOCK tunnel (`enclave/src/services/oauth/{google,github}.rs`).
4. Enclave computes a trust tier from the signals present: Google alone = 1,
   + GitHub = 2, + wallet = 3, + domain = 4 (wallet/domain are Phase 2 stubs
   that reject explicitly rather than pretending to work).
5. Enclave produces an NSM attestation document over the result.
6. Gateway returns `{ identity, attestation }` as JSON, unmodified.

No on-chain writes happen in Phase 1. Nothing is persisted.

## No Rust VSOCK crate

There is no VSOCK crate anywhere in this codebase, by design (mirroring the
proven `nautilus-attestation-backend` pattern). All VSOCK<->TCP bridging is
done at the shell level with `socat`:

- Inbound: `enclave/run.sh` runs
  `socat VSOCK-LISTEN:4000,reuseaddr,fork TCP:localhost:4000 &`, so the
  enclave's Rust binary just binds plain TCP (`enclave/src/vsock/listener.rs`)
  -- completely ordinary Axum/tokio code.
- Outbound: `enclave/run.sh` opens tunnels like
  `socat TCP-LISTEN:8002,reuseaddr,fork VSOCK-CONNECT:3:8002 &`, so
  `enclave/src/services/http.rs` and the OAuth provider clients just call
  `http://127.0.0.1:<port>/...` with plain `reqwest` and the tunnel carries
  it out over VSOCK to the host.
- On the host, `scripts/parent_forwarder.sh` bridges each of those VSOCK
  ports onward to the real external service, and bridges the gateway's
  inbound TCP calls into the enclave's VSOCK port 4000.

In both `mock` and `nitro` mode the Rust code only ever speaks plain TCP/
HTTP; the difference is entirely in whether a socat bridge exists on the
other end.

## VSOCK ports

| Port | Direction        | Purpose                        |
|------|-------------------|---------------------------------|
| 4000 | Gateway -> Enclave | Main API                       |
| 5000 | Enclave -> Host    | Log forwarding                 |
| 8002 | Enclave -> Host    | Google OAuth APIs               |
| 8003 | Enclave -> Host    | GitHub API                      |
| 8004 | Enclave -> Host    | Walrus publisher/aggregator     |
| 8005 | Enclave -> Host    | Walrus Memory relayer           |

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
./scripts/smoke_test.sh         # posts mock tokens through the gateway
kill $(cat .local/enclave.pid) $(cat .local/gateway.pid)
```

The orchestrator has the same discipline: `ORCHESTRATOR_MODE=mock` (default)
needs no API keys -- fixture connector, rule-based extractor, deterministic
hashed-token embeddings. Neo4j and Redis are real services even in mock
mode.

### Full stack, end to end

```bash
cd orchestrator
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp .env.example .env
docker compose up -d                     # neo4j :7688, redis :6380
.venv/bin/pytest                         # 32 tests
cd ..

./scripts/run_local.sh --with-orchestrator   # enclave + gateway + neo4j + redis
./scripts/orchestrator_smoke.sh              # the Phase 2 proof, below
```

`scripts/orchestrator_smoke.sh` walks the whole path and is the thing to run
to see Phase 2 work:

1. `POST /auth/session` with `mock_google_alice` -- the enclave verifies the
   identity and attests it; the gateway issues an owner session JWT.
2. `POST /ingest` on the orchestrator enqueues an RQ job and returns a job id.
3. The worker runs the ingestion graph: the mock connector yields 4 fixture
   records, the rule-based extractor produces 12 entities / 4 events /
   4 claims, the resolver links the superseding decisions, the one sensitive
   record's body is sealed **inside the enclave** (the gateway round trip),
   and everything is written to Neo4j with provenance and ACL fields.
4. `POST /memory/scope/grant` on the gateway mints a scoped grant for
   `agent-demo`.
5. `POST /query` runs the query graph, which introspects the grant, retrieves
   with hybrid ranking, permission-checks each candidate, and answers with
   citations -- including marking the two superseded claims as superseded.
6. The same question under a scope covering only GitHub/organizations
   declines explicitly: `"8 candidate memory object(s) matched, but none are
   within the requesting agent's scope (source not in scope)"`.

## EC2 / Nitro deploy path

```bash
cargo build --release --no-default-features --features nitro -p enclave
./scripts/build_enclave.sh      # stagex/docker build -> enclave/out/*.eif
./scripts/deploy.sh             # ships .eif + gateway binary to DEPLOY_HOST
# on the parent instance:
nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path memorai-enclave.eif --enclave-cid 16
./parent_forwarder.sh &
ENCLAVE_MODE=nitro ./memorai-gateway
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
scripts/      build/run/deploy/smoke-test plumbing
```

`shared/src/memory.rs` and `shared/src/permissions.rs` are the real schema
now, and `orchestrator/src/orchestrator/{schema,permissions}.py` mirror them
field for field on the wire.
`orchestrator/tests/test_schema_parity.py` parses the Rust source and fails
if the two ever drift.

`enclave/src/services/memory.rs` is **gone**: it implied the enclave ingests,
which it does not and should not. Ingestion lives entirely in
`orchestrator/`. What the enclave gained instead is `POST /seal/{encrypt,
decrypt}` -- the one Phase 2 operation that genuinely belongs inside the TEE.

## Phase 2: what exists now

The Phase 1 architecture is untouched -- enclave/gateway/shared,
VSOCK-over-socat, the mock/nitro split are all exactly as they were.
Everything below is additive.

**Product shape.** A user connects sources (starting with Google/GitHub,
since OAuth for both exists from Phase 1); their activity is resolved into
a structured, timestamped memory, attested inside the TEE at the points
where it touches sensitive raw content, encrypted, and stored under the
user's own keys. Authorized agents query it with scoped permissions over
MCP. The bet is that the value is a **resolved, timestamped record** (who
said what, when it changed, why, what it links to), not a pile of
retrievable raw documents.

### Decisions made

Three questions were open at the end of Phase 1. They are now settled:

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
- **Provenance** -- a citation chain back to originating source events, not
  just a confidence float. Confidence is carried, but it is advisory.
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

Two sharp edges to fix before grants are load-bearing:

- **Owner session tokens and agent grant tokens are signed with the same
  secret and carry no type discriminator.** They are not interchangeable
  today, but only because their claim shapes are disjoint and serde rejects
  a missing field -- an accident, not a defence. Adding a `#[serde(default)]`
  or an optional field to either struct would silently make a session usable
  as a grant. A `typ` claim, or separate secrets, would make that
  structural.
- **A grant cannot be revoked before it expires**, except per-object via
  `ObjectAcl.denied_agents`. There is no revocation list. Keep grant TTLs
  short until there is one.

### The Rust/Python split

The enclave's surface grew by exactly one thing: `POST /seal/{encrypt,
decrypt}`. The attestation is only meaningful if what it measures is small
enough to audit, so nothing agentic -- no LLM calls, no retrieval, no
ingestion logic -- went in there.

The gateway's memory surface is deliberately only two things: proxying
enclave-touching operations, and owner-authenticated permission gating.

| Route | Purpose |
|-------|---------|
| `POST /auth/session` | verify identity via the enclave, issue an owner session JWT |
| `POST /memory/seal/encrypt` | seal raw content in the enclave, under the session's owner |
| `POST /memory/scope/grant` | owner mints a scoped, expiring grant for a named agent |
| `POST /memory/scope/introspect` | resolve a grant token to the authoritative scope |

There is no second implementation of retrieval or ranking in Rust, on
purpose. `GET /memory/timeline` is gone -- it was a placeholder for
retrieval, which is Python's.

The orchestrator calls the gateway for those four things and nothing else.
Its ingestion graph's `encrypt` node is the only point in the pipeline that
crosses the trust boundary, and if the gateway is unreachable the sensitive
record is not written -- there is no fallback that stores a sensitive body
in the clear.

See `orchestrator/README.md` for the graphs, the Neo4j node/edge shape, the
LangGraph/LlamaIndex division of labour, and the API.

### Still stubs

Typed, with real signatures, failing explicitly rather than silently:

- **Walrus** reads/writes. Sealed ciphertext is currently carried by the
  ingestion graph and `EncryptedContentRef.blob_id` stays `None`.
- **Real Seal encryption.** `enclave/src/services/seal.rs` has a working
  mock implementation -- a deliberately fake, reversible keystream XOR whose
  output is prefixed `MOCK_SEAL_V1:` and whose scheme id says so, exactly
  like `MOCK_ATTESTATION_`. It is obfuscation, not encryption. The `nitro`
  build's Seal path is a documented stub: real Seal needs a key-server
  committee and an on-chain owner policy object.
- **The real Google/GitHub connectors.** Phase 1 OAuth proves identity; it
  does not request Gmail/Calendar/repo data scopes, and there is no
  per-owner refresh-token store yet.
- **Live LLM/embedding calls.** `extraction/llm.py` is wired and works with
  an `ANTHROPIC_API_KEY` and `ORCHESTRATOR_MODE=live`, but has not been run
  against the live API. `VoyageEmbedder` is a stub.
- **Anything on-chain.** Grants are signed JWTs today; the `Scope` struct is
  shaped to become an on-chain grant object verbatim.
- **OAuth code exchange** (`gateway/src/routes/auth.rs::callback`), and
  wallet/domain identity signals -- unchanged Phase 1 stubs.
- **The MCP server** (`orchestrator/src/orchestrator/mcp_server.py`) exposes
  the query graph as a tool over stdio. It is implemented but has not been
  driven from a real MCP client.

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
  Redis is back in Phase 2, but on the Python side only (RQ ingestion jobs)
  -- nothing in the enclave or gateway talks to it.
