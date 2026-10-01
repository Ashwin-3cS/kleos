# From the Kleos memory layer to a private, voice-first personal assistant

**Goal.** A Jarvis-style personal assistant: small hardware nodes in each room
that listen and answer, backed by a coordination layer and a frontier-model
call path, with privacy as a structural property rather than a promise.

Kleos (this repo) is the memory and permissions core. This plan adds the
voice/edge layer, a fast conversational path, a privacy gateway, and a
decision about where extraction runs.

Phases are ordered by dependency. **Do not start a phase until the previous
phase's exit test passes.**

## Working rules (every phase)

- Small PRs, tests first. `cargo test --workspace`, the Python suite,
  `cargo clippy` and `ruff` stay green.
- Never weaken the core invariants:
  - `permits()` stays pure, total and deny-by-default; a multi-source ACL
    requires *all* its sources in scope.
  - Retrieval stays permission-blind, and the permission check stays its own
    graph node.
  - Traversals stay owner-constrained at every node on the path.
  - The withhold-vs-drop asymmetry between history reads and neighbourhood
    reads stays intact.
- An ADR in `docs/adr/` for every architectural decision: what, why,
  alternatives, consequences.
- Keep the README honest about what is mocked, stubbed, or never run on real
  hardware.
- No real personal data in fixtures, logs or commits. Raw audio is never
  stored by default.
- Every phase ends with a runnable demo script and a *measured* result, not
  just passing tests.
- If a phase's exit test fails, stop and write up why before continuing.

## Phase 0 — Harden the core, test the central bet

Fix known defects, and find out whether a resolved record actually beats
plain retrieval.

- [x] Persist sealed ciphertext on the node so sensitive ingestion stops
      destroying event bodies. Remove the dependency on the in-process
      checkpointer for ciphertext. (ADR 0002)
- [x] Scope `Neo4jStore.link()` by owner.
- [x] Make `IngestionResult` count actual writes, not candidates.
- [x] Fix the recency decay — it is not a true half-life, and a 30-day
      constant penalises old decisions too heavily. Make it configurable and
      evaluated. (ADR 0003)
- [x] Split the single signing secret into separate keys for sessions,
      grants and OAuth state. (ADR 0004)
- [x] Fix the README setup path (`docker compose` is not universally
      available; document the plain `docker`/`podman` route).
- [x] Add an agent read log: which agent, which grant, which objects, when.
      Surface it in the explorer. (ADR 0005)
- [x] Build an eval harness: a labelled question set ("who decided X", "what
      changed and why", "what do I owe whom", "what did I know on date D"),
      expected answers and citations, running both the resolved-record path
      and a plain RAG baseline and reporting the difference. (ADR 0006)
- [ ] Run live LLM extraction and a real embedding model (replace the
      hashed-token stub; pin `EMBEDDING_DIM` and the Neo4j vector index) on a
      consenting owner's own export. *Needs an API key.*
- [ ] Bounded spike, in parallel: build the Nitro `.eif` and run it on EC2.
      Record every tunnel or attestation problem found. *Needs EC2.*

**Exit test.** The eval harness produces a number comparing the resolved
record against plain RAG. If resolution does not help, stop and rethink
before building further. The `.eif` either runs, or its failures are
documented in an ADR.

**Status, 2026-10-01.** The retrieval half of the exit test has run and
passes: recall 100% vs 93%, cited 100% vs 0%, unmarked stale assertions 0%
vs 50% (ADR 0006). Two caveats carried forward rather than swept up: the
query graph *alone* retrieves less than the baseline, so the gain is the
supersession read and the marking rather than the ranking; and the numbers
rest on hashed-token embeddings, so the delta is meaningful and the absolute
figures are not. The two remaining items both need resources this machine
does not have -- an API key, and an EC2 instance.

## Phase 1 — Voice prototype, cloud-first

One room, one node, a conversation that feels natural.

- Hardware reference node: Raspberry Pi (or ESP32-S3 satellite), mic array,
  speaker, a hardware mute switch that physically cuts the mic, status LED.
- On-device wake word and voice-activity detection. Nothing leaves the device
  before the wake word fires.
- Pipeline: streamed speech-to-text, frontier model, streamed text-to-speech.
- Node-to-hub protocol over mTLS, with a pairing flow and per-device identity.
- Instrument every stage and log latency (STT, model first token, TTS first
  audio). Budget: ~1s from end of speech to first audio.

**Exit test.** A scripted 20-turn conversation with recorded p50/p95 latency
per stage. The mute switch is verified to stop all audio capture.

## Phase 2 — Privacy gateway and the memory read path

The assistant answers from memory, and only the minimum leaves the boundary.

- Model gateway: PII redaction and pseudonymisation before sending, reversed
  on the way back; a minimal-context builder (never send whole memory); a
  provider adapter for zero-retention, no-training terms; a swappable
  provider interface; a `local_only` mode that never calls an external model;
  a log of every outbound payload, exposed to the user.
- The voice agent becomes an MCP client of Kleos holding a scoped grant.
  First real MCP client integration test — no client has driven the server yet.
- Fast read path: a recent-context cache so spoken answers do not wait on
  graph queries.
- A "why do you think that?" tool returning supporting claims with citations
  and provenance.
- Decide deliberately whether `assemble` stays a formatted list or becomes
  synthesis. ADR.

**Exit test.** "What did I decide about X last week?" answers correctly with
citations. The outbound log shows only redacted, minimal context for that
request. A request in `local_only` mode makes zero external calls, verified
by test.

## Phase 3 — Voice becomes memory

- Speaker enrollment and identification, so each utterance is attributed to
  an owner. Unknown speakers go to guest mode, which is never ingested.
- Transcript connector: utterances become events with both spoken-at and
  ingested-at timestamps. Store transcripts, not audio, with a retention
  policy.
- Sensitivity labelling, with voice defaulting to sensitive.
- Replace the resolver's `_topic()` heuristic (first three non-stopword
  tokens as an unordered set) with embedding-plus-entity matching. Measure
  false supersessions on the eval set.
- Background consolidation job: deduplicate, handle contradictions, forget
  per policy.
- User controls: view, correct and delete memories, with deletion
  propagating to retrieval and to derived claims.

**Exit test.** Eval scores do not regress; the false-supersession rate is
measured and acceptable. A test proves guest speech is never stored.
Deleting a memory removes it from retrieval and from derived claims.

## Phase 4 — Local-first hub, and the extraction decision

Resolve the tension between "an LLM must read everything to resolve memory"
and "the operator must not see your data".

- Hub service on a mini PC: the orchestrator running locally with a small
  local model for extraction and simple intents.
- Compare local extraction against frontier-model extraction on the eval set.
  Record the quality/privacy trade-off in an ADR, choosing among: hub-side
  extraction, an attested inference endpoint, or the narrower claim
  (confidential from the storage provider and other agents, not from the
  operator).
- Encrypted sync from hub to the enclave-backed cloud, keys held by the user.
- Signed OTA updates, secure device pairing and revocation.

**Exit test.** Common requests work with no internet. The eval gap between
local and frontier extraction is measured, and the ADR states the decision
and its consequences.

## Phase 5 — Multi-room, multi-user, real sources

- Multiple nodes with session handoff across rooms and to a phone/desktop
  client.
- Separate tenants for home and work, with no shared memory between them.
- Per-device grants (a kitchen node cannot read health data).
- Google connector with the short-lived access token design: the enclave
  unseals the refresh token, mints an access token, and returns only that.
  ADR first. One small enclave route, and the host still cannot renew.
- GitHub connector the same way.
- Replace the in-process PKCE verifier store with shared state so restarts
  and multiple gateway instances work.

**Exit test.** An automated leak test: in a two-person household, neither
person's memory is reachable by the other's agent or devices. Real Gmail data
flows end to end into the resolved record, with the host never holding a
refresh token.

## Phase 6 — Actions and agent safety

- Tool registry with risk tiers: 0 read-only, 1 reversible, 2 confirmation
  required (spoken or on-device), 3 never allowed.
- Rate limits, a global kill switch, sandboxing, per-grant action limits.
- Grant revocation list — currently only per-object `denied_agents` and short
  TTLs.
- Adversarial suite: prompt injection via emails, web pages and transcripts;
  a stranger's voice issuing commands; replayed or synthesised audio; tool
  misuse and over-broad grants.
- Every action written to the audit log with its grant and justification.

**Exit test.** The red-team suite passes. Every action is traceable in the
audit log. Revoking a grant takes effect immediately, verified by test.

## Phase 7 — Production hardening and beta

- Real Nitro deployment, with attestation verified by the client before it
  sends anything sensitive.
- Independent security review or penetration test.
- Data-protection review (India's DPDP Act, bystander and guest consent,
  retention). Proper legal advice.
- Backups, monitoring, alerting, incident runbooks.
- Closed beta with a few households. Track latency, answer accuracy, trust
  signals, opt-out/deletion requests.
- Walrus, real Seal (key-server committee) and on-chain grants **only if**
  beta users demonstrably need them.

**Exit test.** Review findings resolved or consciously accepted in writing.
Beta metrics meet the targets set in Phases 1 and 3.

## Later: physical AI

Robots and other actuators plug in as additional tools in the Phase 6
registry, each with its own risk tier and grant. Nothing above should need
redesign to support this.

## Open decisions to record as ADRs

- Where extraction runs (Phase 4).
- Whether `assemble` is retrieval-formatting or true synthesis (Phase 2).
- Retention policy for transcripts and derived memory (Phase 3).
- Which model providers are supported, and their data terms (Phase 2).
- When, if ever, to adopt on-chain components (Phase 7).
