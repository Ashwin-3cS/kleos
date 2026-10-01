"""The agent read log: what was disclosed, to whom, under which grant.

The explorer always showed what a grant *could* see. Nothing showed what it
*did* see, which is the only question an owner can ask about a grant they
cannot revoke. See ADR 0005.

The properties worth holding are mostly negative: the log must not store the
grant token, must not be reachable as memory, and must not miss a read.
"""

from __future__ import annotations

import pytest

from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.graphs.history import context_chain, why_did_this_shift
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.neighbourhood import neighbourhood
from orchestrator.graphs.query import run_query
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope
from orchestrator.storage.reads import ReadEntry, grant_fingerprint

OWNER = "owner-readlog"
TOKEN = "grant-token-for-agent-reader"
NARROW_TOKEN = "grant-token-that-reads-nothing"


class _StubGateway:
    """Resolves grant tokens without a gateway.

    The query graph refuses a caller-supplied scope and insists on
    introspecting the token, which is the behaviour under test everywhere
    else -- so the stub stands in for the gateway, not for the rule.
    """

    def __init__(self, scopes: dict[str, Scope]) -> None:
        self._scopes = scopes

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scopes[grant_token]

    def adopt_session(self, token: str) -> None:
        pass

    def seal_encrypt(self, plaintext: bytes):
        raise AssertionError("no sealing in this test")

    def close(self) -> None:
        pass


def _scope(agent_id: str, **overrides) -> Scope:
    base = dict(
        agent_id=agent_id,
        owner_id=OWNER,
        sources=["mock"],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    return Scope(**{**base, **overrides})


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(settings)
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.gateway = _StubGateway(
        {
            TOKEN: _scope("agent-reader"),
            # Reads nothing: no source is in scope, so every object is denied.
            NARROW_TOKEN: _scope("agent-blind", sources=["github"]),
        }
    )
    # Sensitive fixtures need a gateway to seal; this suite has none, so the
    # one sensitive record is legitimately skipped and everything else lands.
    run_ingestion(runtime=rt, owner_id=OWNER, source="mock", thread_id="readlog-ingest")
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.close()


def test_a_query_is_recorded_with_what_it_disclosed(runtime: Runtime) -> None:
    answer = run_query(runtime, "what did we decide about the migration?", TOKEN)
    assert answer.answered

    entries = runtime.read_log.recent(OWNER)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.kind == "query"
    assert entry.agent_id == "agent-reader"
    assert entry.subject == "what did we decide about the migration?"
    assert sorted(entry.disclosed_ids) == sorted(c.object_id for c in answer.citations)
    assert entry.considered == answer.considered


def test_a_decline_is_recorded_too(runtime: Runtime) -> None:
    """A grant that reads nothing is the entry worth having: one such query is
    a misconfiguration, two hundred is an agent mapping the id space."""
    answer = run_query(runtime, "what did we decide?", NARROW_TOKEN)
    assert not answer.answered

    entry = runtime.read_log.recent(OWNER)[0]
    assert entry.disclosed_ids == []
    assert entry.denied, "the deny reasons belong in the record"
    assert {d["reason"] for d in entry.denied} == {"source_not_in_scope"}
    assert entry.considered > 0, "objects were evaluated even though none passed"


def test_the_grant_token_is_never_stored(runtime: Runtime) -> None:
    """An audit log holding live bearer credentials is a vulnerability wearing
    an accountability costume."""
    run_query(runtime, "anything", TOKEN)

    rows = runtime.store._run(
        "MATCH (r:AgentRead {owner_id: $owner_id}) RETURN properties(r) AS props",
        owner_id=OWNER,
    )
    assert rows
    for row in rows:
        serialised = repr(row["props"])
        assert TOKEN not in serialised
    assert runtime.read_log.recent(OWNER)[0].grant_fp == grant_fingerprint(TOKEN)


def test_the_fingerprint_is_stable_and_distinguishing() -> None:
    assert grant_fingerprint(TOKEN) == grant_fingerprint(TOKEN)
    assert grant_fingerprint(TOKEN) != grant_fingerprint(NARROW_TOKEN)
    assert TOKEN not in grant_fingerprint(TOKEN)


def test_every_read_path_is_logged(runtime: Runtime) -> None:
    """Four read paths, four kinds. A path that forgets to log is a path an
    owner cannot audit, and the omission is invisible from the outside."""
    answer = run_query(runtime, "what did we decide about the migration?", TOKEN)
    seed = answer.citations[0].object_id

    why_did_this_shift(runtime, seed, TOKEN)
    context_chain(runtime, seed, TOKEN, hops=2)
    neighbourhood(runtime, [seed], TOKEN, hops=1)

    kinds = [e.kind for e in runtime.read_log.recent(OWNER)]
    assert sorted(kinds) == ["context", "neighbourhood", "query", "shift"]


def test_a_read_of_a_nonexistent_id_is_still_logged(runtime: Runtime) -> None:
    """Probing ids that were never handed out looks exactly like a typo unless
    the misses are recorded."""
    why_did_this_shift(runtime, "claim-that-does-not-exist", TOKEN)

    entry = runtime.read_log.recent(OWNER)[0]
    assert entry.kind == "shift"
    assert entry.subject == "claim-that-does-not-exist"
    assert entry.disclosed_ids == []
    assert entry.considered == 0


def test_the_log_is_not_reachable_as_memory(runtime: Runtime) -> None:
    """``:AgentRead`` deliberately carries no ``:Memory`` label. If it did, one
    agent's read entries would be retrievable by another agent through the very
    permission check they exist to audit."""
    run_query(runtime, "anything at all", TOKEN)

    labels = runtime.store._run(
        "MATCH (r:AgentRead {owner_id: $owner_id}) RETURN labels(r) AS labels",
        owner_id=OWNER,
    )
    assert labels
    for row in labels:
        assert "Memory" not in row["labels"]

    # And it does not surface through retrieval, which is keyed on :Memory.
    answer = run_query(runtime, "agent-reader read something", TOKEN)
    read_ids = {e.id for e in runtime.read_log.recent(OWNER)}
    assert read_ids.isdisjoint({c.object_id for c in answer.citations})


def test_reads_are_ordered_newest_first(runtime: Runtime) -> None:
    for i in range(3):
        run_query(runtime, f"question {i}", TOKEN)
    entries = runtime.read_log.recent(OWNER)
    assert [e.subject for e in entries[:3]] == ["question 2", "question 1", "question 0"]


def test_the_summary_groups_by_grant_not_by_agent(runtime: Runtime) -> None:
    """The grant is the capability. One agent id holding two grants is two
    authorisations, and an owner deciding which to stop issuing needs them
    apart."""
    second_token = "a-second-grant-for-the-same-agent"
    runtime.gateway._scopes[second_token] = _scope("agent-reader")

    run_query(runtime, "first grant", TOKEN)
    run_query(runtime, "second grant", second_token)

    summary = runtime.read_log.summary(OWNER)
    assert summary["reads"] == 2
    assert len(summary["grants"]) == 2
    assert {g["agent_id"] for g in summary["grants"]} == {"agent-reader"}
    assert {g["grant_fp"] for g in summary["grants"]} == {
        grant_fingerprint(TOKEN),
        grant_fingerprint(second_token),
    }


def test_the_summary_counts_declines_separately(runtime: Runtime) -> None:
    run_query(runtime, "allowed", TOKEN)
    run_query(runtime, "denied", NARROW_TOKEN)
    run_query(runtime, "denied again", NARROW_TOKEN)

    by_fp = {g["grant_fp"]: g for g in runtime.read_log.summary(OWNER)["grants"]}
    assert by_fp[grant_fingerprint(NARROW_TOKEN)]["declined"] == 2
    assert by_fp[grant_fingerprint(NARROW_TOKEN)]["disclosed"] == 0
    assert by_fp[grant_fingerprint(TOKEN)]["declined"] == 0
    assert by_fp[grant_fingerprint(TOKEN)]["disclosed"] > 0


def test_one_owners_log_is_not_another_owners(runtime: Runtime) -> None:
    runtime.read_log.record(
        ReadEntry(
            owner_id="owner-somebody-else",
            agent_id="agent-x",
            grant_fp="deadbeef",
            kind="query",
            disclosed_ids=["x"],
        )
    )
    try:
        assert runtime.read_log.recent(OWNER) == []
        assert len(runtime.read_log.recent("owner-somebody-else")) == 1
    finally:
        runtime.store.wipe_read_log("owner-somebody-else")


def test_a_wipe_of_memory_leaves_the_log(runtime: Runtime) -> None:
    """Re-ingesting does not un-disclose what an agent was already shown."""
    run_query(runtime, "something", TOKEN)
    runtime.store.wipe_owner(OWNER)
    assert len(runtime.read_log.recent(OWNER)) == 1


def test_a_long_question_is_truncated_not_stored_whole(runtime: Runtime) -> None:
    """The log records what was asked, it is not a transcript store."""
    question = "why " * 400
    run_query(runtime, question, TOKEN)
    subject = runtime.read_log.recent(OWNER)[0].subject
    assert len(subject) < len(question)
    assert subject.endswith("...")
