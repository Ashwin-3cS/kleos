"""Full mock-mode path, minus the gateway: ingest fixtures, then query them.

The gateway round trip (sealing sensitive content) is covered by
``scripts/orchestrator_smoke.sh``, which runs the Rust stack alongside.
Here the seal step is exercised only in its failure mode -- no gateway
means the sensitive record is not written, which is the behaviour that
matters: nothing falls back to storing a sensitive body in the clear.
"""

from __future__ import annotations

import time

import pytest

from orchestrator.connectors.mock import MockConnector
from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope, evaluate
from orchestrator.retrieval.index import MemoryRetriever

OWNER = "owner-e2e"
FIXTURE_RECORDS = len(list(MockConnector().fetch(OWNER, 0)))


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(settings)
    rt.store.wipe_owner(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def _full_scope(**overrides) -> Scope:
    base = dict(
        agent_id="agent-e2e",
        owner_id=OWNER,
        sources=["mock"],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    return Scope(**{**base, **overrides})


def test_ingestion_writes_resolved_memory(runtime):
    result = run_ingestion(runtime, owner_id=OWNER, source="mock")

    assert result.records == FIXTURE_RECORDS
    assert result.entities > 0
    assert result.claims > 0
    assert result.supersessions, "the fixture set contains a superseding decision"

    counts = runtime.store.count(OWNER)
    assert counts.get("Entity", 0) > 0
    assert counts.get("Claim", 0) > 0


def test_retrieval_ranks_and_permission_check_filters(runtime):
    run_ingestion(runtime, owner_id=OWNER, source="mock")

    retriever = MemoryRetriever(runtime.store, runtime.embedder, owner_id=OWNER, top_k=8)
    ranked = retriever.retrieve_stored("What datastore will project Atlas use?")
    assert ranked, "hybrid retrieval should return candidates"
    assert any("Atlas" in r.node.text for r in ranked)

    now_ms = int(time.time() * 1000)
    allowed = [r for r in ranked if evaluate(_full_scope(), r.node.node.acl, now_ms).allowed]
    assert allowed

    narrow = _full_scope(entity_kinds=[EntityKind.ORGANIZATION])
    assert not [r for r in ranked if evaluate(narrow, r.node.node.acl, now_ms).allowed]


def test_ingestion_is_idempotent(runtime):
    first = run_ingestion(runtime, owner_id=OWNER, source="mock")
    before = runtime.store.count(OWNER)
    run_ingestion(runtime, owner_id=OWNER, source="mock")
    after = runtime.store.count(OWNER)
    assert before == after
    assert first.records == FIXTURE_RECORDS


def test_sensitive_record_is_not_written_without_a_gateway(runtime):
    result = run_ingestion(runtime, owner_id=OWNER, source="mock")
    if result.sealed:
        pytest.skip("a gateway is running; the failure path is not exercised here")
    assert any("seal failed" in e or "was not sealed" in e for e in result.errors)


def test_chunking_differs_by_source():
    from orchestrator.retrieval.index import chunk_for_source

    diff = "diff --git a/x b/x\n@@ -1 +1 @@\n-a\n+b\n@@ -9 +9 @@\n-c\n+d"
    assert len(chunk_for_source(diff, "github")) == 3
    prose = "para one\n\npara two"
    assert chunk_for_source(prose, "google") == ["para one\n\npara two"]


def test_graph_traversal_does_not_cross_owners(runtime, store):
    """Graph proximity must not walk out of the owner's subgraph.

    Proximity feeds ranking *before* the permission check runs, so an
    unscoped traversal would leak another owner's node ids and hop distances
    with nothing downstream to catch it.
    """
    other = "owner-intruder"
    store.wipe_owner(other)
    try:
        run_ingestion(runtime, owner_id=OWNER, source="mock")
        run_ingestion(runtime, owner_id=other, source="mock")

        theirs = _ids_for(store, other)[:3]
        assert theirs, "the intruder should have nodes to seed from"

        # Seeding with the other owner's ids, as OWNER, must return nothing:
        # neither end of the walk belongs to OWNER.
        assert store.neighbour_ids(OWNER, theirs) == {}

        # And OWNER's own traversal still returns neighbours, so the filter
        # did not simply break proximity for everyone.
        assert store.neighbour_ids(OWNER, _ids_for(store, OWNER)[:3])
    finally:
        store.wipe_owner(other)


def _ids_for(store, owner_id: str) -> list[str]:
    rows = store._run(
        "MATCH (n:Memory {owner_id: $owner_id}) RETURN n.id AS id LIMIT 25",
        owner_id=owner_id,
    )
    return [r["id"] for r in rows]
