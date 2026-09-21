"""The permission-filtered graph neighbourhood.

Reuses the two fixture graphs that already exist: the ``ledger``/``inbox``
scenario from ``test_shift_history`` (supersessions, a contradiction and
cross-source citations) and the seven mock records (commitments, and the
``OWED_BY``/``OWED_TO`` edges they carry).

The read's defining choice is the opposite of the shift history's: a denied
object is **dropped**, not withheld as a placeholder, because in an
open-ended walk a placeholder discloses the structure -- adjacency, degree,
density -- that the walk was asking for in the first place. What comes back
instead is a count, so the picture is known to be partial without saying
where the holes are.
"""

from __future__ import annotations

import json

import pytest

from orchestrator import api
from orchestrator.connectors import REGISTRY, ConnectorSpec
from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.neighbourhood import neighbourhood
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope
from test_shift_history import (
    INBOX_002,
    LEDGER_001,
    NEO4J,
    OWNER,
    POSTGRES,
    REDIS,
    ScriptedConnector,
    _claims,
    _FakeGateway,
    _ids,
    _ingest_scenario,
    _scope,
)
from test_shift_history import runtime as shift_runtime  # noqa: F401 -- a fixture


@pytest.fixture
def runtime(shift_runtime):  # noqa: F811 -- pytest names it from the import above
    """The ledger/inbox scenario, under this module's own fixture name."""
    return shift_runtime

MOCK_OWNER = "owner-neighbourhood-mock"
OTHER_OWNER = "owner-neighbourhood-other"


@pytest.fixture
def mock_runtime(settings, store):
    """The seven mock fixtures: commitments and their entity edges."""
    rt = Runtime.build(settings)
    rt.gateway = _FakeGateway(
        Scope(
            agent_id="agent-neighbourhood",
            owner_id=MOCK_OWNER,
            sources=["mock"],
            entity_kinds=list(EntityKind),
            max_sensitivity=Sensitivity.CONFIDENTIAL,
        )
    )
    rt.store.wipe_owner(MOCK_OWNER)
    run_ingestion(rt, owner_id=MOCK_OWNER, source="mock")
    yield rt
    rt.store.wipe_owner(MOCK_OWNER)
    rt.close()


def _endpoint(rt, seed_ids, hops=2) -> dict:
    """The FastAPI handler itself, over the same runtime."""
    api._runtime = rt
    try:
        return api.memory_neighbourhood(
            api.NeighbourhoodRequest(seed_ids=seed_ids, grant_token="grant-ok", hops=hops)
        )
    finally:
        api._runtime = None


def test_the_neighbourhood_is_nodes_and_typed_edges_around_a_seed(runtime):
    first, second, third, dynamo = _ids(runtime)
    view = neighbourhood(runtime, [first], "grant-ok", hops=2)

    assert view.answered
    ids = {n["id"] for n in view.nodes}
    assert {first, second, third} <= ids
    assert view.nodes[0]["id"] == first and view.nodes[0]["hops"] == 0
    assert {"SUPERSEDES", "CITES", "ABOUT"} <= {e["type"] for e in view.edges}
    assert view.sources == ["inbox", "ledger"]
    assert view.withheld == 0

    seed = view.nodes[0]
    assert seed["label"] == "Claim"
    assert seed["text"] == POSTGRES
    assert seed["status"] == "superseded"
    assert seed["is_commitment"] is False
    assert seed["occurred_at_ms"] > 0
    labels = {n["label"] for n in view.nodes}
    assert {"Claim", "Event", "Entity"} <= labels


def test_hops_bound_the_walk(runtime):
    first, _, _, _ = _ids(runtime)
    near = neighbourhood(runtime, [first], "grant-ok", hops=1)
    far = neighbourhood(runtime, [first], "grant-ok", hops=3)
    assert max(n["hops"] for n in near.nodes) <= 1
    assert len(far.nodes) > len(near.nodes)


def test_commitments_and_their_entity_edges_are_legible(mock_runtime):
    by_statement = _claims(mock_runtime.store, MOCK_OWNER)
    commitment = by_statement["project Atlas will ship the storage migration by 2025-03-07."]
    view = neighbourhood(mock_runtime, [commitment.id], "grant-ok", hops=1)

    assert view.answered
    seed = next(n for n in view.nodes if n["id"] == commitment.id)
    assert seed["is_commitment"] is True
    assert {"OWED_BY", "OWED_TO"} <= {e["type"] for e in view.edges}


def test_a_seed_that_is_not_stored_answers_nothing(runtime):
    view = neighbourhood(runtime, ["clm_does_not_exist"], "grant-ok")
    assert not view.answered
    assert view.nodes == [] and view.edges == [] and view.considered == 0


def test_another_owners_node_returns_nothing_from_the_store_and_the_endpoint(runtime, store):
    """Owner B's grant may not use owner A's node id as an existence oracle.

    Asserted twice: the store's own reads are owner-constrained, and the
    endpoint over them returns an empty answer rather than a decline that
    would confirm the id exists somewhere.
    """
    ledger = ScriptedConnector("ledger", [LEDGER_001])
    inbox = ScriptedConnector("inbox", [INBOX_002])
    registry = REGISTRY.copy()
    registry.register(
        ConnectorSpec("ledger", "Ledger", lambda s: ledger, mock_factory=lambda s: ledger)
    )
    registry.register(
        ConnectorSpec("inbox", "Inbox", lambda s: inbox, mock_factory=lambda s: inbox)
    )
    other = Runtime.build(runtime.settings, registry=registry)
    other.store.wipe_owner(OTHER_OWNER)
    try:
        _ingest_scenario(other, OTHER_OWNER, ledger, inbox)
        theirs = _claims(store, OTHER_OWNER)[REDIS].id
        # It really is a live node -- for its own owner.
        assert store.get_many(OTHER_OWNER, [theirs])
        assert store.neighbour_ids(OTHER_OWNER, [theirs], hops=2)

        # The store, under owner A (the grant's owner).
        assert store.get_many(OWNER, [theirs]) == []
        assert store.neighbour_ids(OWNER, [theirs], hops=2) == {}
        assert store.edges_among(OWNER, [theirs]) == []

        # The endpoint, under owner A's grant.
        body = _endpoint(runtime, [theirs])
        assert body["answered"] is False
        assert body["nodes"] == [] and body["edges"] == []
        assert body["considered"] == 0 and body["withheld"] == 0
    finally:
        other.store.wipe_owner(OTHER_OWNER)
        other.close()


def test_denied_nodes_are_dropped_entirely_and_counted_not_placeholdered(runtime):
    """A ledger-only grant sees the ledger claims and nothing of the inbox.

    Nothing identifies what was removed: no ids, no per-node placeholder, no
    hop distances. The count and the reasons are the whole disclosure.
    """
    first, second, third, dynamo = _ids(runtime)
    runtime.gateway = _FakeGateway(_scope(sources=["ledger"]))

    view = neighbourhood(runtime, [first], "grant-ok", hops=3)
    assert view.answered
    shown = {n["id"] for n in view.nodes}
    assert first in shown
    # The inbox claim and the inbox contradiction are simply not there.
    assert second not in shown and dynamo not in shown
    assert not any("withheld" in n for n in view.nodes)

    blob = json.dumps(view.as_dict())
    assert second not in blob and dynamo not in blob
    assert NEO4J not in blob and "inbox-002" not in blob

    # But the viewer is told the picture is partial, and by how much.
    assert view.withheld >= 2
    assert view.withheld + len(view.nodes) == view.considered
    assert view.withheld_reasons == ["source_not_in_scope"]
    assert view.withheld_edges > 0
    assert "not shown" in view.text and "partial" in view.text


def test_no_edge_survives_with_an_endpoint_the_agent_cannot_see(runtime):
    first, _, _, _ = _ids(runtime)
    runtime.gateway = _FakeGateway(_scope(sources=["ledger"]))

    view = neighbourhood(runtime, [first], "grant-ok", hops=3)
    shown = {n["id"] for n in view.nodes}
    assert view.edges, "the ledger side of the graph still has edges"
    assert all(e["from"] in shown and e["to"] in shown for e in view.edges)


def test_a_scope_covering_nothing_declines_rather_than_drawing_an_empty_graph(runtime):
    first, _, _, _ = _ids(runtime)
    runtime.gateway = _FakeGateway(_scope(sources=["github"]))

    view = neighbourhood(runtime, [first], "grant-ok", hops=2)
    assert not view.answered
    assert view.nodes == [] and view.edges == []
    assert view.considered > 0 and view.withheld == view.considered
    assert "source not in scope" in view.text


def test_a_caller_supplied_scope_is_rejected(runtime):
    first, _, _, _ = _ids(runtime)
    graph = __import__(
        "orchestrator.graphs.neighbourhood", fromlist=["build_neighbourhood_graph"]
    ).build_neighbourhood_graph(runtime)
    with pytest.raises(ValueError, match="caller-supplied scope"):
        graph.invoke(
            {"seed_ids": [first], "scope": _scope().model_dump(mode="json"), "hops": 1},
            config={"configurable": {"thread_id": "neighbourhood:spoof"}},
        )
