"""Why a decision shifted, and the citation chain behind it.

The scenario is a decision that moves twice, across two sources, with each
move carried by a record that cites the one before it:

* ``ledger-001`` (day 0)  -- Helios will use Postgres.
* ``inbox-002``  (day 3)  -- Helios will use Neo4j; the record cites
  ``ledger-001``.
* ``ledger-003`` (day 9)  -- Helios will use Redis; the record cites
  ``inbox-002``. It arrives in a later ledger fetch, which is why the chain
  is linear rather than a fork.
* ``inbox-004``  (day 9)  -- Helios will use DynamoDB, asserted at the same
  instant as ``ledger-003``, so the resolver records a contradiction rather
  than a supersession. Unresolved conflict is part of the story.

Nothing here writes edges by hand: every ``SUPERSEDES``, ``CONTRADICTS`` and
``CITES`` edge below was produced by the ingestion graph.
"""

from __future__ import annotations

import pytest

from orchestrator.connectors import REGISTRY, ConnectorSpec
from orchestrator.enums import ClaimStatus, EntityKind, Sensitivity
from orchestrator.graphs.history import context_chain, why_did_this_shift
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope
from orchestrator.schema import Claim, RawRecord

OWNER = "owner-shift"
INTRUDER = "owner-shift-other"
DAY_MS = 86_400_000
BASE_MS = 1_735_689_600_000  # 2025-01-01T00:00:00Z

POSTGRES = "project Helios will use Postgres for the primary datastore."
NEO4J = "project Helios will use Neo4j for the primary datastore."
REDIS = "project Helios will use Redis for the primary datastore."
DYNAMO = "project Helios will use DynamoDB for the primary datastore."


def _record(external_id, connector, day, who, statement, cites=None) -> RawRecord:
    return RawRecord(
        external_id=external_id,
        connector=connector,
        occurred_at_ms=BASE_MS + day * DAY_MS,
        title=f"Helios datastore ({external_id})",
        body=f"{who} decided that {statement}",
        url=f"https://{connector}.local/{external_id}",
        participants=[who],
        metadata={"cites": list(cites or [])},
    )


LEDGER_001 = _record("ledger-001", "ledger", 0, "Alice", POSTGRES)
INBOX_002 = _record("inbox-002", "inbox", 3, "Bob", NEO4J, cites=["ledger:ledger-001"])
LEDGER_003 = _record("ledger-003", "ledger", 9, "Carol", REDIS, cites=["inbox:inbox-002"])
INBOX_004 = _record("inbox-004", "inbox", 9, "Dana", DYNAMO)


class ScriptedConnector:
    """A fixture source whose record list grows between fetches, the way a
    real one does."""

    def __init__(self, name: str, records: list[RawRecord]) -> None:
        self.name = name
        self.records = records

    def fetch(self, owner_id: str, since_ms: int):
        return [r for r in self.records if r.occurred_at_ms >= since_ms]


class _FakeGateway:
    """Stands in for the gateway's grant introspection.

    The graph must still resolve the token through *something* it did not
    get from the caller, so the token is checked rather than ignored.
    """

    def __init__(self, scope: Scope) -> None:
        self.scope = scope

    def introspect_scope(self, grant_token: str) -> Scope:
        if grant_token != "grant-ok":
            raise ValueError("grant is not active")
        return self.scope

    def close(self) -> None:
        pass


def _scope(**overrides) -> Scope:
    base = dict(
        agent_id="agent-shift",
        owner_id=OWNER,
        sources=["ledger", "inbox"],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    return Scope(**{**base, **overrides})


def _ingest_scenario(rt: Runtime, owner_id: str, ledger, inbox) -> None:
    run_ingestion(rt, owner_id=owner_id, source="ledger", thread_id=f"{owner_id}:l1")
    run_ingestion(rt, owner_id=owner_id, source="inbox", thread_id=f"{owner_id}:i1")
    ledger.records.append(LEDGER_003)
    run_ingestion(rt, owner_id=owner_id, source="ledger", thread_id=f"{owner_id}:l2")
    inbox.records.append(INBOX_004)
    run_ingestion(rt, owner_id=owner_id, source="inbox", thread_id=f"{owner_id}:i2")


@pytest.fixture
def runtime(settings, store):
    ledger = ScriptedConnector("ledger", [LEDGER_001])
    inbox = ScriptedConnector("inbox", [INBOX_002])
    registry = REGISTRY.copy()
    registry.register(
        ConnectorSpec("ledger", "Ledger", lambda s: ledger, mock_factory=lambda s: ledger)
    )
    registry.register(
        ConnectorSpec("inbox", "Inbox", lambda s: inbox, mock_factory=lambda s: inbox)
    )
    rt = Runtime.build(settings, registry=registry)
    rt.gateway = _FakeGateway(_scope())
    rt.store.wipe_owner(OWNER)
    _ingest_scenario(rt, OWNER, ledger, inbox)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def _claims(store, owner_id: str = OWNER) -> dict[str, Claim]:
    rows = store._run(
        "MATCH (c:Claim {owner_id: $owner_id}) RETURN c.payload AS payload", owner_id=owner_id
    )
    claims = [Claim.model_validate_json(r["payload"]) for r in rows]
    return {c.statement: c for c in claims}


def _ids(runtime) -> tuple[str, str, str, str]:
    by_statement = _claims(runtime.store)
    return (
        by_statement[POSTGRES].id,
        by_statement[NEO4J].id,
        by_statement[REDIS].id,
        by_statement[DYNAMO].id,
    )


def test_the_fixture_really_shifts_twice_across_two_sources(runtime):
    by_statement = _claims(runtime.store)
    first, second, third = by_statement[POSTGRES], by_statement[NEO4J], by_statement[REDIS]

    assert first.id in second.supersedes
    assert second.id in third.supersedes
    assert [first.status, second.status] == [ClaimStatus.SUPERSEDED] * 2
    assert first.acl.sources == ["ledger"]
    assert second.acl.sources == ["inbox"]
    assert by_statement[DYNAMO].status is ClaimStatus.CONTRADICTED


def test_the_chain_answers_from_the_head_the_tail_or_the_middle(runtime):
    first, second, third, _ = _ids(runtime)
    for seed in (first, second, third):
        history = why_did_this_shift(runtime, seed, "grant-ok")
        assert history.answered
        assert [c["id"] for c in history.chain] == [first, second, third]


def test_each_step_carries_the_citations_new_in_the_superseder(runtime):
    first, second, third, _ = _ids(runtime)
    history = why_did_this_shift(runtime, first, "grant-ok")

    assert [(s["superseded"]["id"], s["superseding"]["id"]) for s in history.steps] == [
        (first, second),
        (second, third),
    ]

    step_one, step_two = history.steps
    # The evidence that moved the decision is what appeared in the superseder
    # and was not already cited by the claim it replaced -- and it came from
    # a different source each time.
    assert [c["connector"] for c in step_one["new_citations"]] == ["inbox"]
    assert [c["external_id"] for c in step_one["new_citations"]] == ["inbox-002"]
    assert [c["connector"] for c in step_two["new_citations"]] == ["ledger"]
    assert [c["external_id"] for c in step_two["new_citations"]] == ["ledger-003"]
    assert step_one["elapsed_ms"] == 3 * DAY_MS
    assert step_two["elapsed_ms"] == 6 * DAY_MS
    assert not any(s["withheld"] for s in history.steps)

    # A citation the superseded claim already had is not new information.
    assert all(
        c["event_id"] not in {x["event_id"] for x in step_two["new_citations"]}
        for c in step_one["new_citations"]
    )


def test_an_unresolved_contradiction_is_part_of_the_story(runtime):
    _, _, third, dynamo = _ids(runtime)
    history = why_did_this_shift(runtime, third, "grant-ok")
    pairs = [(c["claim"]["id"], c["contradicts"]["id"]) for c in history.conflicts]
    assert (dynamo, third) in pairs
    assert "contradicts" in history.text


def test_a_scope_missing_one_source_withholds_that_link_without_dropping_it(runtime):
    """A step whose evidence came from an un-granted source is the whole
    reason this read is permission-checked. It is withheld, not dropped: a
    two-step history silently reported as one step would misstate the record
    with no way for the agent to tell."""
    first, second, third, dynamo = _ids(runtime)
    runtime.gateway = _FakeGateway(_scope(sources=["ledger"]))

    history = why_did_this_shift(runtime, first, "grant-ok")
    assert history.answered
    # The shape of the history survives; the inbox claim's content does not.
    assert [c["id"] for c in history.chain] == [first, second, third]
    withheld = [c for c in history.chain if c.get("withheld")]
    assert [c["id"] for c in withheld] == [second]
    assert set(withheld[0]) == {"id", "withheld", "reason"}
    assert withheld[0]["reason"] == "source_not_in_scope"
    # The contradicting inbox claim is out of scope for the same reason.
    assert {d["id"] for d in history.denied} == {second, dynamo}
    assert {d["reason"] for d in history.denied} == {"source_not_in_scope"}

    # Both steps touch the withheld claim, so neither may report an interval
    # or the citation that moved the decision -- that citation names the
    # source the grant does not cover.
    assert all(s["withheld"] for s in history.steps)
    assert all(s["elapsed_ms"] is None and s["new_citations"] == [] for s in history.steps)
    assert "withheld" in history.text
    # And nothing about the withheld claim leaked into the rendered text.
    assert NEO4J not in history.text
    assert "inbox-002" not in history.text


def test_a_scope_covering_nothing_declines_rather_than_returning_empty(runtime):
    first, _, _, _ = _ids(runtime)
    runtime.gateway = _FakeGateway(_scope(sources=["github"]))

    history = why_did_this_shift(runtime, first, "grant-ok")
    assert not history.answered
    assert history.chain == [] and history.steps == []
    assert history.considered == 4
    assert "source not in scope" in history.text
    assert {d["reason"] for d in history.denied} == {"source_not_in_scope"}


def test_a_claim_belonging_to_another_owner_returns_nothing(runtime, store):
    """The walk is owner-constrained at every node, like ``neighbour_ids``:
    a claim id from another owner is not an existence oracle."""
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
    other.store.wipe_owner(INTRUDER)
    try:
        _ingest_scenario(other, INTRUDER, ledger, inbox)
        theirs = _claims(store, INTRUDER)[NEO4J].id

        history = why_did_this_shift(runtime, theirs, "grant-ok")
        assert not history.answered
        assert history.chain == [] and history.steps == [] and history.considered == 0
        assert history.denied == []
        assert theirs in history.text and "is present in this memory" in history.text

        chain = context_chain(runtime, theirs, "grant-ok")
        assert not chain.answered and chain.nodes == []
    finally:
        other.store.wipe_owner(INTRUDER)
        other.close()


def test_context_chain_crosses_sources_over_citation_edges(runtime):
    _, _, third, _ = _ids(runtime)
    chain = context_chain(runtime, third, "grant-ok", hops=3)

    assert chain.answered
    assert chain.sources == ["inbox", "ledger"]
    reached = {n["id"]: n for n in chain.nodes if n["hops"] > 0}
    events = {n.get("source", {}).get("external_id") for n in reached.values()}
    # claim -> its own event -> the inbox record it cites -> the ledger
    # record that one cites: three sources' worth of hops, no Thread node.
    assert {"ledger-003", "inbox-002", "ledger-001"} <= events
    assert chain.edges, "the chain is made of stored CITES edges"


def test_context_chain_withholds_an_out_of_scope_hop(runtime):
    _, _, third, _ = _ids(runtime)
    runtime.gateway = _FakeGateway(_scope(sources=["ledger"]))
    chain = context_chain(runtime, third, "grant-ok", hops=3)

    assert chain.answered
    withheld = [n for n in chain.nodes if n.get("withheld")]
    assert withheld, "the inbox hop is not visible under a ledger-only grant"
    assert all(n["reason"] == "source_not_in_scope" for n in withheld)
    assert all("summary" not in n and "source" not in n for n in withheld)
    assert chain.sources == ["ledger"]
    assert "inbox-002" not in chain.text
