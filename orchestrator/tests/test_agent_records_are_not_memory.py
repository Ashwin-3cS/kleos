"""The one mechanism that keeps the system's record of itself out of its memory.

Three kinds of node now record what the harness did rather than what the person
did: `:AgentRead` (what a grant disclosed), `:AgentSession` and `:SessionBlock`
(what an agent was working from). None of them carries the `:Memory` label, and
that single fact is what makes them unretrievable -- the vector index and every
traversal in `neo4j_store` key on that label and nothing else.

It matters because the alternative is a feedback loop rather than a leak. If an
agent's reads and scratchpads were memory, then agent B being briefed on agent
A's decision would itself create memory, which agent C's briefing would surface,
which would create more -- a record whose growth is a function of how often it is
read rather than of what happened. Within a week the graph is mostly the system's
commentary on itself, and the resolver is comparing agent-about-agent material
against the person's actual decisions in the same subject neighbourhood.

Asserted rather than reviewed, because the way this breaks is one convenient
`SET n:Memory` added by someone who wanted a node to show up in the explorer.
This file is what fails when that happens. See ADR 0005 and ADR 0016.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.graphs.runtime import Runtime
from orchestrator.storage.mutations import (
    KIND_STATUS,
    RULE_NEWER_ASSERTED_AT,
    Actor,
    MutationEntry,
)
from orchestrator.storage.reads import ReadEntry

OWNER = "owner-not-memory"

#: Every label that records the harness's own activity. A new one gets added
#: here, which is the point: the list is the invariant.
HARNESS_LABELS = ["AgentRead", "AgentSession", "SessionBlock", "Mutation"]


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    _wipe(rt)
    # One of each, written through the real writers rather than hand-built, so
    # the test covers the code path that actually runs.
    rt.read_log.record(
        ReadEntry(
            owner_id=OWNER,
            agent_id="claude-code",
            device_id="device-1",
            grant_fp="fp-1",
            kind="query",
            disclosed_ids=["clm_x"],
            subject="what did we decide about the database",
        )
    )
    session = rt.sessions.open_session(
        owner_id=OWNER,
        agent_id="claude-code",
        device_id="device-1",
        grant_fp="fp-1",
        ttl_secs=600,
    )
    rt.sessions.append_block(
        owner_id=OWNER,
        session_id=session.id,
        block="decided on Postgres because the migration is cheaper",
        max_blocks=10,
        max_bytes=10_000,
    )
    rt.store.append_mutation(
        MutationEntry.for_actor(
            Actor(agent_id="claude-code", device_id="device-1"),
            owner_id=OWNER,
            object_id="clm_not_memory",
            kind=KIND_STATUS,
            field_name="status",
            before="active",
            after="superseded",
            reason="a later decision about Postgres replaced it",
            rule=RULE_NEWER_ASSERTED_AT,
        )
    )
    yield rt
    _wipe(rt)
    rt.close()


def _wipe(rt: Runtime) -> None:
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.store.wipe_sessions(OWNER)
    rt.store.wipe_mutations(OWNER)


@pytest.mark.parametrize("label", HARNESS_LABELS)
def test_a_harness_record_never_carries_the_memory_label(
    runtime: Runtime, label: str
) -> None:
    rows = runtime.store._run(
        f"MATCH (n:{label} {{owner_id: $owner_id}}) RETURN labels(n) AS labels",
        owner_id=OWNER,
    )
    assert rows, f"the fixture should have written at least one :{label}"
    for row in rows:
        assert "Memory" not in row["labels"], (
            f":{label} must not carry :Memory -- the vector index and every "
            "traversal key on that label, so this is the whole separation"
        )


@pytest.mark.parametrize("label", HARNESS_LABELS)
def test_a_harness_record_is_not_reachable_as_memory(runtime: Runtime, label: str) -> None:
    """Belt and braces: the label check above is the mechanism, this is the
    consequence. If someone replaces the mechanism with something else, this is
    the test that says whether the consequence survived."""
    ids = [
        row["id"]
        for row in runtime.store._run(
            f"MATCH (n:{label} {{owner_id: $owner_id}}) RETURN n.id AS id",
            owner_id=OWNER,
        )
        if row["id"]
    ]
    if not ids:  # :SessionBlock has no id of its own; it is addressed by index.
        pytest.skip(f":{label} nodes are not addressed by id")

    assert not runtime.store.get_many(OWNER, ids)
    assert not runtime.store.neighbour_ids(OWNER, ids, hops=3)
    assert not runtime.store.edges_among(OWNER, ids)


def test_the_memory_graph_holds_only_memory(runtime: Runtime) -> None:
    """From the other direction: whatever is retrievable is only ever one of the
    three memory node types. A fourth label showing up here means something that
    records the harness's activity became retrievable."""
    rows = runtime.store._run(
        "MATCH (n:Memory {owner_id: $owner_id}) RETURN DISTINCT labels(n) AS labels",
        owner_id=OWNER,
    )
    seen = {label for row in rows for label in row["labels"]}
    assert seen <= {"Memory", "Entity", "Event", "Claim"}, seen


def test_a_scratchpad_is_not_retrievable_by_its_own_words(runtime: Runtime) -> None:
    """The failure this is really about: an agent's working notes answering
    another agent's question."""
    hits = runtime.store.vector_search(
        OWNER, runtime.embedder.embed("why did we choose Postgres"), top_k=25
    )
    assert hits == [] or all(h.label in {"Entity", "Event", "Claim"} for h in hits)
