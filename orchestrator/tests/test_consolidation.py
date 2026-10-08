"""The consolidator: what a session concluded, and what it must never invent.

Consolidation is the one thing that moves working context into memory, and
almost nothing should move. So these tests are mostly about restraint.

Not yet wired: `close_session(consolidate=True)` still raises. What exists is
the consolidator and the path that reads a session's blocks back.
"""

from __future__ import annotations

from orchestrator.enums import MemoryKind
from orchestrator.extraction.consolidate import (
    RuleBasedConsolidator,
    _parse,
)

NOTES = [
    "opened migrations.py\nran the suite: 318 passed",
    "Decision: project Lantern uses Neo4j because graph proximity is a hard requirement.",
    "Procedure: to deploy, build the eif then run parent_forwarder before the gateway.",
    "he always seems to prefer postgres, probably a habit from the old job",
]


def test_it_finds_only_what_was_marked() -> None:
    """A regex cannot tell what a session concluded, and one that guessed would
    write invented claims into a real person's memory under an authenticated
    device id. So it recognises explicit cues and nothing else."""
    found = RuleBasedConsolidator().consolidate(NOTES)

    assert [c.kind for c in found] == [MemoryKind.EPISODIC, MemoryKind.PROCEDURAL]
    assert found[0].statement == "project Lantern uses Neo4j."
    assert found[0].reason == "graph proximity is a hard requirement"


def test_the_mock_consolidator_emits_no_tacit_claims() -> None:
    """The single worst thing a fixture could produce: an inference about how
    somebody thinks, unfalsifiable, maximally sensitive, attributed to a real
    person by a pattern match. The notes contain an obvious temptation."""
    found = RuleBasedConsolidator().consolidate(NOTES)
    assert all(c.kind is not MemoryKind.TACIT for c in found)


def test_an_ordinary_session_concludes_nothing() -> None:
    """Most sessions conclude nothing durable, and an empty list is the correct
    and common answer rather than a failure to extract."""
    assert RuleBasedConsolidator().consolidate(["ran the tests", "fixed a typo"]) == []


def test_a_repeated_conclusion_is_one_conclusion() -> None:
    """A scratchpad repeats itself; the record should not."""
    twice = [NOTES[1], NOTES[1]]
    assert len(RuleBasedConsolidator().consolidate(twice)) == 1


def test_a_conclusion_with_no_stated_reason_gets_no_invented_one() -> None:
    found = RuleBasedConsolidator().consolidate(["Decision: the API stays on :8090."])
    assert found[0].reason == "marked as a conclusion in the agent's own session notes"


def test_an_llm_conclusion_without_a_reason_is_dropped() -> None:
    """Dropped rather than defaulted: a conclusion with no stated reason is the
    thing the briefing cannot use, and inventing one puts words in the model's
    mouth."""
    parsed = _parse(
        '{"conclusions": ['
        '{"statement": "A.", "kind": "episodic", "reason": "because B"},'
        '{"statement": "C.", "kind": "episodic"},'
        '{"statement": "D.", "kind": "vibes", "reason": "because E"}]}'
    )
    assert [c.statement for c in parsed] == ["A."]


# -- the three states, as one transition --------------------------------
#
# Blocks are *stored* until consolidation runs, and only what it writes becomes
# *searchable*. These tests are that sentence, checked.

import pytest  # noqa: E402

from orchestrator.config import Settings  # noqa: E402
from orchestrator.connectors.agent import AGENT  # noqa: E402
from orchestrator.enums import EntityKind, Sensitivity  # noqa: E402
from orchestrator.gateway_client import ResolvedGrant  # noqa: E402
from orchestrator.graphs.decide import consolidate_session  # noqa: E402
from orchestrator.graphs.runtime import Runtime  # noqa: E402
from orchestrator.permissions import Scope  # noqa: E402
from orchestrator.storage.reads import grant_fingerprint  # noqa: E402
from orchestrator.storage.sessions import SessionError  # noqa: E402

OWNER = "owner-consolidate"
DEVICE = "device-1a2b3c"
DECIDED = "project Lantern uses Neo4j"
WHY = "graph proximity is a hard requirement"


class _Gateway:
    def __init__(self, scopes: dict[str, Scope]) -> None:
        self._scopes = scopes

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scopes[grant_token]

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        return ResolvedGrant(
            scope=self._scopes[grant_token],
            device_id=DEVICE,
            grant_fp=grant_fingerprint(grant_token),
        )

    def adopt_session(self, token: str) -> None:
        pass

    def seal_encrypt(self, plaintext: bytes):
        raise AssertionError("no enclave in this suite")

    def close(self) -> None:
        pass


def _scope(**overrides) -> Scope:
    base = dict(
        agent_id="claude-code",
        owner_id=OWNER,
        sources=["mock", AGENT],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
        may_write=True,
        write_sources=[AGENT],
        memory_kinds=list(MemoryKind),
    )
    return Scope(**{**base, **overrides})


SCOPES = {
    "writer": _scope(),
    "reader": _scope(may_write=False, write_sources=[]),
    "episodes-only": _scope(memory_kinds=[MemoryKind.EPISODIC]),
}


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    rt.gateway = _Gateway(dict(SCOPES))
    _wipe(rt)
    yield rt
    _wipe(rt)
    rt.close()


def _wipe(rt: Runtime) -> None:
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_sessions(OWNER)
    rt.store.wipe_mutations(OWNER)


def _session(rt: Runtime, token: str = "writer"):
    return rt.sessions.open_session(
        owner_id=OWNER,
        agent_id="claude-code",
        device_id=DEVICE,
        grant_fp=grant_fingerprint(token),
        ttl_secs=600,
    )


def _append(rt: Runtime, session_id: str, block: str) -> None:
    rt.sessions.append_block(
        owner_id=OWNER,
        session_id=session_id,
        block=block,
        max_blocks=50,
        max_bytes=100_000,
    )


def test_blocks_become_kinded_claims_citing_the_session(runtime: Runtime) -> None:
    session = _session(runtime)
    _append(runtime, session.id, "opened migrations.py\nran the suite")
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")
    _append(runtime, session.id, "Procedure: to deploy, build the eif then the gateway.")

    result = consolidate_session(runtime, "writer", session.id)

    assert result.blocks == 3
    assert len(result.claims) >= 2
    assert {c["kind"] for c in result.conclusions} == {"episodic", "procedural"}

    # The edge, read off the graph rather than off the session's own property.
    from_edges = runtime.store.consolidated_from(OWNER, session.id)
    assert set(from_edges) == set(result.claims)
    # And the property, which is the one-read version of the same thing.
    assert set(runtime.sessions.get(OWNER, session.id).consolidated_into) == set(
        result.claims
    )


def test_the_blocks_stay_out_of_the_index_and_the_claims_go_in(
    runtime: Runtime,
) -> None:
    """The three-state split as one assertion. Before consolidation the words
    exist in the store and are unreachable; after it, the conclusion is
    retrievable and the scratchpad still is not."""
    session = _session(runtime)
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")

    def hits() -> set[str]:
        # `vector_search` returns (node, score) pairs. Worth saying, because the
        # first version of this read `h.id` over the pairs and passed anyway --
        # the owner had no indexed memory yet, so the comprehension never ran and
        # the assertion was vacuous.
        found = runtime.store.vector_search(
            OWNER, runtime.embedder.embed(DECIDED), top_k=25
        )
        return {node.id for node, _score in found}

    assert session.id not in hits(), "a scratchpad is stored, not searchable"
    before = hits()

    result = consolidate_session(runtime, "writer", session.id)

    after = hits()
    assert set(result.claims) & after, "the conclusion must become retrievable"
    assert session.id not in after, "and the session must not"
    assert after > before


def test_consolidation_needs_may_write(runtime: Runtime) -> None:
    """A session is not a licence to write; the grant is. The outcome of
    consolidating is a claim in the person's record, so it is gated exactly like
    a direct write."""
    session = _session(runtime, "reader")
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")

    result = consolidate_session(runtime, "reader", session.id)

    assert result.claims == []
    assert result.errors, "a refusal has to be reported, not swallowed"
    assert "write_not_permitted" in " ".join(result.errors)


def test_one_refused_conclusion_does_not_refuse_the_rest(runtime: Runtime) -> None:
    """A grant covering episodes and not procedures should keep the episodes, and
    say which it would not keep."""
    session = _session(runtime, "episodes-only")
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")
    _append(runtime, session.id, "Procedure: to deploy, build the eif first.")

    result = consolidate_session(runtime, "episodes-only", session.id)

    assert [c["kind"] for c in result.conclusions] == ["episodic"]
    assert any("procedural" in e for e in result.errors)


def test_an_ordinary_session_leaves_nothing_behind(runtime: Runtime) -> None:
    session = _session(runtime)
    _append(runtime, session.id, "ran the tests\nfixed a typo in a docstring")

    result = consolidate_session(runtime, "writer", session.id)

    assert result.claims == []
    assert result.errors == []
    assert result.blocks == 1
    assert runtime.sessions.get(OWNER, session.id).consolidated_into == []


def test_consolidating_twice_adds_nothing(runtime: Runtime) -> None:
    """A conclusion is dated to the session and the record is content-addressed
    over its inputs, so re-consolidating produces the same record -- which the
    resolver recognises as a duplicate and does not write again.

    So the second call reports **no claims**, and that is the right answer rather
    than a failure: `claims` is what this call wrote, while the session's
    `consolidated_into` is everything it ever produced. Asserting the two apart
    is what catches a retry that silently writes a second copy of every
    conclusion.
    """
    session = _session(runtime)
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")

    first = consolidate_session(runtime, "writer", session.id)
    assert first.claims

    second = consolidate_session(runtime, "writer", session.id)
    assert second.claims == [], "a retry writes nothing new"
    assert second.errors == []

    stored = runtime.sessions.get(OWNER, session.id).consolidated_into
    assert sorted(stored) == sorted(first.claims)
    assert len(stored) == len(set(stored))

    # And the graph agrees: one claim, one edge.
    assert sorted(runtime.store.consolidated_from(OWNER, session.id)) == sorted(
        first.claims
    )


def test_an_unknown_session_is_refused(runtime: Runtime) -> None:
    with pytest.raises(SessionError):
        consolidate_session(runtime, "writer", "ses_does_not_exist")


def test_a_session_from_another_owner_is_not_consolidatable(runtime: Runtime) -> None:
    session = _session(runtime)
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")
    runtime.gateway._scopes["other"] = _scope(owner_id="someone-else")

    with pytest.raises(SessionError):
        consolidate_session(runtime, "other", session.id)


def test_the_consolidated_claim_names_the_device(runtime: Runtime) -> None:
    session = _session(runtime)
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")

    result = consolidate_session(runtime, "writer", session.id)

    for claim_id in result.claims:
        claim = runtime.store.get_many(OWNER, [claim_id])[0].node
        assert claim.provenance.actor_device_id == DEVICE
        assert claim.provenance.actor_session_id == session.id


def test_the_edge_does_not_make_a_session_reachable(runtime: Runtime) -> None:
    """The one edge that crosses from memory into the harness's own record, and
    it only goes one way: every traversal keys on `:Memory`, which a session is
    deliberately not."""
    session = _session(runtime)
    _append(runtime, session.id, f"Decision: {DECIDED} because {WHY}.")
    result = consolidate_session(runtime, "writer", session.id)
    assert result.claims

    reached = runtime.store.neighbour_ids(OWNER, result.claims, hops=3)
    assert session.id not in reached
