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
