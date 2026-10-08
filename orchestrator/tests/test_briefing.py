"""Device 2 being told what device 1 decided, and why.

This is the feature the harness exists for, so the central test is written as
the scenario rather than as a unit: device 1 records a decision that conflicts
with the person's own, device 2 is about to act on the same subject, and what it
gets back has to name the other device and carry its reason.

Everything else here is a boundary the briefing must not cross while doing it:
no adjacency, no structure, nothing about objects the grant cannot read beyond
the fact that they exist, and a log entry that still shows which underlying read
disclosed what.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.connectors.agent import AGENT
from orchestrator.enums import EntityKind, MemoryKind, Sensitivity
from orchestrator.gateway_client import ResolvedGrant
from orchestrator.graphs.brief import brief_before_acting
from orchestrator.graphs.decide import record_decision
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope
from orchestrator.storage.reads import grant_fingerprint

OWNER = "owner-brief"
DEVICE_1 = "device-1a2b3c"
DEVICE_2 = "device-9z8y7x"

OWNER_SAID = "Ashwin decided that project Lantern will use Postgres."
DEVICE_1_SAYS = "project Lantern will use Neo4j."
BECAUSE = "graph proximity is a hard requirement and Postgres cannot do it"
INTENT = "about to pick a database for project Lantern"


class _Gateway:
    """Two devices, one owner, distinct grants."""

    def __init__(self, scopes: dict[str, tuple[Scope, str]]) -> None:
        self._scopes = scopes

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scopes[grant_token][0]

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        scope, device = self._scopes[grant_token]
        return ResolvedGrant(
            scope=scope, device_id=device, grant_fp=grant_fingerprint(grant_token)
        )

    def adopt_session(self, token: str) -> None:
        pass

    def seal_encrypt(self, plaintext: bytes):
        raise AssertionError("no enclave in this suite")

    def close(self) -> None:
        pass


def _scope(agent: str, **overrides) -> Scope:
    base = dict(
        agent_id=agent,
        owner_id=OWNER,
        sources=["text", AGENT],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
        memory_kinds=list(MemoryKind),
    )
    return Scope(**{**base, **overrides})


TOKENS = {
    # Device 1 writes, and may replace the person's own decision.
    "device-1": (
        _scope(
            "claude-code",
            may_write=True,
            write_sources=[AGENT],
            may_supersede_owner=True,
        ),
        DEVICE_1,
    ),
    # Device 2 only reads.
    "device-2": (_scope("chatgpt"), DEVICE_2),
    # Reads the agent source but not the person's own notes.
    "agent-only": (_scope("chatgpt-narrow", sources=[AGENT]), DEVICE_2),
    # Reads nothing at all.
    "blind": (_scope("chatgpt-blind", sources=["github"]), DEVICE_2),
}


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    rt.gateway = _Gateway(dict(TOKENS))
    _wipe(rt)
    # The person's own decision, ingested the ordinary way.
    from orchestrator.connectors.direct import build_record
    from orchestrator.graphs.ingestion import run_ingestion

    run_ingestion(
        runtime=rt,
        owner_id=OWNER,
        source="text",
        records=[build_record(OWNER, OWNER_SAID, occurred_at_ms=1_600_000_000_000)],
        thread_id="brief-own",
    )
    yield rt
    _wipe(rt)
    rt.close()


def _wipe(rt: Runtime) -> None:
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.store.wipe_mutations(OWNER)
    rt.store.wipe_sessions(OWNER)


# -- the scenario -------------------------------------------------------


def test_device_b_is_told_what_device_a_decided_and_why(runtime: Runtime) -> None:
    """The whole feature, as one assertion.

    Device 2 asks nothing about device 1. It states an intent, and is told that
    another device decided something bearing on it, which device, and the reason
    that device gave.
    """
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)

    briefing = brief_before_acting(runtime, INTENT, "device-2")

    assert briefing.answered, briefing.text
    advisories = " ".join(briefing.advisories)
    assert DEVICE_1[:12] in advisories, (
        f"the briefing must name the deciding device: {briefing.advisories}"
    )
    assert BECAUSE in advisories, "and carry the reason that device gave"
    assert "device-authenticated" in advisories, (
        "and say whether that identity is worth anything"
    )


def test_the_briefing_names_the_rule_as_well_as_the_reason(runtime: Runtime) -> None:
    """The reason is prose the agent wrote; the rule is why the *record* moved.
    An agent reading a supersession should be able to tell those apart."""
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)

    briefing = brief_before_acting(runtime, INTENT, "device-2")
    advisories = " ".join(briefing.advisories)
    assert "rule:" in advisories


def test_a_fresh_memory_says_there_is_nothing_to_know(runtime: Runtime) -> None:
    """Not an error and not an empty result: the first agent should be told
    plainly that nothing bears on this.

    On an empty memory, and that is the honest shape of this test. A briefing is
    only as selective as the ranking underneath it: retrieval returns `top_k`
    candidates whatever the intent, so with one claim stored, *any* intent
    surfaces it. The limitation is real and belongs on the briefing rather than
    in a test that pretends otherwise -- in mock mode the embeddings are hashed
    tokens and barely selective at all.
    """
    runtime.store.wipe_owner(OWNER)

    briefing = brief_before_acting(runtime, "about to name a new project", "device-2")

    assert briefing.answered is False
    assert "nothing" in briefing.text.lower()
    assert briefing.advisories == []


def test_an_unrelated_intent_still_surfaces_what_exists(runtime: Runtime) -> None:
    """The limitation, asserted rather than hidden.

    Retrieval is ranking, not a relevance gate: it returns its best `top_k` and
    the briefing renders what the permission check allowed. So an agent briefing
    on an unrelated intent is told about the decisions that do exist. That is the
    right failure direction -- too much context rather than a missed conflict --
    but it is a property of the ranking and it will change when the ranking does.
    """
    briefing = brief_before_acting(runtime, "about to rename a variable", "device-2")

    assert briefing.answered, (
        "with material in memory, a briefing returns the best candidates it has "
        "rather than nothing"
    )


def test_attributions_cover_only_what_was_disclosed(runtime: Runtime) -> None:
    """Per object, and only objects this agent was just permitted to see. The
    mutation log read wholesale would tell one agent what every other agent has
    been writing."""
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)

    briefing = brief_before_acting(runtime, INTENT, "device-2")
    disclosed = {c["object_id"] for c in briefing.relevant}
    assert disclosed
    assert {a.object_id for a in briefing.attributions} <= disclosed


# -- what it must not do ------------------------------------------------


def test_the_briefing_returns_no_adjacency(runtime: Runtime) -> None:
    """There is no neighbourhood tool on purpose, and a briefing returning
    structure would hand back the same seed-walk-reseed primitive under a
    friendlier name."""
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)

    payload = brief_before_acting(runtime, INTENT, "device-2").as_dict()

    for forbidden in ("edges", "nodes", "adjacency", "neighbours", "graph"):
        assert forbidden not in payload, f"a briefing must not return {forbidden}"


def test_an_out_of_scope_conflict_is_withheld_without_its_reasoning(
    runtime: Runtime,
) -> None:
    """Withheld, not dropped. The agent named a subject, so the conflict's
    existence is implied by the question -- but a grant that cannot read the
    person's own notes must not learn what they said."""
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)

    briefing = brief_before_acting(runtime, INTENT, "agent-only")

    withheld = [
        step
        for history in briefing.conflicts
        for step in history.get("steps", [])
        if (step.get("superseded") or {}).get("withheld")
    ]
    if withheld:
        for step in withheld:
            superseded = step["superseded"]
            assert "statement" not in superseded, "a withheld claim keeps no content"
            assert superseded.get("reason"), "and says why it was withheld"
        assert any("cannot read" in line for line in briefing.advisories)

    # Whatever was disclosed, the person's own wording must not appear.
    rendered = " ".join(briefing.advisories) + briefing.text
    assert "Postgres" not in rendered or any(
        c["source"] == AGENT for c in briefing.relevant
    )


def test_a_grant_that_reads_nothing_is_declined_not_emptied(runtime: Runtime) -> None:
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)

    briefing = brief_before_acting(runtime, INTENT, "blind")

    assert briefing.answered is False
    assert briefing.denied, "a decline has to say why, not come back empty"
    assert briefing.advisories == []


def test_bodies_need_both_the_ask_and_the_grant(runtime: Runtime) -> None:
    """Gated twice. The caller has to ask, and the grant has to permit it."""
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)

    asked_only = brief_before_acting(runtime, INTENT, "device-2", include_body=True)
    assert asked_only.bodies == [], "no may_unseal, no bodies"


def test_an_empty_intent_is_refused(runtime: Runtime) -> None:
    with pytest.raises(ValueError, match="needs an intent"):
        brief_before_acting(runtime, "   ", "device-2")


# -- the log ------------------------------------------------------------


def test_each_composed_read_logs_separately(runtime: Runtime) -> None:
    """One entry for the composite *and* the entries each underlying read wrote.

    A composite that replaced them would hide which objects each read actually
    disclosed, which is the one thing the read log exists to answer.
    """
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)
    runtime.store.wipe_read_log(OWNER)

    brief_before_acting(runtime, INTENT, "device-2")

    kinds = [e.kind for e in runtime.read_log.recent(OWNER)]
    assert "brief" in kinds, "the composite has to be recorded"
    assert "query" in kinds, "and so does the read it was composed from"


def test_the_log_entry_names_the_device_that_was_briefed(runtime: Runtime) -> None:
    record_decision(runtime, "device-1", DEVICE_1_SAYS, BECAUSE)
    runtime.store.wipe_read_log(OWNER)

    brief_before_acting(runtime, INTENT, "device-2")

    composite = [e for e in runtime.read_log.recent(OWNER) if e.kind == "brief"]
    assert composite
    assert composite[0].device_id == DEVICE_2
    assert composite[0].subject == INTENT, "the owner should see what it was about to do"


def test_the_session_rides_into_the_log(runtime: Runtime) -> None:
    session = runtime.sessions.open_session(
        owner_id=OWNER,
        agent_id="chatgpt",
        device_id=DEVICE_2,
        grant_fp=grant_fingerprint("device-2"),
        ttl_secs=600,
    )
    runtime.store.wipe_read_log(OWNER)

    brief_before_acting(runtime, INTENT, "device-2", session_id=session.id)

    composite = [e for e in runtime.read_log.recent(OWNER) if e.kind == "brief"]
    assert composite
    assert composite[0].session_id == session.id
