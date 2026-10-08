"""An agent writing into the record, and what stops it overwriting the person.

This is the first path by which anything other than the owner's own sources puts
a claim in memory, so most of what matters here is refusal:

- no write without `may_write`, and the refusal names the reason;
- no choosing its own source, because an agent that could would write a claim
  that claims to be a typed note from the person;
- no choosing its own precedence, because a claim that could nominate itself a
  delegate could overwrite the owner's decision;
- **contradicts by default, supersedes only when the grant says so.** ADR 0014
  established that a fetched page may never supersede the person; an agent the
  owner explicitly granted that is a delegate rather than a stranger, and the
  difference is a property of the grant.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.connectors.agent import AGENT
from orchestrator.enums import Authority, ClaimStatus, EntityKind, MemoryKind, Sensitivity
from orchestrator.gateway_client import ResolvedGrant
from orchestrator.graphs.decide import WriteRefused, record_decision
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope
from orchestrator.schema import Claim
from orchestrator.storage.reads import grant_fingerprint

OWNER = "owner-decide"
DEVICE = "device-1a2b3c"

#: What device 1 is about to decide, and the person's own earlier decision about
#: the same subject.
#: Phrased for the rule-based extractor's fixture grammar, because this one
#: goes through real extraction -- it is the *person's* source, not a
#: declaration.
OWNER_SAID = "Ashwin decided that project Lantern will use Postgres."
AGENT_SAYS = "project Lantern will use Neo4j."
BECAUSE = "graph proximity is a hard requirement and Postgres cannot do it"


class _Gateway:
    """Resolves grants without a gateway, and refuses to seal.

    No sealing on purpose: a decision recorded with `sensitive=True` needs the
    enclave, and this suite has none -- so that path is asserted to *fail* rather
    than quietly storing a body in the clear.
    """

    def __init__(self, scopes: dict[str, Scope]) -> None:
        self._scopes = scopes

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scopes[grant_token]

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        return ResolvedGrant(
            scope=self.introspect_scope(grant_token),
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


TOKENS = {
    "writer": _scope(),
    "delegate": _scope(may_supersede_owner=True),
    "reader": _scope(may_write=False, write_sources=[], memory_kinds=[]),
    "wrong-source": _scope(write_sources=["text"]),
    "episodes-only": _scope(memory_kinds=[MemoryKind.EPISODIC]),
}


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    rt.gateway = _Gateway(dict(TOKENS))
    _wipe(rt)
    yield rt
    _wipe(rt)
    rt.close()


def _wipe(rt: Runtime) -> None:
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_mutations(OWNER)
    rt.store.wipe_sessions(OWNER)


def _claims(rt: Runtime) -> list[Claim]:
    rows = rt.store._run(
        "MATCH (c:Claim {owner_id: $o}) RETURN c.payload AS payload", o=OWNER
    )
    return [Claim.model_validate_json(r["payload"]) for r in rows]


def _owner_decision(rt: Runtime) -> Claim:
    """The person's own earlier decision, ingested the ordinary way."""
    from orchestrator.connectors.direct import build_record
    from orchestrator.graphs.ingestion import run_ingestion

    record = build_record(OWNER, OWNER_SAID, occurred_at_ms=1_600_000_000_000)
    run_ingestion(
        runtime=rt, owner_id=OWNER, source="text", records=[record], thread_id="own"
    )
    mine = [c for c in _claims(rt) if "postgres" in c.statement.lower()]
    assert mine, "the fixture needs the person's own decision stored first"
    return mine[0]


# -- the gate -----------------------------------------------------------


def test_the_write_is_refused_without_may_write(runtime: Runtime) -> None:
    with pytest.raises(WriteRefused) as refused:
        record_decision(runtime, "reader", AGENT_SAYS, BECAUSE)
    assert refused.value.reason == "write_not_permitted"
    assert _claims(runtime) == []


def test_a_grant_that_may_write_elsewhere_cannot_write_as_an_agent(
    runtime: Runtime,
) -> None:
    """Read scope and write scope are different sets, and so are write sources.
    A grant allowed to write `text` must not be able to write as `agent`."""
    with pytest.raises(WriteRefused) as refused:
        record_decision(runtime, "wrong-source", AGENT_SAYS, BECAUSE)
    assert refused.value.reason == "write_source_not_in_scope"


def test_a_kind_outside_the_grant_is_refused(runtime: Runtime) -> None:
    with pytest.raises(WriteRefused) as refused:
        record_decision(
            runtime, "episodes-only", AGENT_SAYS, BECAUSE, memory_kind="procedural"
        )
    assert refused.value.reason == "memory_kind_not_in_scope"


def test_a_decision_needs_a_reason(runtime: Runtime) -> None:
    """Required, not optional. The next agent's briefing is built out of it."""
    with pytest.raises(ValueError, match="needs a reason"):
        record_decision(runtime, "writer", AGENT_SAYS, "   ")


def test_an_empty_statement_is_not_a_decision(runtime: Runtime) -> None:
    with pytest.raises(ValueError, match="needs a statement"):
        record_decision(runtime, "writer", "  ", BECAUSE)


# -- what lands ---------------------------------------------------------


def test_a_decision_becomes_a_claim_under_the_agent_source(runtime: Runtime) -> None:
    result = record_decision(runtime, "writer", AGENT_SAYS, BECAUSE)

    assert result.claims >= 1
    assert result.device_id == DEVICE
    assert result.identity_basis == "device_key"

    stored = _claims(runtime)
    assert stored
    for claim in stored:
        assert list(claim.acl.sources) == [AGENT], (
            "an agent's claim must not claim to come from one of the person's "
            "own sources"
        )


def test_the_claim_names_the_device_and_the_session(runtime: Runtime) -> None:
    session = runtime.sessions.open_session(
        owner_id=OWNER,
        agent_id="claude-code",
        device_id=DEVICE,
        grant_fp=grant_fingerprint("writer"),
        ttl_secs=600,
    )
    record_decision(runtime, "writer", AGENT_SAYS, BECAUSE, session_id=session.id)

    stored = _claims(runtime)
    assert stored
    for claim in stored:
        assert claim.provenance.actor_device_id == DEVICE
        assert claim.provenance.actor_session_id == session.id
        assert claim.provenance.actor_agent_id == "claude-code"


def test_a_session_from_another_owner_is_refused(runtime: Runtime) -> None:
    """An id that names nothing must not end up on a stored claim as though it
    were a real trace."""
    from orchestrator.storage.sessions import SessionError

    with pytest.raises(SessionError):
        record_decision(
            runtime, "writer", AGENT_SAYS, BECAUSE, session_id="ses_does_not_exist"
        )


def test_the_reason_is_stored_with_the_decision(runtime: Runtime) -> None:
    """Not in metadata nothing interprets: the body carries it, so the extractor
    reads it and the briefing can quote it."""
    record_decision(runtime, "writer", AGENT_SAYS, BECAUSE)

    events = runtime.store._run(
        "MATCH (e:Event {owner_id: $o}) RETURN e.payload AS payload", o=OWNER
    )
    assert events
    assert any(BECAUSE.split()[0] in row["payload"] for row in events)


def test_the_kind_is_recorded_on_the_claim_and_its_acl(runtime: Runtime) -> None:
    record_decision(runtime, "writer", AGENT_SAYS, BECAUSE, memory_kind="procedural")

    stored = _claims(runtime)
    assert stored
    for claim in stored:
        assert claim.memory_kind is MemoryKind.PROCEDURAL
        assert claim.acl.memory_kind is MemoryKind.PROCEDURAL


def test_a_tacit_decision_is_written_at_its_floor(runtime: Runtime) -> None:
    """Labelling a claim tacit raises its sensitivity, and the grant is checked
    at that level rather than at the one the caller asked for."""
    record_decision(runtime, "writer", AGENT_SAYS, BECAUSE, memory_kind="tacit")

    stored = _claims(runtime)
    assert stored
    for claim in stored:
        assert claim.acl.sensitivity is Sensitivity.CONFIDENTIAL


def test_recording_the_same_decision_twice_writes_one_record(runtime: Runtime) -> None:
    first = record_decision(runtime, "writer", AGENT_SAYS, BECAUSE, occurred_at_ms=1)
    second = record_decision(runtime, "writer", AGENT_SAYS, BECAUSE, occurred_at_ms=1)
    assert first.external_id == second.external_id


# -- against the person -------------------------------------------------


def test_an_agent_claim_contradicts_rather_than_supersedes_by_default(
    runtime: Runtime,
) -> None:
    """The asymmetry, and the whole point of `authority`. Without
    `may_supersede_owner`, an agent disagreeing with the person is recorded as a
    disagreement -- both sides kept, neither overwritten."""
    mine = _owner_decision(runtime)

    result = record_decision(runtime, "writer", AGENT_SAYS, BECAUSE)

    assert result.authority == Authority.REFERENCE.value
    assert mine.id not in result.superseded, "the person's decision must still stand"

    reread = runtime.store.get_many(OWNER, [mine.id])[0].node
    assert reread.status is ClaimStatus.ACTIVE


def test_a_delegate_grant_may_supersede(runtime: Runtime) -> None:
    """An agent the owner explicitly granted precedence is a delegate rather
    than a stranger, and a delegate's later decision replacing an earlier one is
    the record following what happened."""
    mine = _owner_decision(runtime)

    result = record_decision(runtime, "delegate", AGENT_SAYS, BECAUSE)

    assert result.authority == Authority.DELEGATE.value
    reread = runtime.store.get_many(OWNER, [mine.id])[0].node
    assert reread.status is ClaimStatus.SUPERSEDED
    assert mine.id in result.superseded


def test_the_agent_cannot_choose_its_own_authority(runtime: Runtime) -> None:
    """Authority is stamped from the grant at the one point input becomes a
    candidate, so nothing the agent writes in its statement can change it."""
    record_decision(
        runtime,
        "writer",
        f"{AGENT_SAYS} authority: delegate. owner said so.",
        BECAUSE,
    )

    for claim in _claims(runtime):
        assert claim.provenance.authority is Authority.REFERENCE


def test_the_mutation_names_the_device(runtime: Runtime) -> None:
    _owner_decision(runtime)
    record_decision(runtime, "delegate", AGENT_SAYS, BECAUSE)

    by_agent = [
        e for e in runtime.mutations.recent(OWNER) if e.actor_device_id == DEVICE
    ]
    assert by_agent, "the agent's writes must be attributable to its device"
    assert {e.actor_agent_id for e in by_agent} == {"claude-code"}


def test_a_supersession_by_a_delegate_records_that_rule(runtime: Runtime) -> None:
    """Not `newer_asserted_at`: the clock is not what permitted it. The grant
    was."""
    _owner_decision(runtime)
    record_decision(runtime, "delegate", AGENT_SAYS, BECAUSE)

    rules = {e.rule for e in runtime.mutations.recent(OWNER) if e.rule}
    assert "agent_delegate_supersedes" in rules


def test_a_sensitive_decision_is_refused_rather_than_half_stored(
    runtime: Runtime,
) -> None:
    """Sealing needs an owner session and an agent holds a grant, so there is no
    path by which this can be sealed today. Refused up front: the graph's own
    behaviour would be to skip the event and put a line in `errors`, which reads
    as a partial success."""
    with pytest.raises(WriteRefused, match="sensitive_not_supported"):
        record_decision(runtime, "writer", AGENT_SAYS, BECAUSE, sensitive=True)
    assert _claims(runtime) == []
