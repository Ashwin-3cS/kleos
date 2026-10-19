"""Reasoning across sessions: what it may conclude, and what it may never do.

ADR 0025. This is the first thing in the service that writes a claim **nobody
asserted**, so almost everything here is about restraint and about attribution:

- it may contradict what somebody decided and may never replace it, whatever
  the grant says -- the one constraint the whole feature rests on;
- it is attributed to the harness, with no device and no borrowed label, because
  a derived inference rendered as an agent's decision is worse than no
  inference;
- a caller cannot write *as* the harness;
- it declines below two sessions, because one session's claims were already
  reasoned over when it closed;
- it writes nothing twice, because a conclusion drawn from unchanged memory is
  the same conclusion.

The reasoner itself is unit-tested without a store: the rule-based one is what
mock mode runs, and both of its patterns are facts about the claim set rather
than readings of it.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.connectors.agent import AGENT
from orchestrator.enums import (
    Authority,
    ClaimStatus,
    EntityKind,
    MemoryKind,
    Sensitivity,
)
from orchestrator.extraction.reasoning import (
    CHURN_THRESHOLD,
    MIN_SESSIONS,
    Observation,
    RuleBasedReasoner,
    _parse,
    get_reasoner,
)
from orchestrator.gateway_client import ResolvedGrant
from orchestrator.graphs.decide import WriteRefused, record_decision
from orchestrator.graphs.reason import SubjectNotFound, reason_about
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope
from orchestrator.schema import Claim
from orchestrator.storage.mutations import HARNESS_AGENT_ID
from orchestrator.storage.reads import grant_fingerprint

OWNER = "owner-reason"
SUBJECT = "Lantern"

#: Two devices, because "two agents disagree" is a fact about devices and a test
#: with one device could not tell the difference.
DEVICE_1 = "device-aaaa1111"
DEVICE_2 = "device-bbbb2222"


# -- the reasoner, without a store --------------------------------------


def _obs(n: int, status: str, device: str | None = None, session: str | None = None):
    return Observation(
        claim_id=f"clm_{n}",
        statement=f"statement {n}",
        status=status,
        asserted_at_ms=1_700_000_000_000 + n,
        device_id=device,
        session_id=session,
    )


def test_churn_is_found_at_the_threshold_and_not_below_it() -> None:
    """Two reversals is a decision that changed its mind once, which is
    ordinary. Three is a pattern worth telling the next agent about, and the
    line between them is a number this test pins rather than a judgement."""
    reasoner = RuleBasedReasoner()
    below = [_obs(i, ClaimStatus.SUPERSEDED.value) for i in range(CHURN_THRESHOLD - 1)]
    at = [_obs(i, ClaimStatus.SUPERSEDED.value) for i in range(CHURN_THRESHOLD)]

    assert reasoner.reason(SUBJECT, below) == []
    found = reasoner.reason(SUBJECT, at)
    assert len(found) == 1
    assert str(CHURN_THRESHOLD) in found[0].statement
    assert found[0].kind is MemoryKind.PROCEDURAL


def test_a_disagreement_needs_two_devices_not_two_claims() -> None:
    """One agent contradicting itself across two sessions is one agent being
    unsure, which is not the thing an incoming agent needs warning about. Two
    devices holding incompatible positions is."""
    reasoner = RuleBasedReasoner()
    one_device = [
        _obs(1, ClaimStatus.CONTRADICTED.value, device=DEVICE_1),
        _obs(2, ClaimStatus.CONTRADICTED.value, device=DEVICE_1),
    ]
    two_devices = [
        _obs(1, ClaimStatus.CONTRADICTED.value, device=DEVICE_1),
        _obs(2, ClaimStatus.CONTRADICTED.value, device=DEVICE_2),
    ]

    assert reasoner.reason(SUBJECT, one_device) == []
    found = reasoner.reason(SUBJECT, two_devices)
    assert len(found) == 1
    assert "incompatible" in found[0].statement


def test_an_ordinary_subject_concludes_nothing() -> None:
    """The common outcome. Several sessions about one subject usually add up to
    exactly what each of them already said, and an empty list is the correct
    answer rather than a failure to reason."""
    active = [_obs(i, ClaimStatus.ACTIVE.value, device=DEVICE_1) for i in range(5)]
    assert RuleBasedReasoner().reason(SUBJECT, active) == []


def test_a_conclusion_names_the_claims_it_came_from() -> None:
    """A derived claim whose inputs cannot be named is one nobody can check,
    and this is the only kind of claim in the record that nobody asserted."""
    at = [_obs(i, ClaimStatus.SUPERSEDED.value) for i in range(CHURN_THRESHOLD)]
    found = RuleBasedReasoner().reason(SUBJECT, at)
    assert set(found[0].basis) == {o.claim_id for o in at}


def test_the_mock_reasoner_emits_no_tacit_claims() -> None:
    """Same bar as the mock consolidator. A tacit claim is an inference about
    how somebody thinks; one produced by counting rows would be unfalsifiable,
    maximally sensitive, and attributed to a real person by arithmetic."""
    mixed = [_obs(i, ClaimStatus.SUPERSEDED.value, device=DEVICE_1) for i in range(4)]
    mixed += [
        _obs(9, ClaimStatus.CONTRADICTED.value, device=DEVICE_1),
        _obs(10, ClaimStatus.CONTRADICTED.value, device=DEVICE_2),
    ]
    found = RuleBasedReasoner().reason(SUBJECT, mixed)
    assert found, "the fixture should trigger both patterns"
    assert all(c.kind is not MemoryKind.TACIT for c in found)


def test_mock_mode_gets_the_rule_based_reasoner(settings: Settings) -> None:
    """Follows `EXTRACTOR`, like the consolidator, so a deployment cannot end up
    reasoning with a model while extracting with regexes."""
    assert isinstance(get_reasoner(settings), RuleBasedReasoner)


# -- what the LLM reasoner's output is allowed to be --------------------


def test_a_restatement_of_an_input_is_dropped() -> None:
    """The prompt forbids it; a model does it anyway. A restatement written as a
    *derived* claim says what an agent already said, and the resolver would then
    compare the two and mark a duplicate or a contradiction -- noise, attributed
    to the harness."""
    inputs = [Observation(claim_id="c1", statement="Lantern uses Neo4j.",
                          status="active", asserted_at_ms=1)]
    parsed = _parse(
        '{"conclusions": ['
        '{"statement": "lantern uses neo4j", "kind": "episodic", "reason": "r"},'
        '{"statement": "Datastore choices here turn on traversal depth.",'
        ' "kind": "procedural", "reason": "r"}]}',
        inputs,
    )
    assert [c.statement for c in parsed] == [
        "Datastore choices here turn on traversal depth."
    ]


def test_an_unknown_kind_is_dropped_rather_than_defaulted() -> None:
    """`tacit` raises sensitivity and `procedural` does not, so defaulting picks
    a disclosure level on the model's behalf."""
    parsed = _parse(
        '{"conclusions": [{"statement": "A.", "kind": "vibes", "reason": "r"}]}', []
    )
    assert parsed == []


def test_a_conclusion_with_no_reason_is_dropped() -> None:
    """Same bar `record_decision` sets for an agent: the briefing is built out
    of the reason, and a derived claim with no stated basis is the least
    justifiable thing that could be in the record."""
    parsed = _parse('{"conclusions": [{"statement": "A.", "kind": "episodic"}]}', [])
    assert parsed == []


def test_unparseable_output_loses_nothing_else() -> None:
    assert _parse("not json at all", []) == []


# -- the pass, against a real store -------------------------------------


class _Gateway:
    def __init__(self, scopes: dict[str, Scope], device: str = DEVICE_1) -> None:
        self._scopes = scopes
        self.device = device

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scopes[grant_token]

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        return ResolvedGrant(
            scope=self.introspect_scope(grant_token),
            device_id=self.device,
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
    # The grant that makes the authority cap testable: with this, an agent's own
    # decision would be a `delegate` write.
    "delegate": _scope(may_supersede_owner=True),
    "reader": _scope(may_write=False, write_sources=[], memory_kinds=[]),
    # A caller trying to write under the harness's own label.
    "impostor": _scope(agent_id=HARNESS_AGENT_ID),
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
    return [rt.content.unseal_node(Claim.model_validate_json(r["payload"])) for r in rows]


def _derived(rt: Runtime) -> list[Claim]:
    return [
        c for c in _claims(rt)
        if c.provenance.actor_agent_id == HARNESS_AGENT_ID
    ]


def _open_session(rt: Runtime, token: str, device: str) -> str:
    return rt.sessions.open_session(
        owner_id=OWNER,
        agent_id="claude-code",
        device_id=device,
        grant_fp=grant_fingerprint(token),
        ttl_secs=3_600,
    ).id


def _history(rt: Runtime, token: str = "writer") -> None:
    """A subject with a history: three decisions on it, from two devices in two
    sessions, each superseding the last.

    Written through `record_decision` rather than crafted, so the statuses are
    the ones the resolver actually assigns -- a fixture that set `superseded` by
    hand would be testing the reasoner against a graph the resolver would never
    produce.
    """
    gateway: _Gateway = rt.gateway  # type: ignore[assignment]
    plan = [
        (DEVICE_1, "will use Postgres", "it is already in the stack", 0),
        (DEVICE_2, "will use Neo4j", "graph proximity is a hard requirement", 100),
        (DEVICE_1, "will use DynamoDB", "the team knows it best", 200),
        (DEVICE_2, "will use Neo4j after all", "traversal depth settled it", 300),
        ]
    sessions: dict[str, str] = {}
    for device, verb, reason, offset in plan:
        gateway.device = device
        if device not in sessions:
            sessions[device] = _open_session(rt, token, device)
        record_decision(
            rt,
            token,
            f"project {SUBJECT} {verb}.",
            reason,
            session_id=sessions[device],
            occurred_at_ms=1_700_000_000_000 + offset * 1_000,
        )
    gateway.device = DEVICE_1


def test_a_derived_conclusion_is_never_a_delegate_write(runtime: Runtime) -> None:
    """**The constraint the whole feature rests on.**

    The grant says `may_supersede_owner`, so an agent's own decision under it
    would be a `delegate` write and could replace one of the owner's. A
    conclusion the harness drew must not be, whatever the grant says: an
    inference nobody asserted replacing a decision somebody made is the exact
    inversion of what this service is for.
    """
    _history(runtime, "delegate")
    result = reason_about(runtime, "delegate", SUBJECT)

    assert result.ran and result.written, result.as_dict()
    derived = _derived(runtime)
    assert derived, "the pass wrote nothing to check"
    for claim in derived:
        assert claim.provenance.authority is Authority.REFERENCE


def test_a_derived_conclusion_names_the_harness_and_no_device(
    runtime: Runtime,
) -> None:
    """No device, because there is no device -- and a fabricated one would be
    indistinguishable from an authenticated one in every row that stores it. No
    borrowed agent label either: nothing chose a name for a writer that had
    none."""
    _history(runtime)
    reason_about(runtime, "writer", SUBJECT)

    derived = _derived(runtime)
    assert derived
    for claim in derived:
        assert claim.provenance.actor_device_id is None
        assert claim.provenance.actor_session_id in (None, "")
        assert claim.provenance.actor_agent_id == HARNESS_AGENT_ID


def test_the_identity_basis_is_derived_rather_than_label(runtime: Runtime) -> None:
    """`label` would say somebody typed a name for this writer into a scope.
    Nobody did, and the three-valued basis is what keeps an agent able to tell a
    derived inference from a decision."""
    _history(runtime)
    from orchestrator.graphs.brief import HARNESS_ACTOR, _attributions

    reason_about(runtime, "writer", SUBJECT)
    ids = [c.id for c in _derived(runtime)]
    assert ids
    bases = {
        a.identity_basis
        for a in _attributions(runtime, OWNER, ids)
        if a.actor_agent_id == HARNESS_ACTOR
    }
    assert bases == {"derived"}


def test_running_twice_over_unchanged_memory_writes_nothing_new(
    runtime: Runtime,
) -> None:
    """The record id is content-addressed over the statement, the reason and the
    timestamp, and the timestamp comes from the newest claim read rather than
    from the clock. Without that a pass would write a fresh copy of the same
    conclusion every time it ran.

    The second pass reaches the same conclusions and writes none of them, which
    is how "already recorded" is distinguishable from "concluded nothing":
    conclusions present, `written` empty, no errors. That `written` is empty
    rather than naming the existing claim is pre-existing `record_decision`
    behaviour on a retry -- the resolver skips the duplicate id before anything
    is written, so `_kinded` has nothing to report, which its own comment says
    should not happen. Asserted here as it actually is.
    """
    _history(runtime)
    first = reason_about(runtime, "writer", SUBJECT)
    before = {c.id for c in _claims(runtime)}
    assert first.written

    second = reason_about(runtime, "writer", SUBJECT)

    assert second.ran and second.conclusions == first.conclusions
    assert second.written == []
    assert second.errors == []
    assert {c.id for c in _claims(runtime)} == before


def test_it_declines_below_two_sessions(runtime: Runtime) -> None:
    """One session's claims were already reasoned over when it closed, so a
    pass over them would spend a model call restating that session's own
    conclusions -- and a restatement written as derived is worse than nothing.

    Declined is reported distinctly from ran-and-found-nothing, because the two
    are different facts and both have an empty `written`.
    """
    gateway: _Gateway = runtime.gateway  # type: ignore[assignment]
    session = _open_session(runtime, "writer", DEVICE_1)
    gateway.device = DEVICE_1
    for n, text in enumerate(["Postgres", "Neo4j", "DynamoDB"]):
        record_decision(
            runtime,
            "writer",
            f"project {SUBJECT} will use {text}.",
            "a reason",
            session_id=session,
            occurred_at_ms=1_700_000_000_000 + n * 1_000,
        )

    result = reason_about(runtime, "writer", SUBJECT)

    assert result.ran is False
    assert result.declined and "too_few_sessions" in result.declined
    assert result.sessions < MIN_SESSIONS
    assert result.written == []
    assert _derived(runtime) == []


def test_an_unknown_subject_is_a_lookup_failure_not_an_empty_pass(
    runtime: Runtime,
) -> None:
    """This reasons over what was written; it does not go looking. A subject
    memory has never heard of coming back as "concluded nothing" would read as
    a considered answer about a project that does not exist."""
    with pytest.raises(SubjectNotFound):
        reason_about(runtime, "writer", "a project nobody ever mentioned")


def test_the_pass_needs_may_write(runtime: Runtime) -> None:
    """Gated by the same `may_write` an agent's own write is. A pass the owner
    did not ask for is not more entitled than an agent they did."""
    _history(runtime)
    result = reason_about(runtime, "reader", SUBJECT)

    # Refused per conclusion by `record_decision`, so the pass reports the
    # refusals rather than raising: it ran, and nothing was written.
    assert result.ran
    assert result.written == []
    assert result.errors and "write_not_permitted" in result.errors[0]
    assert _derived(runtime) == []


def test_a_caller_cannot_write_as_the_harness(runtime: Runtime) -> None:
    """`harness` is how a derived conclusion is attributed. A grant signed with
    that `agent_id` would have every claim the caller wrote rendered as
    something the harness concluded rather than something an agent asserted --
    refused by name, because silently relabelling would hide that somebody
    tried."""
    with pytest.raises(WriteRefused) as refused:
        record_decision(runtime, "impostor", "A claim.", "a reason")
    assert refused.value.reason.startswith("reserved_agent_id")
    assert _claims(runtime) == []


def test_the_subject_is_matched_by_name_not_by_id(runtime: Runtime) -> None:
    """A caller asking about "Lantern" has a project in mind, not a content
    address. Matched the way canonicalisation matches entities, so the longer
    form reaches the same subject."""
    _history(runtime)
    result = reason_about(runtime, "writer", f"project {SUBJECT}")
    assert result.subject_entity_ids
    assert result.considered > 0


def test_a_briefing_says_nobody_asserted_a_derived_claim() -> None:
    """The line an agent actually reads.

    An agent that cannot tell a derived inference from a decision somebody made
    will treat them alike -- and these are the ones it should push back on. The
    harness has no device, like the owner's own ingestion, but it is the *least*
    authoritative writer here rather than the most, so the two cannot render the
    same way.
    """
    from orchestrator.graphs.brief import HARNESS_ACTOR, Attribution, _advisory_line
    from orchestrator.schema import Claim, Provenance

    claim = Claim(
        id="clm_derived",
        owner_id=OWNER,
        statement=f"Decisions about {SUBJECT} have been reversed 3 times.",
        status=ClaimStatus.ACTIVE,
        asserted_at_ms=1,
        provenance=Provenance(derived_by="x", created_at_ms=1),
        acl=_acl(),
    )
    who = Attribution(
        object_id=claim.id,
        actor_agent_id=HARNESS_ACTOR,
        actor_device_id=None,
        actor_session_id=None,
        identity_basis="derived",
        kind="create",
        before=None,
        after="active",
        reason="the subject has a history of reversal",
        rule=None,
        at_ms=1,
    )

    line = _advisory_line(claim, who)
    assert "harness" in line and "derived" in line
    assert "nobody asserted it" in line
    # Not the owner's ingestion, and not an unauthenticated agent label either.
    assert "the owner's own ingestion" not in line
    assert "label only" not in line


def _acl():
    from orchestrator.permissions import ObjectAcl

    return ObjectAcl(
        owner_id=OWNER,
        sources=[AGENT],
        sensitivity=Sensitivity.PERSONAL,
        entity_kinds=[EntityKind.PROJECT],
        occurred_at_ms=1,
    )


def test_a_live_deployment_keeps_the_structural_patterns() -> None:
    """The regression this composition exists for.

    Choosing the model *instead of* the rules made live mode strictly worse
    than mock at the two patterns that are arithmetic rather than judgement.
    Found by running the live path against a subject whose history had three
    reversals in it and getting nothing back.
    """
    from orchestrator.extraction.reasoning import CompositeReasoner

    composite = CompositeReasoner.__new__(CompositeReasoner)
    composite._rules = RuleBasedReasoner()

    class _Silent:
        """A model that adds nothing, which is the common case and the one that
        must not also subtract."""

        name = "silent"

        def reason(self, subject, observations, *, also_known=None):
            self.also_known = list(also_known or [])
            return []

        def close(self) -> None:
            pass

    composite._llm = _Silent()
    at = [_obs(i, ClaimStatus.SUPERSEDED.value) for i in range(CHURN_THRESHOLD)]

    found = composite.reason(SUBJECT, at)

    assert len(found) == 1, "the structural pattern was lost"
    # And the model was told what is already covered, so the interesting case is
    # what it says *given* that -- not a duplicate it produces and we discard.
    assert composite._llm.also_known == [found[0].statement]


def test_one_conclusion_becomes_exactly_one_claim(runtime: Runtime) -> None:
    """Found on the live path, and it was self-contradicting.

    A derived conclusion's record body is a statement a model produced, so
    extraction run over it returns a reworded copy of the same thing -- asserted
    at the same instant, which the resolver marks `equal_asserted_at_contradicts`
    against the real one. The result was one conclusion landing as two claims in
    unresolved conflict, both attributed to the harness.
    """
    _history(runtime)
    result = reason_about(runtime, "writer", SUBJECT)

    assert len(result.conclusions) == 1, result.as_dict()
    derived = _derived(runtime)
    assert len(derived) == 1, [c.statement for c in derived]
    assert derived[0].status is ClaimStatus.ACTIVE
    # The statement is the conclusion's own words, not a rewording of them.
    assert derived[0].statement == result.conclusions[0]["statement"]
