"""Every state change, who made it, and which rule decided.

The read log answered "what was this agent shown". Nothing answered the other
half, and the gap was not a missing feature so much as four `if` statements that
decided and forgot: newer `asserted_at_ms` wins, equal timestamps contradict, a
late arrival is born superseded, a weaker source may not supersede. The graph
recorded that B replaced A; nothing recorded why.

So the properties worth holding are mostly about *not losing* things: the prior
value is what was actually in the store, the first writer of an edge keeps the
credit, an unattributed change cannot be written at all, and none of this is
retrievable as memory.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.enums import ClaimStatus, EntityKind, Sensitivity
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import ObjectAcl
from orchestrator.schema import Claim, Provenance
from orchestrator.storage.mutations import (
    KIND_CREATE,
    KIND_STATUS,
    RULE_NEWER_ASSERTED_AT,
    Actor,
    MutationEntry,
)

OWNER = "owner-mutations"
NOW = 1_700_000_000_000


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    _wipe(rt)
    yield rt
    _wipe(rt)
    rt.close()


def _wipe(rt: Runtime) -> None:
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_mutations(OWNER)


def _claim(suffix: str, *, status: ClaimStatus = ClaimStatus.ACTIVE) -> Claim:
    return Claim(
        id=f"clm_mut_{suffix}",
        owner_id=OWNER,
        statement=f"a claim about {suffix}",
        subject_entity_ids=[],
        status=status,
        asserted_at_ms=NOW,
        provenance=Provenance(derived_by="test", created_at_ms=NOW),
        acl=ObjectAcl(
            owner_id=OWNER,
            sources=["mock"],
            sensitivity=Sensitivity.PERSONAL,
            entity_kinds=[EntityKind.PROJECT],
            occurred_at_ms=NOW,
        ),
    )


# -- the entry ----------------------------------------------------------


def test_before_is_the_prior_status_read_back_from_the_store(
    runtime: Runtime, vector
) -> None:
    """Not what the caller believed was there. `_mutate_claim` reads the payload
    anyway, so a snapshot of it costs one parse and makes `before` a fact."""
    runtime.store.upsert(_claim("prior"), vector(0.1))
    runtime.store.set_claim_status(
        OWNER,
        "clm_mut_prior",
        ClaimStatus.SUPERSEDED.value,
        actor=Actor.pipeline(),
        reason="a later decision replaced it",
        rule=RULE_NEWER_ASSERTED_AT,
    )

    entry = runtime.mutations.recent(OWNER)[0]
    assert (entry.before, entry.after) == ("active", "superseded")
    assert entry.kind == KIND_STATUS
    assert entry.field_name == "status"
    assert entry.rule == RULE_NEWER_ASSERTED_AT
    assert entry.reason == "a later decision replaced it"


def test_a_change_that_changes_nothing_is_not_recorded(runtime: Runtime, vector) -> None:
    """The resolver legitimately re-asserts a supersession it has already
    applied. Recording it would put a change in the log that did not happen."""
    runtime.store.upsert(_claim("idem", status=ClaimStatus.SUPERSEDED), vector(0.2))
    runtime.store.set_claim_status(
        OWNER,
        "clm_mut_idem",
        ClaimStatus.SUPERSEDED.value,
        actor=Actor.pipeline(),
        reason="already superseded",
        rule=RULE_NEWER_ASSERTED_AT,
    )

    assert runtime.mutations.recent(OWNER) == []


def test_an_unattributed_change_does_not_type_check() -> None:
    """`actor`, `reason` and `rule` are keyword-only with no defaults, so the
    caller cannot forget -- there is nothing to forget, because the call does not
    resolve without them. The same shape as `link` refusing an unscoped write."""
    import inspect

    from orchestrator.storage.neo4j_store import Neo4jStore

    params = inspect.signature(Neo4jStore.set_claim_status).parameters
    for name in ("actor", "reason", "rule"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert params[name].default is inspect.Parameter.empty, (
            f"{name} must have no default, or an unattributed change becomes "
            "writable by omission"
        )


def test_an_unknown_rule_is_refused() -> None:
    """A typo would read as a real reason forever, and a genuinely new branch
    belongs in `RULES` beside the others."""
    with pytest.raises(ValueError, match="unknown rule"):
        MutationEntry(
            owner_id=OWNER, object_id="clm_x", kind=KIND_STATUS, rule="vibes"
        )


def test_the_reason_is_capped(runtime: Runtime) -> None:
    """An uncapped reason field is where a model dumps its chain of thought.
    What is wanted is the consolidated statement of why."""
    entry = MutationEntry(
        owner_id=OWNER, object_id="clm_x", kind=KIND_STATUS, reason="x" * 900
    )
    assert len(entry.reason) < 900
    assert entry.reason.endswith("...")


# -- the actor ----------------------------------------------------------


def test_the_pipelines_own_writes_name_no_device(runtime: Runtime, vector) -> None:
    """A connector pulling a mailbox is the owner's own machinery. A fabricated
    device id would be indistinguishable from an authenticated one in every row
    that stores it."""
    runtime.store.upsert(_claim("pipeline"), vector(0.3))
    runtime.store.set_claim_status(
        OWNER,
        "clm_mut_pipeline",
        ClaimStatus.SUPERSEDED.value,
        actor=Actor.pipeline(),
        reason="superseded during ingestion",
        rule=RULE_NEWER_ASSERTED_AT,
    )

    entry = runtime.mutations.recent(OWNER)[0]
    assert entry.actor_agent_id == "owner"
    assert entry.actor_device_id is None
    assert entry.actor_session_id is None


def test_an_agents_write_names_its_device_and_session(runtime: Runtime, vector) -> None:
    runtime.store.upsert(_claim("agent"), vector(0.4))
    runtime.store.set_claim_status(
        OWNER,
        "clm_mut_agent",
        ClaimStatus.SUPERSEDED.value,
        actor=Actor(
            agent_id="claude-code",
            device_id="device-1a2b3c",
            session_id="ses_abc",
            grant_fp="fp-xyz",
        ),
        reason="the migration ADR says otherwise",
        rule=RULE_NEWER_ASSERTED_AT,
    )

    entry = runtime.mutations.recent(OWNER)[0]
    assert entry.actor_agent_id == "claude-code"
    assert entry.actor_device_id == "device-1a2b3c"
    assert entry.actor_session_id == "ses_abc"
    assert entry.grant_fp == "fp-xyz"


# -- the edge -----------------------------------------------------------


def test_a_re_link_does_not_rewrite_who_did_it_first(runtime: Runtime, vector) -> None:
    """`MERGE` with an unconditional `SET` would let the second writer quietly
    take credit for a decision made once."""
    runtime.store.upsert(_claim("a"), vector(0.5))
    runtime.store.upsert(_claim("b"), vector(0.6))

    runtime.store.link(
        OWNER,
        "clm_mut_a",
        "SUPERSEDES",
        "clm_mut_b",
        actor=Actor(agent_id="first", device_id="device-first"),
        rule=RULE_NEWER_ASSERTED_AT,
    )
    runtime.store.link(
        OWNER,
        "clm_mut_a",
        "SUPERSEDES",
        "clm_mut_b",
        actor=Actor(agent_id="second", device_id="device-second"),
        rule=RULE_NEWER_ASSERTED_AT,
    )

    row = runtime.store._run(
        "MATCH (:Claim {id: 'clm_mut_a'})-[r:SUPERSEDES]->(:Claim {id: 'clm_mut_b'}) "
        "RETURN r.actor_agent_id AS agent, r.actor_device_id AS device, r.rule AS rule"
    )[0]
    assert row["agent"] == "first"
    assert row["device"] == "device-first"


def test_structural_edges_carry_no_actor(runtime: Runtime, vector) -> None:
    """`MENTIONS`, `ABOUT` and `CITES` follow from an object's own content. Only
    a supersession or a contradiction is a decision about the record."""
    runtime.store.upsert(_claim("c"), vector(0.7))
    runtime.store.upsert(_claim("d"), vector(0.8))
    runtime.store.link(
        OWNER,
        "clm_mut_c",
        "CITES",
        "clm_mut_d",
        actor=Actor(agent_id="someone", device_id="device-x"),
        rule=RULE_NEWER_ASSERTED_AT,
    )

    row = runtime.store._run(
        "MATCH (:Claim {id: 'clm_mut_c'})-[r:CITES]->(:Claim {id: 'clm_mut_d'}) "
        "RETURN properties(r) AS props"
    )[0]
    assert row["props"] == {}


# -- the resolver's reasons --------------------------------------------


def test_a_supersession_records_which_rule_fired(runtime: Runtime) -> None:
    """End to end through the real ingestion graph.

    The mock corpus's supersessions are entirely **within one batch**, which is
    the case the create entry exists for: the resolver marks the earlier claim
    superseded before anything is written, so the claim is stored already
    superseded and there is no status *transition* for `set_claim_status` to
    notice. If creation were not recorded, the rule would be lost exactly here --
    for every supersession a single ingest discovers, which is most of them.
    """
    run_ingestion(runtime=runtime, owner_id=OWNER, source="mock", thread_id="mut-ingest")

    entries = runtime.mutations.recent(OWNER)
    assert entries, "the mock corpus asserts claims"

    born_superseded = [e for e in entries if e.after == "superseded"]
    assert born_superseded, "the mock corpus supersedes at least one decision"
    for entry in born_superseded:
        assert entry.kind == KIND_CREATE
        assert entry.rule == RULE_NEWER_ASSERTED_AT
        assert entry.reason, "a recorded change with no reason is half a record"
        assert entry.before is None, "it was never active in the store"
        assert entry.actor_agent_id == "owner"

    # An ordinary claim is recorded too, and carries no rule: no branch decided
    # it, it was simply extracted.
    plain = [e for e in entries if e.after == "active"]
    assert plain
    assert all(e.rule is None for e in plain)


def test_a_stored_claim_superseded_later_records_the_transition(
    runtime: Runtime, vector
) -> None:
    """The other half: when the earlier claim is already in the store, the
    change is a transition and `before` is what was actually there."""
    runtime.store.upsert(_claim("stored"), vector(0.9))
    runtime.store.set_claim_status(
        OWNER,
        "clm_mut_stored",
        ClaimStatus.SUPERSEDED.value,
        actor=Actor.pipeline(),
        reason="a later assertion about the same subject replaced it",
        rule=RULE_NEWER_ASSERTED_AT,
    )

    entry = runtime.mutations.recent(OWNER)[0]
    assert entry.kind == KIND_STATUS
    assert (entry.before, entry.after) == ("active", "superseded")


def test_mutations_can_be_read_per_object(runtime: Runtime) -> None:
    """What a briefing is allowed to surface: changes to the objects the asking
    agent has just been permitted to see, rather than the whole log."""
    run_ingestion(runtime=runtime, owner_id=OWNER, source="mock", thread_id="mut-ingest-2")

    everything = runtime.mutations.recent(OWNER)
    assert everything
    one = everything[0].object_id

    scoped = runtime.mutations.for_objects(OWNER, [one])
    assert scoped
    assert {e.object_id for e in scoped} == {one}
    assert runtime.mutations.for_objects(OWNER, []) == []


def test_the_log_never_crosses_owners(runtime: Runtime) -> None:
    run_ingestion(runtime=runtime, owner_id=OWNER, source="mock", thread_id="mut-ingest-3")
    assert runtime.mutations.recent("someone-else") == []
    assert runtime.mutations.for_objects("someone-else", ["clm_mut_a"]) == []


def test_re_ingesting_does_not_erase_the_log(runtime: Runtime) -> None:
    """Same rule as the read log: re-deriving a claim does not un-happen the
    change that was made to the one it replaced. `wipe_owner` leaves it alone."""
    run_ingestion(runtime=runtime, owner_id=OWNER, source="mock", thread_id="mut-ingest-4")
    before = len(runtime.mutations.recent(OWNER))
    assert before

    runtime.store.wipe_owner(OWNER)
    assert len(runtime.mutations.recent(OWNER)) == before
