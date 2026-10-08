"""Memory kinds: a closed vocabulary, an indexed column, and one exception.

Long-term memory is a hierarchy rather than one pile -- episodic, procedural,
tacit -- because the three answer different questions and an agent can
reasonably be granted one and not another. "You may read how I do things, not
what I did" is a sentence a person would say, and `Scope` can only express it if
the kinds are named.

Two properties need holding, and the second is the awkward one:

- the kind is **queryable without loading the payload**, like the commitment
  fields, because the briefing asks "what procedure do we use for X" on every
  call;
- an **unkinded** claim stays readable. That is the one deliberate exception to
  deny-by-default in `permits`, and an undocumented exception to the invariant
  the README puts first is how that invariant stops being true.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.enums import (
    Authority,
    ClaimStatus,
    EntityKind,
    MemoryKind,
    Sensitivity,
)
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import ObjectAcl, Scope, evaluate, permits
from orchestrator.schema import Claim, Provenance
from orchestrator.storage.migrations import apply_migrations

OWNER = "owner-kinds"
NOW = 1_700_000_000_000


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    rt.store.wipe_owner(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def _claim(
    suffix: str,
    *,
    kind: MemoryKind | None,
    statement: str = "a stored claim",
    status: ClaimStatus = ClaimStatus.ACTIVE,
    occurred_at_ms: int = NOW,
) -> Claim:
    return Claim(
        id=f"clm_kind_{suffix}",
        owner_id=OWNER,
        statement=statement,
        subject_entity_ids=[],
        status=status,
        supersedes=[],
        contradicts=[],
        reconciled_into=None,
        commitment=None,
        asserted_at_ms=occurred_at_ms,
        memory_kind=kind,
        provenance=Provenance(
            citations=[],
            derived_by="test",
            confidence=1.0,
            created_at_ms=occurred_at_ms,
            authority=Authority.OWNER,
        ),
        acl=ObjectAcl(
            owner_id=OWNER,
            sources=["mock"],
            sensitivity=Sensitivity.PERSONAL,
            entity_kinds=[EntityKind.PROJECT],
            occurred_at_ms=occurred_at_ms,
            memory_kind=kind,
        ),
    )


def _scope(**overrides) -> Scope:
    base = dict(
        agent_id="agent-kinds",
        owner_id=OWNER,
        sources=["mock"],
        entity_kinds=[EntityKind.PROJECT],
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    return Scope(**{**base, **overrides})


# -- the column ---------------------------------------------------------


def test_kind_is_an_indexed_query_not_a_scan(runtime: Runtime, settings: Settings) -> None:
    rows = runtime.store._run("SHOW INDEXES YIELD name, properties")
    indexed = {tuple(r["properties"]) for r in rows if r["properties"]}
    assert ("memory_kind",) in indexed

    # Migrations run on every boot, so re-applying must not duplicate them.
    before = len(rows)
    apply_migrations(runtime.store.driver, settings.neo4j_database, settings.embedding_dim)
    assert len(runtime.store._run("SHOW INDEXES YIELD name, properties")) == before


def test_the_kind_is_promoted_onto_the_node(runtime: Runtime, vector) -> None:
    runtime.store.upsert(_claim("promoted", kind=MemoryKind.PROCEDURAL), vector(0.4))

    row = runtime.store._run(
        "MATCH (c:Claim {id: $id, owner_id: $owner}) RETURN c.memory_kind AS kind",
        id="clm_kind_promoted",
        owner="OWNER".replace("OWNER", OWNER),
    )[0]
    assert row["kind"] == "procedural"


def test_an_unkinded_claim_promotes_null_rather_than_a_default(
    runtime: Runtime, vector
) -> None:
    """Not `episodic`. A default here would be a value an indexed query serves
    and a grant filter enforces, asserted by nothing."""
    runtime.store.upsert(_claim("unkinded", kind=None), vector(0.5))

    row = runtime.store._run(
        "MATCH (c:Claim {id: $id, owner_id: $owner}) RETURN c.memory_kind AS kind",
        id="clm_kind_unkinded",
        owner=OWNER,
    )[0]
    assert row["kind"] is None


def test_claims_of_kind_returns_only_that_kind(runtime: Runtime, vector) -> None:
    runtime.store.upsert(_claim("ep", kind=MemoryKind.EPISODIC), vector(0.1))
    runtime.store.upsert(_claim("proc", kind=MemoryKind.PROCEDURAL), vector(0.2))
    runtime.store.upsert(_claim("tacit", kind=MemoryKind.TACIT), vector(0.3))
    runtime.store.upsert(_claim("none", kind=None), vector(0.6))

    found = runtime.store.claims_of_kind(OWNER, MemoryKind.PROCEDURAL.value)
    assert [n.id for n in found] == ["clm_kind_proc"]


def test_claims_of_kind_excludes_superseded_by_default(runtime: Runtime, vector) -> None:
    """A procedure that was replaced is still stored, but it is not the one to
    follow -- and returning both leaves the caller to guess."""
    runtime.store.upsert(
        _claim("old", kind=MemoryKind.PROCEDURAL, status=ClaimStatus.SUPERSEDED),
        vector(0.7),
    )
    runtime.store.upsert(_claim("new", kind=MemoryKind.PROCEDURAL), vector(0.8))

    assert [n.id for n in runtime.store.claims_of_kind(OWNER, "procedural")] == [
        "clm_kind_new"
    ]
    both = runtime.store.claims_of_kind(OWNER, "procedural", include_superseded=True)
    assert {n.id for n in both} == {"clm_kind_new", "clm_kind_old"}


def test_claims_of_kind_never_crosses_owners(runtime: Runtime, vector) -> None:
    runtime.store.upsert(_claim("mine", kind=MemoryKind.TACIT), vector(0.9))
    assert runtime.store.claims_of_kind("someone-else", "tacit") == []


# -- the permission rule ------------------------------------------------


def test_an_unkinded_claim_is_not_hidden_by_a_kind_scope() -> None:
    """The exception, stated as a test. Every claim written before this field
    existed has no kind; the strict reading would retroactively hide the entire
    stored graph behind something nothing has set."""
    scope = _scope()
    assert scope.memory_kinds == []
    assert permits(scope, _claim("x", kind=None).acl, NOW + 1)


def test_a_kinded_claim_needs_its_kind_in_scope() -> None:
    acl = _claim("x", kind=MemoryKind.TACIT).acl

    assert not permits(_scope(), acl, NOW + 1)
    assert not permits(_scope(memory_kinds=[MemoryKind.EPISODIC]), acl, NOW + 1)
    assert permits(_scope(memory_kinds=[MemoryKind.TACIT]), acl, NOW + 1)


def test_procedures_can_be_granted_without_episodes() -> None:
    scope = _scope(memory_kinds=[MemoryKind.PROCEDURAL])
    assert permits(scope, _claim("p", kind=MemoryKind.PROCEDURAL).acl, NOW + 1)
    assert not permits(scope, _claim("e", kind=MemoryKind.EPISODIC).acl, NOW + 1)


def test_a_granted_kind_does_not_override_the_other_checks() -> None:
    """The exception is for absence, not a loosening. Everything else still
    applies to a claim whose kind is in scope."""
    acl = _claim("x", kind=MemoryKind.TACIT).acl
    acl.sensitivity = Sensitivity.RESTRICTED
    scope = _scope(memory_kinds=[MemoryKind.TACIT])

    assert evaluate(scope, acl, NOW + 1).reason.value == "too_sensitive"


# -- what asserted it --------------------------------------------------


def test_an_object_stored_before_authority_existed_has_none() -> None:
    """`None` has to survive a round trip: the resolver's precedence rule falls
    back to the source rule exactly when authority is absent, so a default would
    silently relabel every claim already stored."""
    old = Provenance.model_validate(
        {
            "citations": [],
            "derived_by": "mock-extractor@v1",
            "confidence": 1.0,
            "created_at_ms": NOW,
        }
    )
    assert old.authority is None
    assert old.actor_agent_id is None
    assert old.actor_device_id is None
    assert old.actor_session_id is None


def test_the_actor_survives_a_round_trip_through_the_store(
    runtime: Runtime, vector
) -> None:
    claim = _claim("actor", kind=MemoryKind.EPISODIC)
    claim.provenance.authority = Authority.DELEGATE
    claim.provenance.actor_agent_id = "claude-code"
    claim.provenance.actor_device_id = "device-1a2b3c"
    claim.provenance.actor_session_id = "ses_abc"
    runtime.store.upsert(claim, vector(0.11))

    stored = runtime.store.get_many(OWNER, ["clm_kind_actor"])[0].node
    assert stored.provenance.authority is Authority.DELEGATE
    assert stored.provenance.actor_device_id == "device-1a2b3c"
    assert stored.provenance.actor_session_id == "ses_abc"
