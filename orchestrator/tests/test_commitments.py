"""The commitment facet, end to end over the mock fixtures.

The fixture scenario (``connectors/mock.py``, records 005-007):

* mock-005 -- Alice commits to Bob that Atlas ships the storage migration by
  2025-02-14.
* mock-006 -- three days later the same obligation is reassigned: Bob commits
  to Alice, deadline moved to 2025-03-07. The resolver supersedes mock-005's
  claim, which stays stored and linked.
* mock-007 -- Carol commits that Beacon publishes the rollout plan by
  2025-01-24, and nothing ever fulfils it.

As of ``AS_OF`` (2025-02-01) that makes exactly one commitment past due.
"""

from __future__ import annotations

import pytest

from orchestrator.connectors.mock import BASE_MS, DAY_MS
from orchestrator.enums import ClaimStatus, EntityKind, FulfillmentStatus, Sensitivity
from orchestrator.extraction.mock import MockExtractor
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope, evaluate
from orchestrator.resolution.resolver import Resolver
from orchestrator.schema import Claim, RawRecord
from orchestrator.storage.migrations import apply_migrations

OWNER = "owner-commitments"
AS_OF = BASE_MS + 31 * DAY_MS  # 2025-02-01

MIGRATION_EARLY = "project Atlas will ship the storage migration by 2025-02-14."
MIGRATION_LATE = "project Atlas will ship the storage migration by 2025-03-07."
ROLLOUT = "project Beacon will publish the rollout plan by 2025-01-24."


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(settings)
    rt.store.wipe_owner(OWNER)
    run_ingestion(rt, owner_id=OWNER, source="mock")
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def _claims(store) -> dict[str, Claim]:
    rows = store._run(
        "MATCH (c:Claim {owner_id: $owner_id}) RETURN c.payload AS payload", owner_id=OWNER
    )
    claims = [Claim.model_validate_json(r["payload"]) for r in rows]
    return {c.statement: c for c in claims}


def test_commitments_are_extracted_as_a_facet_not_a_node_type(runtime):
    by_statement = _claims(runtime.store)
    assert set(runtime.store.count(OWNER)) <= {"Entity", "Event", "Claim"}

    early = by_statement[MIGRATION_EARLY]
    assert early.commitment is not None
    assert early.commitment.owed_to_entity_id is not None
    rollout = by_statement[ROLLOUT]
    # Plenty of commitments are to no one in particular.
    assert rollout.commitment.owed_to_entity_id is None
    # And a plain decision is still a plain claim.
    assert by_statement["project Beacon will ship behind a feature flag."].commitment is None


def test_reassignment_supersedes_through_the_existing_machinery(runtime):
    by_statement = _claims(runtime.store)
    early, late = by_statement[MIGRATION_EARLY], by_statement[MIGRATION_LATE]

    assert early.id in late.supersedes
    assert early.status is ClaimStatus.SUPERSEDED
    assert late.status is ClaimStatus.ACTIVE
    # Superseded, kept, and linked -- not overwritten.
    linked = runtime.store._run(
        "MATCH (a:Claim {id: $late})-[:SUPERSEDES]->(b:Claim {id: $early}) RETURN b.id AS id",
        late=late.id,
        early=early.id,
    )
    assert [r["id"] for r in linked] == [early.id]
    # The obligation moved from Alice to Bob.
    assert early.commitment.owed_by_entity_id == late.commitment.owed_to_entity_id
    assert late.commitment.owed_by_entity_id == early.commitment.owed_to_entity_id


def test_commitment_parties_are_linked_as_typed_edges(runtime):
    late = _claims(runtime.store)[MIGRATION_LATE]
    rows = runtime.store._run(
        "MATCH (c:Claim {id: $id})-[r:OWED_BY|OWED_TO]->(e:Entity) "
        "RETURN type(r) AS rel, e.id AS id",
        id=late.id,
    )
    edges = {r["rel"]: r["id"] for r in rows}
    assert edges["OWED_BY"] == late.commitment.owed_by_entity_id
    assert edges["OWED_TO"] == late.commitment.owed_to_entity_id


def test_open_and_past_due_read(runtime):
    by_statement = _claims(runtime.store)

    open_now = runtime.store.open_commitments(OWNER)
    assert [s.node.statement for s in open_now] == [ROLLOUT, MIGRATION_LATE]

    past_due = runtime.store.open_commitments(OWNER, due_before_ms=AS_OF)
    assert [s.node.statement for s in past_due] == [ROLLOUT]

    owed_by_bob = runtime.store.open_commitments(
        OWNER, owed_by_entity_id=by_statement[MIGRATION_LATE].commitment.owed_by_entity_id
    )
    assert [s.node.statement for s in owed_by_bob] == [MIGRATION_LATE]

    # The reassigned-away commitment is excluded by default and available on
    # request; either way it was not deleted.
    with_superseded = runtime.store.open_commitments(OWNER, include_superseded=True)
    assert MIGRATION_EARLY in [s.node.statement for s in with_superseded]


def test_the_read_is_answered_by_cypher_against_indexed_properties(runtime, settings):
    rows = runtime.store._run("SHOW INDEXES YIELD name, properties")
    # Token-lookup indexes have no properties at all.
    indexed = {tuple(r["properties"]): r["name"] for r in rows if r["properties"]}
    assert ("commitment_fulfillment", "commitment_due_at_ms") in indexed
    assert ("commitment_owed_by",) in indexed

    # Migrations run on every boot, so re-applying must not duplicate them.
    before = len(rows)
    apply_migrations(runtime.store.driver, settings.neo4j_database, settings.embedding_dim)
    after = runtime.store._run("SHOW INDEXES YIELD name, properties")
    assert len(after) == before

    promoted = runtime.store._run(
        "MATCH (c:Claim {id: $id}) RETURN c.commitment_fulfillment AS f, "
        "c.commitment_due_at_ms AS due, c.claim_status AS status",
        id=_claims(runtime.store)[ROLLOUT].id,
    )[0]
    assert promoted == {"f": "open", "due": 1737676800000, "status": "active"}


def test_fulfillment_and_epistemic_status_move_independently(runtime):
    by_statement = _claims(runtime.store)
    early, late = by_statement[MIGRATION_EARLY], by_statement[MIGRATION_LATE]

    # Superseded, and still open: the obligation did not stop existing when
    # our understanding of who owed it changed.
    assert early.status is ClaimStatus.SUPERSEDED
    assert early.commitment.fulfillment is FulfillmentStatus.OPEN

    # Active, and fulfilled: the promise was kept and the claim is still our
    # best understanding of it.
    updated = runtime.store.set_fulfillment(late.id, "fulfilled", settled_at_ms=AS_OF)
    assert updated.status is ClaimStatus.ACTIVE
    assert updated.commitment.fulfillment is FulfillmentStatus.FULFILLED
    assert updated.commitment.settled_at_ms == AS_OF
    assert [s.node.statement for s in runtime.store.open_commitments(OWNER)] == [ROLLOUT]

    # And moving the epistemic axis leaves fulfillment where it was.
    runtime.store.set_claim_status(late.id, ClaimStatus.SUPERSEDED.value)
    reread = runtime.store.get(late.id).node
    assert reread.status is ClaimStatus.SUPERSEDED
    assert reread.commitment.fulfillment is FulfillmentStatus.FULFILLED


def test_set_fulfillment_rejects_a_claim_that_promised_nothing(runtime):
    plain = _claims(runtime.store)["project Beacon will ship behind a feature flag."]
    with pytest.raises(ValueError, match="no commitment facet"):
        runtime.store.set_fulfillment(plain.id, "fulfilled")


def test_a_scope_without_the_source_sees_no_commitments(runtime):
    """A commitment is subject to the identical query-time check as any other
    claim -- it carries an ``ObjectAcl`` and there is no bypass."""
    commitments = [c for c in _claims(runtime.store).values() if c.commitment is not None]
    assert commitments

    wide = Scope(
        agent_id="agent-commitments",
        owner_id=OWNER,
        sources=["mock"],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    assert all(evaluate(wide, c.acl, AS_OF).allowed for c in commitments)

    elsewhere = wide.model_copy(update={"sources": ["github"]})
    decisions = [evaluate(elsewhere, c.acl, AS_OF) for c in commitments]
    assert not any(d.allowed for d in decisions)
    assert {d.reason.value for d in decisions} == {"source_not_in_scope"}

    # The parties are part of what a commitment is about, so a scope with no
    # persons in it must not see one either.
    no_persons = wide.model_copy(
        update={"entity_kinds": [k for k in EntityKind if k is not EntityKind.PERSON]}
    )
    assert not any(evaluate(no_persons, c.acl, AS_OF).allowed for c in commitments)


def test_a_pure_reassignment_is_not_mistaken_for_a_duplicate(store):
    """Who owes a commitment lives in the facet, not the statement text, so
    two claims can read identically and still be different obligations."""
    other = "owner-reassign"
    store.wipe_owner(other)
    try:
        records = [
            RawRecord(
                external_id=f"reassign-{n}",
                connector="mock",
                occurred_at_ms=BASE_MS + n * DAY_MS,
                title="Atlas migration",
                body=(
                    f"{who} committed that project Atlas will ship the storage "
                    "migration by 2025-02-14."
                ),
                participants=[who],
            )
            for n, who in enumerate(["Alice", "Bob"], start=1)
        ]
        extractor = MockExtractor()
        candidates = [extractor.extract(other, r) for r in records]
        resolutions = Resolver(store).resolve_batch(other, candidates)
        assert [p for r in resolutions for p in r.supersessions], (
            "same wording, different party: a reassignment, not a duplicate"
        )
        assert not [d for r in resolutions for d in r.duplicates]
    finally:
        store.wipe_owner(other)
