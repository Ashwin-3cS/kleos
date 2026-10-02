"""Edges stay inside one owner.

Every traversal in `neo4j_store` is owner-constrained at each node on the
path, so a foreign node can never become a candidate for a permission check.
``link`` was the one write that did not enforce the same thing: it matched
both endpoints by id alone. Ids are derived and collision is unlikely, which
is why it held in practice -- but an edge written across owners would place a
foreign node inside a permission-checked walk, and "unlikely" is not the
property a boundary should rest on.
"""

from __future__ import annotations

import time

import pytest
from neo4j.exceptions import Neo4jError

from orchestrator.enums import ClaimStatus, EntityKind, Sensitivity
from orchestrator.permissions import ObjectAcl
from orchestrator.schema import Claim, Entity, Provenance

OWNER = "owner-scoping-a"
OTHER = "owner-scoping-b"


def _entity(owner_id: str, node_id: str) -> Entity:
    now = int(time.time() * 1000)
    return Entity(
        id=node_id,
        owner_id=owner_id,
        kind=EntityKind.PROJECT,
        name=f"project {node_id}",
        first_seen_at_ms=now,
        last_seen_at_ms=now,
        provenance=Provenance(derived_by="test", created_at_ms=now),
        acl=ObjectAcl(
            owner_id=owner_id,
            sources=["mock"],
            sensitivity=Sensitivity.PERSONAL,
            entity_kinds=[EntityKind.PROJECT],
            occurred_at_ms=now,
        ),
    )


@pytest.fixture
def two_owners(store):
    store.wipe_owner(OWNER)
    store.wipe_owner(OTHER)
    mine_a = _entity(OWNER, "scoping-mine-a")
    mine_b = _entity(OWNER, "scoping-mine-b")
    theirs = _entity(OTHER, "scoping-theirs")
    for node in (mine_a, mine_b, theirs):
        store.upsert(node, [0.0] * 256)
    yield store, mine_a, mine_b, theirs
    store.wipe_owner(OWNER)
    store.wipe_owner(OTHER)


def test_a_link_within_one_owner_is_written(two_owners) -> None:
    store, mine_a, mine_b, _ = two_owners
    assert store.link(OWNER, mine_a.id, "MENTIONS", mine_b.id) is True
    assert store.neighbour_ids(OWNER, [mine_a.id], hops=1) == {mine_b.id: 1}


def test_a_link_across_owners_is_refused(two_owners) -> None:
    store, mine_a, _, theirs = two_owners
    assert store.link(OWNER, mine_a.id, "MENTIONS", theirs.id) is False
    assert store.neighbour_ids(OWNER, [mine_a.id], hops=2) == {}
    assert store.neighbour_ids(OTHER, [theirs.id], hops=2) == {}


def test_the_other_owner_cannot_claim_the_edge_either(two_owners) -> None:
    """Passing the *other* owner's id does not help: both endpoints must
    belong to whichever owner is named, so neither direction works."""
    store, mine_a, _, theirs = two_owners
    assert store.link(OTHER, mine_a.id, "MENTIONS", theirs.id) is False
    assert store.link(OTHER, theirs.id, "MENTIONS", mine_a.id) is False


def test_a_missing_endpoint_reports_a_miss_rather_than_raising(two_owners) -> None:
    """Ordinary during ingestion: a citation can name an event a later batch
    brings in, so the caller logs and moves on."""
    store, mine_a, _, _ = two_owners
    assert store.link(OWNER, mine_a.id, "CITES", "scoping-never-written") is False


def test_an_illegal_relationship_type_is_rejected(two_owners) -> None:
    """The type is interpolated into Cypher, so it is validated rather than
    parameterised -- Neo4j does not parameterise relationship types."""
    store, mine_a, mine_b, _ = two_owners
    for bad in ["MENTIONS]->() DETACH DELETE n //", "has space", "", "a-b"]:
        with pytest.raises(ValueError):
            store.link(OWNER, mine_a.id, bad, mine_b.id)


def test_link_is_idempotent(two_owners) -> None:
    store, mine_a, mine_b, _ = two_owners
    assert store.link(OWNER, mine_a.id, "MENTIONS", mine_b.id) is True
    assert store.link(OWNER, mine_a.id, "MENTIONS", mine_b.id) is True
    edges = store.edges_among(OWNER, [mine_a.id, mine_b.id])
    assert edges == [(mine_a.id, "MENTIONS", mine_b.id)]


# -- the cases a source-text check cannot see ---------------------------


def test_upsert_cannot_take_over_another_owners_node(store) -> None:
    """``upsert`` passes the textual check because its SET assigns owner_id, but
    what matters is whether the *pattern* names one.

    A MERGE by id alone would match a node that already exists under another
    owner and then overwrite its owner_id -- a takeover rather than a leak, and
    invisible to a check that only looks for the string ``$owner_id``. With the
    owner in the pattern the same call instead attempts a second node with a
    duplicate id and trips the uniqueness constraint, which is the loud failure.
    """
    now = int(time.time() * 1000)
    shared_id = "ent_takeover_probe"

    def entity(owner_id: str) -> Entity:
        return Entity(
            id=shared_id,
            owner_id=owner_id,
            kind=EntityKind.PROJECT,
            name=f"{owner_id}'s project",
            first_seen_at_ms=now,
            last_seen_at_ms=now,
            provenance=Provenance(derived_by="test", created_at_ms=now),
            acl=ObjectAcl(
                owner_id=owner_id,
                sources=["mock"],
                sensitivity=Sensitivity.PERSONAL,
                entity_kinds=[EntityKind.PROJECT],
                occurred_at_ms=now,
            ),
        )

    store.wipe_owner("owner-takeover-a")
    store.wipe_owner("owner-takeover-b")
    try:
        store.upsert(entity("owner-takeover-a"), [0.0] * 256)

        # Same id, different owner. Must not silently become owner-b's node.
        with pytest.raises(Neo4jError):
            store.upsert(entity("owner-takeover-b"), [0.0] * 256)

        still_mine = store.get_many("owner-takeover-a", [shared_id])
        assert len(still_mine) == 1
        assert still_mine[0].node.owner_id == "owner-takeover-a"
        assert store.get_many("owner-takeover-b", [shared_id]) == []
    finally:
        store.wipe_owner("owner-takeover-a")
        store.wipe_owner("owner-takeover-b")


def test_a_mutation_cannot_cross_owners(store) -> None:
    """``set_claim_status`` is called during ingestion with an id taken from a
    claim's ``supersedes`` list. If that id crossed owners, one owner's ingest
    would mark another owner's claim superseded."""
    now = int(time.time() * 1000)
    claim = Claim(
        id="clm_cross_owner_probe",
        owner_id="owner-mutate-a",
        statement="project Probe will use Sqlite.",
        asserted_at_ms=now,
        provenance=Provenance(derived_by="test", created_at_ms=now),
        acl=ObjectAcl(
            owner_id="owner-mutate-a",
            sources=["mock"],
            sensitivity=Sensitivity.PERSONAL,
            entity_kinds=[EntityKind.PROJECT],
            occurred_at_ms=now,
        ),
    )
    store.wipe_owner("owner-mutate-a")
    try:
        store.upsert(claim, [0.0] * 256)

        # Another owner naming the same claim id changes nothing.
        store.set_claim_status("owner-mutate-b", claim.id, ClaimStatus.SUPERSEDED.value)
        assert store.get_many("owner-mutate-a", [claim.id])[0].node.status is ClaimStatus.ACTIVE

        # Its own owner can.
        store.set_claim_status("owner-mutate-a", claim.id, ClaimStatus.SUPERSEDED.value)
        assert (
            store.get_many("owner-mutate-a", [claim.id])[0].node.status
            is ClaimStatus.SUPERSEDED
        )
    finally:
        store.wipe_owner("owner-mutate-a")
