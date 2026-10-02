"""A dimension change must not be silently ignored.

The vector index is created with ``CREATE VECTOR INDEX ... IF NOT EXISTS``, which
means changing ``EMBEDDING_DIM`` against an existing database used to do nothing
at all: the old index survived, `apply_migrations` logged the *new* dimension as
though it had taken effect, writes landed as list properties the index declined to
cover, and reads then failed inside ``vector_search`` with an arity error a long
way from the cause.

That is the worst shape a failure can have -- configuration and reality
disagreeing, with the log siding with configuration. These tests hold the two
things that make it loud instead: the index is recreated when the dimension
changes, and a vector of the wrong width is refused at the point of writing.
"""

from __future__ import annotations

import time

import pytest

from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.permissions import ObjectAcl
from orchestrator.schema import Entity, Provenance
from orchestrator.storage.migrations import (
    VECTOR_INDEX_NAME,
    apply_migrations,
    vector_index_dim,
)
from orchestrator.storage.neo4j_store import Neo4jStore

OWNER = "owner-dimension"


def _entity(owner_id: str = OWNER, node_id: str = "ent_dim_probe") -> Entity:
    now = int(time.time() * 1000)
    return Entity(
        id=node_id,
        owner_id=owner_id,
        kind=EntityKind.PROJECT,
        name="dimension probe",
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


def _dim(store: Neo4jStore) -> int | None:
    with store.driver.session(database=store.database) as session:
        return vector_index_dim(session)


def test_the_live_index_dimension_is_readable(store) -> None:
    """Read from SHOW INDEXES rather than assumed from configuration, because the
    two disagreeing is the whole failure being guarded against."""
    assert _dim(store) is not None, f"{VECTOR_INDEX_NAME} should exist after migrations"


def test_a_changed_dimension_recreates_the_index(store, settings) -> None:
    configured = settings.embedding_dim
    other = configured + 128

    apply_migrations(store.driver, settings.neo4j_database, other)
    assert _dim(store) == other, "the index must follow the configured dimension"

    # And back, so the rest of the suite sees the database it expects.
    apply_migrations(store.driver, settings.neo4j_database, configured)
    assert _dim(store) == configured


def test_an_unchanged_dimension_leaves_the_index_alone(store, settings) -> None:
    """Re-running migrations is a boot-time operation, so the common case must not
    drop and rebuild an index over a populated graph."""
    before = _dim(store)
    apply_migrations(store.driver, settings.neo4j_database, settings.embedding_dim)
    assert _dim(store) == before


def test_a_wrong_width_vector_is_refused_at_write(store, settings, vector) -> None:
    """Neo4j accepts a mis-sized vector as an ordinary list property and simply
    does not index it, so without this check the node is stored and permanently
    invisible to retrieval -- a write that succeeds and loses the data."""
    store.wipe_owner(OWNER)
    try:
        with pytest.raises(ValueError, match="dimensions"):
            store.upsert(_entity(), [0.1] * (settings.embedding_dim - 1))
        with pytest.raises(ValueError, match="dimensions"):
            store.upsert(_entity(), [0.1] * (settings.embedding_dim + 1))

        # The right width still works.
        store.upsert(_entity(), vector())
        assert len(store.get_many(OWNER, ["ent_dim_probe"])) == 1
    finally:
        store.wipe_owner(OWNER)


def test_a_store_without_a_declared_dimension_does_not_check(settings) -> None:
    """The parameter is optional so existing callers are unaffected, and a store
    built without it behaves exactly as before. Worth pinning: the check is a
    guard, not a new requirement on every construction."""
    unchecked = Neo4jStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
        settings.neo4j_database,
    )
    try:
        assert unchecked._embedding_dim is None
    finally:
        unchecked.close()


def test_the_configured_dimension_matches_the_embedder(settings) -> None:
    """The one that catches a model swap that forgot the config. Uses whichever
    embedder is configured, so it holds for the mock path too."""
    from orchestrator.retrieval.embeddings import get_embedder, verify_dim

    embedder = get_embedder(settings)
    verify_dim(embedder, settings.embedding_dim)
    assert len(embedder.embed("a probe")) == settings.embedding_dim
