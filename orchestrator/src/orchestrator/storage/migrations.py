"""Idempotent Neo4j schema setup: uniqueness constraints and the vector index.

Safe to run on every boot; every statement is ``IF NOT EXISTS``.
"""

from __future__ import annotations

import logging

from neo4j import Driver

log = logging.getLogger(__name__)

_CONSTRAINTS = [
    "CREATE CONSTRAINT memorai_entity_id IF NOT EXISTS "
    "FOR (n:Entity) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT memorai_event_id IF NOT EXISTS "
    "FOR (n:Event) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT memorai_claim_id IF NOT EXISTS "
    "FOR (n:Claim) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT memorai_agent_read_id IF NOT EXISTS "
    "FOR (n:AgentRead) REQUIRE n.id IS UNIQUE",
]

_INDEXES = [
    "CREATE INDEX memorai_memory_owner IF NOT EXISTS FOR (n:Memory) ON (n.owner_id)",
    "CREATE INDEX memorai_memory_occurred IF NOT EXISTS FOR (n:Memory) ON (n.occurred_at_ms)",
    # The open/past-due read: fulfillment narrows to a handful of claims and
    # the deadline orders them, so one composite index answers it without
    # touching the payload blob.
    "CREATE INDEX memorai_claim_commitment IF NOT EXISTS "
    "FOR (n:Claim) ON (n.commitment_fulfillment, n.commitment_due_at_ms)",
    # "what does this person still owe" -- the other way commitments are read.
    "CREATE INDEX memorai_claim_commitment_owed_by IF NOT EXISTS "
    "FOR (n:Claim) ON (n.commitment_owed_by)",
    # Epistemic status, promoted alongside it and indexed for the same reason:
    # the open-commitment read excludes superseded claims by default.
    "CREATE INDEX memorai_claim_status IF NOT EXISTS FOR (n:Claim) ON (n.claim_status)",
    # The read log. Owner plus time is the only way it is read -- "show me what
    # agents have seen, newest first" -- and the composite index serves both
    # the filter and the ordering. `:AgentRead` carries no `:Memory` label, so
    # none of the indexes above touch it. See ADR 0005.
    "CREATE INDEX memorai_agent_read_owner_at IF NOT EXISTS "
    "FOR (n:AgentRead) ON (n.owner_id, n.at_ms)",
    "CREATE INDEX memorai_agent_read_grant IF NOT EXISTS "
    "FOR (n:AgentRead) ON (n.grant_fp)",
]

# Every stored node also carries the :Memory label so one vector index covers
# entities, events and claims alike -- retrieval ranks them in a single pass.
_VECTOR_INDEX = """
CREATE VECTOR INDEX memorai_memory_embedding IF NOT EXISTS
FOR (n:Memory) ON (n.embedding)
OPTIONS {indexConfig: {
  `vector.dimensions`: $dim,
  `vector.similarity_function`: 'cosine'
}}
"""

# There is deliberately no full-text index on `n.text` any more. Since ADR 0010
# that property holds sealed ciphertext, so an index over it would match nothing
# and cost writes -- a broken index that still looks like a feature. Text search
# over sealed content needs either a searchable-encryption scheme or the
# enclave-side query engine of ADR 0010 stage 2; neither is a Lucene index.
# Dropped rather than left, because a fresh database would otherwise differ from
# an upgraded one.
_DROP_FULLTEXT_INDEX = "DROP INDEX memorai_memory_text IF EXISTS"


VECTOR_INDEX_NAME = "memorai_memory_embedding"

_DROP_VECTOR_INDEX = f"DROP INDEX {VECTOR_INDEX_NAME} IF EXISTS"


def vector_index_dim(session, name: str = VECTOR_INDEX_NAME) -> int | None:
    """The dimension the live vector index was actually created with.

    ``None`` when the index does not exist. Read from ``SHOW INDEXES`` rather than
    assumed from configuration, because the two disagreeing is exactly the failure
    this exists to catch.
    """
    rows = session.run(
        "SHOW INDEXES YIELD name, options WHERE name = $name RETURN options",
        name=name,
    ).data()
    if not rows:
        return None
    config = (rows[0].get("options") or {}).get("indexConfig") or {}
    dim = config.get("vector.dimensions")
    return int(dim) if dim is not None else None


def apply_migrations(driver: Driver, database: str, embedding_dim: int) -> None:
    """Applies the schema, recreating the vector index if its dimension changed.

    **Why the recreate exists.** The vector index is created ``IF NOT EXISTS``,
    which means a dimension change is otherwise *silently ignored*: the old index
    survives, this function logs the new dimension as though it had taken effect,
    writes land as properties the index refuses to cover, and every read then
    fails inside ``vector_search`` with an arity error far from the cause. That is
    the worst available failure -- configuration and reality disagreeing, with the
    log agreeing with configuration.

    So the live dimension is read back and the index is dropped and recreated on a
    mismatch. Dropping it does **not** re-embed anything: every stored vector was
    produced by the old model and is still the wrong width and the wrong meaning,
    so a dimension change requires a re-ingest. That is logged as a warning rather
    than done automatically, because re-embedding a corpus is an expensive,
    owner-scoped operation and silently starting one on boot would be worse than
    saying so.
    """
    with driver.session(database=database) as session:
        for statement in _CONSTRAINTS + _INDEXES:
            session.run(statement)

        live_dim = vector_index_dim(session)
        if live_dim is not None and live_dim != embedding_dim:
            log.warning(
                "vector index %s exists at %d dimensions but configuration says %d; "
                "dropping and recreating it. Every embedding already stored was "
                "produced by the previous model and is now unusable -- re-ingest, or "
                "retrieval will silently return nothing.",
                VECTOR_INDEX_NAME,
                live_dim,
                embedding_dim,
            )
            session.run(_DROP_VECTOR_INDEX)

        session.run(_VECTOR_INDEX, dim=embedding_dim)
        session.run(_DROP_FULLTEXT_INDEX)
    log.info("neo4j migrations applied (embedding_dim=%s)", embedding_dim)
