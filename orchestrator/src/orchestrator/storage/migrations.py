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

_FULLTEXT_INDEX = """
CREATE FULLTEXT INDEX memorai_memory_text IF NOT EXISTS
FOR (n:Memory) ON EACH [n.text]
"""


def apply_migrations(driver: Driver, database: str, embedding_dim: int) -> None:
    with driver.session(database=database) as session:
        for statement in _CONSTRAINTS + _INDEXES:
            session.run(statement)
        session.run(_VECTOR_INDEX, dim=embedding_dim)
        session.run(_FULLTEXT_INDEX)
    log.info("neo4j migrations applied (embedding_dim=%s)", embedding_dim)
