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
