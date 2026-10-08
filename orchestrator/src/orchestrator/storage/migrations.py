"""Idempotent Neo4j schema setup: uniqueness constraints and the vector index.

Safe to run on every boot; every statement is ``IF NOT EXISTS``.
"""

from __future__ import annotations

import logging

from neo4j import Driver

log = logging.getLogger(__name__)

_CONSTRAINTS = [
    "CREATE CONSTRAINT kleos_entity_id IF NOT EXISTS "
    "FOR (n:Entity) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT kleos_event_id IF NOT EXISTS "
    "FOR (n:Event) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT kleos_claim_id IF NOT EXISTS "
    "FOR (n:Claim) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT kleos_agent_read_id IF NOT EXISTS "
    "FOR (n:AgentRead) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT kleos_agent_session_id IF NOT EXISTS "
    "FOR (n:AgentSession) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT kleos_mutation_id IF NOT EXISTS "
    "FOR (n:Mutation) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT kleos_agent_action_id IF NOT EXISTS "
    "FOR (n:AgentAction) REQUIRE n.id IS UNIQUE",
]

_INDEXES = [
    "CREATE INDEX kleos_memory_owner IF NOT EXISTS FOR (n:Memory) ON (n.owner_id)",
    "CREATE INDEX kleos_memory_occurred IF NOT EXISTS FOR (n:Memory) ON (n.occurred_at_ms)",
    # The open/past-due read: fulfillment narrows to a handful of claims and
    # the deadline orders them, so one composite index answers it without
    # touching the payload blob.
    "CREATE INDEX kleos_claim_commitment IF NOT EXISTS "
    "FOR (n:Claim) ON (n.commitment_fulfillment, n.commitment_due_at_ms)",
    # "what does this person still owe" -- the other way commitments are read.
    "CREATE INDEX kleos_claim_commitment_owed_by IF NOT EXISTS "
    "FOR (n:Claim) ON (n.commitment_owed_by)",
    # Epistemic status, promoted alongside it and indexed for the same reason:
    # the open-commitment read excludes superseded claims by default.
    "CREATE INDEX kleos_claim_status IF NOT EXISTS FOR (n:Claim) ON (n.claim_status)",
    # Which kind of long-term memory a claim is, promoted for the same reason
    # the commitment fields are: "what procedures do we have about X" and the
    # grant filter for a scope that covers procedures and not episodes both have
    # to be indexed queries rather than scans that hydrate every payload.
    "CREATE INDEX kleos_claim_memory_kind IF NOT EXISTS "
    "FOR (n:Claim) ON (n.memory_kind)",
    # The read log. Owner plus time is the only way it is read -- "show me what
    # agents have seen, newest first" -- and the composite index serves both
    # the filter and the ordering. `:AgentRead` carries no `:Memory` label, so
    # none of the indexes above touch it. See ADR 0005.
    "CREATE INDEX kleos_agent_read_owner_at IF NOT EXISTS "
    "FOR (n:AgentRead) ON (n.owner_id, n.at_ms)",
    "CREATE INDEX kleos_agent_read_grant IF NOT EXISTS "
    "FOR (n:AgentRead) ON (n.grant_fp)",
    # Agent sessions. Read the same two ways the log is -- an owner's sessions
    # newest first, and everything one grant did -- and off `:Memory` for the
    # same reason: a scratchpad that could be retrieved as memory would put an
    # agent's working context into another agent's answers. See ADR 0016.
    "CREATE INDEX kleos_agent_session_owner_at IF NOT EXISTS "
    "FOR (n:AgentSession) ON (n.owner_id, n.opened_at_ms)",
    "CREATE INDEX kleos_agent_session_grant IF NOT EXISTS "
    "FOR (n:AgentSession) ON (n.grant_fp)",
    # A block belongs to exactly one session and is only ever read in order, so
    # the session id is the whole access path.
    "CREATE INDEX kleos_session_block_session IF NOT EXISTS "
    "FOR (n:SessionBlock) ON (n.owner_id, n.session_id, n.index)",
    # The mutation log, read two ways: an owner's changes newest first, and
    # every change to one object -- which is what a briefing surfaces for the
    # objects an agent was just permitted to see. Off `:Memory`, like the read
    # log, so the system's record of its own changes can never be retrieved as
    # memory.
    "CREATE INDEX kleos_mutation_owner_at IF NOT EXISTS "
    "FOR (n:Mutation) ON (n.owner_id, n.at_ms)",
    "CREATE INDEX kleos_mutation_object IF NOT EXISTS "
    "FOR (n:Mutation) ON (n.owner_id, n.object_id)",
    # What agents asked the enclave to *do*. Off `:Memory` like the other three
    # append-only records, and read the one way it is read: an owner's actions,
    # newest first.
    "CREATE INDEX kleos_agent_action_owner_at IF NOT EXISTS "
    "FOR (n:AgentAction) ON (n.owner_id, n.at_ms)",
]

# Every stored node also carries the :Memory label so one vector index covers
# entities, events and claims alike -- retrieval ranks them in a single pass.
_VECTOR_INDEX = """
CREATE VECTOR INDEX kleos_memory_embedding IF NOT EXISTS
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
_DROP_FULLTEXT_INDEX = "DROP INDEX kleos_memory_text IF EXISTS"


# -- the rename, as a migration ------------------------------------------
#
# Everything above used to be named `memorai_*`. A Neo4j constraint or index is
# identified by its name, so renaming one in source does not rename it in a live
# database: `CREATE ... IF NOT EXISTS` under the new name simply creates a second
# object over the same property, and the old one keeps being maintained on every
# write. Two indexes doing one index's job, paid for on every upsert, and nothing
# failing to say so.
#
# So the old names are dropped explicitly. Order matters: the new ones are created
# first, so a database that is interrupted between the two statements is left with
# a duplicate index rather than with none -- the recoverable failure rather than
# the one that makes every read slow and the uniqueness constraint absent.
#
# `IF EXISTS` throughout, so this is a no-op on a database that never had them,
# and safe to keep running forever. It is cheap and it stays: deleting it would
# mean a database last migrated before the rename silently keeps its duplicates.
_DROP_RENAMED = [
    "DROP CONSTRAINT memorai_entity_id IF EXISTS",
    "DROP CONSTRAINT memorai_event_id IF EXISTS",
    "DROP CONSTRAINT memorai_claim_id IF EXISTS",
    "DROP CONSTRAINT memorai_agent_read_id IF EXISTS",
    "DROP CONSTRAINT memorai_agent_session_id IF EXISTS",
    "DROP INDEX memorai_memory_owner IF EXISTS",
    "DROP INDEX memorai_memory_occurred IF EXISTS",
    "DROP INDEX memorai_claim_commitment IF EXISTS",
    "DROP INDEX memorai_claim_commitment_owed_by IF EXISTS",
    "DROP INDEX memorai_claim_status IF EXISTS",
    "DROP INDEX memorai_agent_read_owner_at IF EXISTS",
    "DROP INDEX memorai_agent_read_grant IF EXISTS",
    "DROP INDEX memorai_agent_session_owner_at IF EXISTS",
    "DROP INDEX memorai_agent_session_grant IF EXISTS",
    "DROP INDEX memorai_session_block_session IF EXISTS",
    # The full-text index was already being dropped under its old name; it stays
    # here rather than only in `_DROP_FULLTEXT_INDEX`, which now names the new one.
    "DROP INDEX memorai_memory_text IF EXISTS",
]

#: The vector index is the one that cannot simply be dropped and forgotten: it
#: holds the embeddings every read goes through. Dropping it does not delete the
#: vectors -- they are node properties -- so the new index populates from the same
#: data, exactly as the dimension-change path already relies on.
_DROP_RENAMED_VECTOR = "DROP INDEX memorai_memory_embedding IF EXISTS"


VECTOR_INDEX_NAME = "kleos_memory_embedding"

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

        # After the new names exist, never before. See `_DROP_RENAMED`.
        for statement in _DROP_RENAMED:
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
        # The old vector index goes last, for the ordering reason above and more
        # so here: it is the index every read goes through, so the window in which
        # neither exists has to be empty. Dropping it deletes no embeddings -- they
        # are node properties, which is what makes the recreate above safe too.
        session.run(_DROP_RENAMED_VECTOR)
        session.run(_DROP_FULLTEXT_INDEX)
    log.info("neo4j migrations applied (embedding_dim=%s)", embedding_dim)
