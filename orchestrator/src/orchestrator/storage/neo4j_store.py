"""Neo4j driver wrapper: the queryable index over resolved memory.

Neo4j holds entities, events, claims, their edges and their embeddings. It
is conceptually rebuildable from source material, which is why nothing here
is treated as the system of record -- raw content belongs in Walrus, under
the owner's keys, once that is wired.

Each object is stored twice over: as scalar properties for filtering and
ranking, and as a ``payload`` JSON blob so it round-trips back into the
pydantic model without a lossy column mapping.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from neo4j import Driver, GraphDatabase

from ..enums import ClaimStatus, FulfillmentStatus
from ..schema import Claim, Entity, Event, MemoryNode

log = logging.getLogger(__name__)

_LABELS = {"Entity": Entity, "Event": Event, "Claim": Claim}


@dataclass(slots=True)
class StoredNode:
    id: str
    label: str
    node: MemoryNode
    text: str
    occurred_at_ms: int


def _label_of(node: MemoryNode) -> str:
    return type(node).__name__


def _text_of(node: MemoryNode) -> str:
    if isinstance(node, Entity):
        return " ".join([node.name, *node.aliases])
    if isinstance(node, Event):
        return f"{node.summary} {node.body or ''}".strip()
    return node.statement


def _occurred_at(node: MemoryNode) -> int:
    if isinstance(node, Entity):
        return node.last_seen_at_ms
    if isinstance(node, Event):
        return node.source.occurred_at_ms
    return node.asserted_at_ms


#: Claim fields lifted out of the opaque ``payload`` blob into real,
#: indexable Neo4j properties. Everything else still round-trips through the
#: blob; these are promoted because "which commitments are open and past
#: due?" has to be a Cypher query against an index, not a full scan that
#: filters in Python. Non-claims get ``None``, which Neo4j stores as an
#: absent property.
#: Fields lifted out of the opaque ``payload`` blob into real Neo4j properties,
#: because a question has to be answerable without loading and parsing every
#: payload in Python. Listed once and expanded into every statement that writes
#: them (`_promoted_set`), because they used to be spelled out in three places
#: and a field added to two of them is a column that is silently always null in
#: whichever path was missed.
_PROMOTED_KEYS = (
    "claim_status",
    "commitment_fulfillment",
    "commitment_due_at_ms",
    "commitment_owed_by",
    "commitment_owed_to",
    "memory_kind",
)


def _promoted_set(var: str) -> str:
    """The ``SET`` clause for the promoted columns, for one Cypher variable."""
    return ", ".join(f"{var}.{key} = ${key}" for key in _PROMOTED_KEYS)


def _promoted(node: MemoryNode) -> dict[str, Any]:
    if not isinstance(node, Claim):
        return dict.fromkeys(_PROMOTED_KEYS)
    c = node.commitment
    return {
        "claim_status": node.status.value,
        "commitment_fulfillment": c.fulfillment.value if c else None,
        "commitment_due_at_ms": c.due_at_ms if c else None,
        "commitment_owed_by": c.owed_by_entity_id if c else None,
        "commitment_owed_to": c.owed_to_entity_id if c else None,
        # `None` stays `None`: a claim with no kind has none, and writing a
        # default here would put a value an indexed query then serves and a
        # grant filter then enforces.
        "memory_kind": node.memory_kind.value if node.memory_kind else None,
    }


def _hydrate(record: dict[str, Any]) -> StoredNode:
    label = next(lbl for lbl in record["labels"] if lbl in _LABELS)
    model = _LABELS[label]
    return StoredNode(
        id=record["id"],
        label=label,
        node=model.model_validate_json(record["payload"]),
        text=record["text"],
        occurred_at_ms=record["occurred_at_ms"],
    )


#: The session columns, listed once: three reads return the same shape and a
#: column added to one and forgotten in another is a field that is silently
#: always None.
_SESSION_COLUMNS = (
    "s.id AS id, s.owner_id AS owner_id, s.agent_id AS agent_id, "
    "s.device_id AS device_id, s.grant_fp AS grant_fp, "
    "s.opened_at_ms AS opened_at_ms, s.expires_at_ms AS expires_at_ms, "
    "s.closed_at_ms AS closed_at_ms, s.block_count AS block_count, "
    "s.byte_len AS byte_len, s.consolidated_into AS consolidated_into"
)


def _session_to_row(session) -> dict:
    return {
        "id": session.id,
        "owner_id": session.owner_id,
        "agent_id": session.agent_id,
        "device_id": session.device_id,
        "grant_fp": session.grant_fp,
        "opened_at_ms": int(session.opened_at_ms),
        "expires_at_ms": int(session.expires_at_ms),
        "closed_at_ms": session.closed_at_ms,
        "block_count": int(session.block_count),
        "byte_len": int(session.byte_len),
        "consolidated_into": list(session.consolidated_into),
    }


def _row_to_session(row: dict):
    from .sessions import AgentSession

    return AgentSession(
        id=row["id"],
        owner_id=row["owner_id"],
        agent_id=row["agent_id"],
        device_id=row["device_id"],
        grant_fp=row["grant_fp"],
        opened_at_ms=int(row["opened_at_ms"]),
        expires_at_ms=int(row["expires_at_ms"] or 0),
        closed_at_ms=None if row["closed_at_ms"] is None else int(row["closed_at_ms"]),
        block_count=int(row["block_count"] or 0),
        byte_len=int(row["byte_len"] or 0),
        consolidated_into=list(row["consolidated_into"] or []),
    )


class Neo4jStore:
    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        database: str = "neo4j",
        embedding_dim: int | None = None,
    ) -> None:
        # Neo4j warns on every query that references a property or
        # relationship type not yet present in an empty database, which is
        # normal on a fresh store and drowns out real logs.
        self._driver: Driver = GraphDatabase.driver(
            uri, auth=(user, password), notifications_min_severity="OFF"
        )
        self._database = database
        # Checked on every upsert when set. Neo4j accepts a vector of the wrong
        # width as an ordinary list property and simply declines to index it, so
        # the write succeeds, retrieval never sees the node, and nothing says why.
        self._embedding_dim = embedding_dim

    @property
    def driver(self) -> Driver:
        return self._driver

    @property
    def database(self) -> str:
        return self._database

    def close(self) -> None:
        self._driver.close()

    def verify(self) -> None:
        self._driver.verify_connectivity()

    def _run(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        with self._driver.session(database=self._database) as session:
            return [record.data() for record in session.run(cypher, **params)]

    # -- writes ---------------------------------------------------------

    def upsert(self, node: MemoryNode, embedding: list[float]) -> bool:
        if self._embedding_dim is not None and len(embedding) != self._embedding_dim:
            raise ValueError(
                f"embedding for {node.id} has {len(embedding)} dimensions, index expects "
                f"{self._embedding_dim}. Neo4j would accept this as a plain list property "
                f"and leave it unindexed, so the node would be stored and unreachable."
            )
        label = _label_of(node)
        # owner_id is in the MERGE *pattern*, not only in the SET. Matching by
        # id alone would let a node that already exists under another owner be
        # matched and then have its owner_id overwritten -- a takeover rather
        # than a leak. With the owner in the pattern, that case instead tries to
        # create a second node with a duplicate id and trips the uniqueness
        # constraint, which is the loud failure we want.
        cypher = f"""
        MERGE (n:{label} {{id: $id, owner_id: $owner_id}})
        ON CREATE SET n.created_at_ms = timestamp()
        SET n:Memory,
            n.changed_at_ms = timestamp(),
            n.payload = $payload,
            n.text = $text,
            n.occurred_at_ms = $occurred_at_ms,
            n.acl_sources = $acl_sources,
            n.acl_sensitivity = $acl_sensitivity,
            n.acl_entity_kinds = $acl_entity_kinds,
            n.embedding = $embedding,
            {_promoted_set("n")}
        RETURN n.created_at_ms = n.changed_at_ms AS created
        """
        rows = self._run(
            cypher,
            **_promoted(node),
            id=node.id,
            owner_id=node.owner_id,
            payload=node.model_dump_json(),
            text=_text_of(node),
            occurred_at_ms=_occurred_at(node),
            acl_sources=list(node.acl.sources),
            acl_sensitivity=node.acl.sensitivity.value,
            acl_entity_kinds=[k.value for k in node.acl.entity_kinds],
            embedding=embedding,
        )
        # Whether this call created the node or rewrote one that was already
        # there. The caller needs it to avoid recording a creation five times
        # for an entity mentioned in five records -- the same overcount
        # `IngestionResult` already refuses to make.
        #
        # `changed_at_ms` is also the change timestamp the schema never had:
        # `asserted_at_ms` is when the thing was asserted and
        # `Provenance.created_at_ms` is when the extractor ran, and neither says
        # when the row last moved.
        return bool(rows and rows[0]["created"])

    #: Edge types whose creation is itself a state change, and which therefore
    #: carry who made it. Only these two: `MENTIONS`, `ABOUT` and `CITES` are
    #: statements of structure that follow from the object's own content, not
    #: decisions about the record.
    _ATTRIBUTED_EDGES = frozenset({"SUPERSEDES", "CONTRADICTS"})

    def link(
        self,
        owner_id: str,
        from_id: str,
        rel: str,
        to_id: str,
        *,
        actor=None,
        rule: str | None = None,
    ) -> bool:
        """Creates ``(from)-[:rel]->(to)``, both ends inside one owner.

        Owner-scoped like every traversal here, and for the same reason: an
        edge is the unit the reads walk over, so one written across owners
        would place a foreign node inside a permission-checked walk. The
        owner constraint on the traversals exists precisely so a foreign node
        never becomes a candidate in the first place; an unscoped write is
        the one way to get one in anyway.

        Ids are derived and collision is unlikely, which is why this held in
        practice. "Unlikely" is not the property a boundary should rest on.

        Returns whether an edge was written. A miss means an endpoint was
        absent or belonged to someone else, which some callers legitimately
        ignore -- a citation can name an event this batch has not reached yet.
        """
        if not rel.isidentifier():
            raise ValueError(f"illegal relationship type {rel!r}")
        # `ON CREATE` only, so a re-link never rewrites who did it first. A
        # supersession asserted twice was decided once, and `MERGE` would
        # otherwise let the second writer quietly take credit.
        #
        # A denormalisation, deliberately: `:Mutation` is the authority, and
        # these properties exist so `why_did_this_shift` can render "superseded
        # by device 1" without a second query per step. They are also why the
        # neighbourhood read keeps returning edge *types* and nothing else --
        # it drops rather than withholds, so edge properties there would be a
        # new disclosure surface.
        attributed = rel in self._ATTRIBUTED_EDGES and actor is not None
        on_create = (
            " ON CREATE SET r.at_ms = timestamp(), "
            "r.actor_agent_id = $actor_agent_id, "
            "r.actor_device_id = $actor_device_id, "
            "r.rule = $rule"
            if attributed
            else ""
        )
        params: dict[str, Any] = {
            "owner_id": owner_id,
            "from_id": from_id,
            "to_id": to_id,
        }
        if attributed:
            params["actor_agent_id"] = actor.agent_id
            params["actor_device_id"] = actor.device_id
            params["rule"] = rule
        rows = self._run(
            f"MATCH (a:Memory {{id: $from_id, owner_id: $owner_id}}), "
            f"(b:Memory {{id: $to_id, owner_id: $owner_id}}) "
            f"MERGE (a)-[r:{rel}]->(b)"
            f"{on_create} "
            f"RETURN count(r) AS n",
            **params,
        )
        return bool(rows and rows[0]["n"])

    def _mutate_claim(self, owner_id: str, claim_id: str, mutate) -> Claim | None:
        """Read-modify-write a stored claim, within one owner.

        The claim's fields live inside the opaque ``payload`` blob, so they
        cannot be patched in Cypher; the promoted properties are rewritten
        from the mutated model so the blob and the indexed columns can never
        disagree.

        Owner-scoped like every other statement here. It was not, and that was
        the same latent bug ``link`` had: ``set_claim_status`` is called during
        ingestion with an id taken from a claim's ``supersedes`` list, so an id
        that crossed owners would have let one owner's write mark another
        owner's claim superseded.
        """
        rows = self._run(
            "MATCH (c:Claim {id: $id, owner_id: $owner_id}) RETURN c.payload AS payload",
            id=claim_id,
            owner_id=owner_id,
        )
        if not rows:
            return None
        claim = Claim.model_validate_json(rows[0]["payload"])
        # The prior snapshot, read back from the store rather than reconstructed
        # from what the caller believed was there. It is what makes a mutation
        # entry's `before` a fact instead of an assumption, and it costs one
        # parse of a payload already in hand.
        prior = claim.model_copy(deep=True)
        mutate(claim)
        self._run(
            "MATCH (c:Claim {id: $id, owner_id: $owner_id}) SET c.payload = $payload, "
            + _promoted_set("c"),
            id=claim_id,
            owner_id=owner_id,
            payload=claim.model_dump_json(),
            **_promoted(claim),
        )
        return prior, claim

    def set_claim_status(
        self,
        owner_id: str,
        claim_id: str,
        status: str,
        *,
        actor,
        reason: str,
        rule: str,
    ) -> None:
        """Moves the *epistemic* axis only. Fulfillment is untouched: a
        commitment that was reassigned is superseded and still open.

        ``actor``, ``reason`` and ``rule`` are keyword-only and have **no
        defaults**, so an unattributed status change does not type-check. The
        same shape as `link` refusing an unscoped write rather than warning
        about one: the caller cannot forget, because there is nothing to forget
        -- the call does not compile without it.
        """
        from .mutations import KIND_STATUS, MutationEntry

        def mutate(claim: Claim) -> None:
            claim.status = ClaimStatus(status)

        result = self._mutate_claim(owner_id, claim_id, mutate)
        if result is None:
            return
        prior, claim = result
        if prior.status is claim.status:
            # Nothing moved. Recording it would put a change in the log that did
            # not happen, and the resolver legitimately re-asserts a supersession
            # it has already applied.
            return
        self.append_mutation(
            MutationEntry.for_actor(
                actor,
                owner_id=owner_id,
                object_id=claim_id,
                kind=KIND_STATUS,
                field_name="status",
                before=prior.status.value,
                after=claim.status.value,
                reason=reason,
                rule=rule,
            )
        )

    def set_reconciled_into(
        self,
        owner_id: str,
        claim_id: str,
        into_claim_id: str,
        *,
        actor,
        reason: str,
        rule: str,
    ) -> Claim | None:
        """Marks one side of a settled disagreement, pointing at what settled it.

        Moves the epistemic axis to `reconciled` and sets `reconciled_into`
        together, because they are one fact and a claim reconciled with nothing
        to point at is worse than an unreconciled one -- `graphs/history.py`
        reads the pointer to render what resolved the conflict.

        Attributed like every other mutation, and for the same reason: this is a
        change to what the record believes, and the question "who decided this
        disagreement was over" is exactly the kind the log exists for.
        """
        from .mutations import KIND_RECONCILE, MutationEntry

        def mutate(claim: Claim) -> None:
            claim.status = ClaimStatus.RECONCILED
            claim.reconciled_into = into_claim_id

        result = self._mutate_claim(owner_id, claim_id, mutate)
        if result is None:
            return None
        prior, claim = result
        if prior.reconciled_into == claim.reconciled_into and prior.status is claim.status:
            return claim
        self.append_mutation(
            MutationEntry.for_actor(
                actor,
                owner_id=owner_id,
                object_id=claim_id,
                kind=KIND_RECONCILE,
                field_name="reconciled_into",
                before=prior.reconciled_into,
                after=into_claim_id,
                reason=reason,
                rule=rule,
            )
        )
        return claim

    def set_fulfillment(
        self,
        owner_id: str,
        claim_id: str,
        fulfillment: str,
        settled_at_ms: int | None = None,
        *,
        actor,
        reason: str,
    ) -> Claim | None:
        """Moves the *lifecycle* axis only, leaving ``status`` alone.

        Raises if the claim carries no commitment facet: fulfilling a claim
        that promised nothing is a caller bug, not a no-op.
        """
        state = FulfillmentStatus(fulfillment)

        def mutate(claim: Claim) -> None:
            if claim.commitment is None:
                raise ValueError(f"claim {claim_id!r} has no commitment facet")
            claim.commitment.fulfillment = state
            claim.commitment.settled_at_ms = (
                None if state is FulfillmentStatus.OPEN else settled_at_ms
            )

        from .mutations import KIND_FULFILLMENT, MutationEntry

        result = self._mutate_claim(owner_id, claim_id, mutate)
        if result is None:
            return None
        prior, claim = result
        # No `rule` here, and that is the distinction: the resolver's rules are
        # about what the record now believes, while a fulfillment move is
        # something that happened in the world. There is no branch that decided
        # it -- someone says the thing was done.
        if prior.commitment.fulfillment is not claim.commitment.fulfillment:
            self.append_mutation(
                MutationEntry.for_actor(
                    actor,
                    owner_id=owner_id,
                    object_id=claim_id,
                    kind=KIND_FULFILLMENT,
                    field_name="commitment.fulfillment",
                    before=prior.commitment.fulfillment.value,
                    after=claim.commitment.fulfillment.value,
                    reason=reason,
                )
            )
        return claim

    def replace_payload(self, node: MemoryNode) -> None:
        """Rewrites one object in place. The owner comes from the node itself,
        so there is no way to call this without naming one."""
        self._run(
            "MATCH (n:Memory {id: $id, owner_id: $owner_id}) SET n.payload = $payload, "
            + _promoted_set("n"),
            id=node.id,
            owner_id=node.owner_id,
            payload=node.model_dump_json(),
            **_promoted(node),
        )

    # -- reads ----------------------------------------------------------

    def get(self, node_id: str) -> StoredNode | None:
        rows = self._run(
            "MATCH (n:Memory {id: $id}) "
            "RETURN n.id AS id, labels(n) AS labels, n.payload AS payload, "
            "n.text AS text, n.occurred_at_ms AS occurred_at_ms",
            id=node_id,
        )
        return _hydrate(rows[0]) if rows else None

    def count(self, owner_id: str) -> dict[str, int]:
        rows = self._run(
            "MATCH (n:Memory {owner_id: $owner_id}) "
            "UNWIND labels(n) AS label "
            "WITH label WHERE label <> 'Memory' "
            "RETURN label, count(*) AS n",
            owner_id=owner_id,
        )
        return {row["label"]: row["n"] for row in rows}

    def claims_about(self, owner_id: str, entity_ids: Iterable[str]) -> list[StoredNode]:
        rows = self._run(
            "MATCH (c:Claim {owner_id: $owner_id})-[:ABOUT]->(e:Entity) "
            "WHERE e.id IN $entity_ids "
            "RETURN DISTINCT c.id AS id, labels(c) AS labels, c.payload AS payload, "
            "c.text AS text, c.occurred_at_ms AS occurred_at_ms",
            owner_id=owner_id,
            entity_ids=list(entity_ids),
        )
        return [_hydrate(row) for row in rows]

    def recent_entities(self, owner_id: str, limit: int = 2_000) -> list[StoredNode]:
        """This owner's entities, most recently seen first.

        The read canonicalisation needs: deciding whether a new ``RAG`` is the
        stored ``retrieval augmented generation`` means comparing names, and there
        is no index that answers "which stored name is an acronym of this one".
        So the candidate set is the entity set, and the work is done in Python.

        **The limit is a real bound, not a paper one.** Past it, an entity that
        has not been mentioned in a long time stops being a merge target and a
        duplicate gets created instead. That is the right way for this to
        degrade -- a duplicate is recoverable and a wrong merge is not -- but it
        does mean canonicalisation is best-effort on a graph larger than the cap.
        Ordering by last-seen is what makes the truncation sensible: the entities
        a person is actively talking about are the ones a new mention is likely
        to be about.

        Kind is *not* filtered here. ``entity_kind`` is not a promoted property,
        so filtering on it would mean either a schema migration or abusing
        ``acl_entity_kinds``, which answers a different question. The caller
        filters by kind after hydrating, which it can do for free because it has
        to hydrate the payload for the name anyway.
        """
        rows = self._run(
            "MATCH (e:Entity {owner_id: $owner_id}) "
            "RETURN e.id AS id, labels(e) AS labels, e.payload AS payload, "
            "e.text AS text, e.occurred_at_ms AS occurred_at_ms "
            "ORDER BY e.occurred_at_ms DESC "
            "LIMIT $limit",
            owner_id=owner_id,
            limit=limit,
        )
        return [_hydrate(row) for row in rows]

    def claims_of_kind(
        self,
        owner_id: str,
        kind: str,
        *,
        subject_entity_ids: list[str] | None = None,
        include_superseded: bool = False,
        limit: int = 50,
    ) -> list[StoredNode]:
        """Claims of one memory kind, newest assertion first.

        An indexed query on the promoted column rather than a scan that hydrates
        every payload and filters in Python -- the same reason
        ``open_commitments`` exists in this form. "What procedure do we use for
        X" is a question the briefing asks on every call, and it has to cost one
        index seek.

        Superseded claims are excluded by default, like there: a procedure that
        was replaced is still a stored procedure, but it is not the one to
        follow, and returning both leaves the caller to guess.

        **Permission-blind, like every other read in this store.** The caller
        runs ``permits`` per candidate; a scope that grants procedures and not
        episodes is enforced in the permission node, not here.
        """
        rows = self._run(
            "MATCH (c:Claim {owner_id: $owner_id}) "
            "WHERE c.memory_kind = $kind "
            "  AND ($include_superseded OR c.claim_status = 'active') "
            "  AND ($subjects IS NULL OR ANY(e IN $subjects WHERE "
            "       (c)-[:ABOUT]->(:Entity {id: e, owner_id: $owner_id}))) "
            "RETURN c.id AS id, labels(c) AS labels, c.payload AS payload, "
            "c.text AS text, c.occurred_at_ms AS occurred_at_ms "
            "ORDER BY c.occurred_at_ms DESC, c.id LIMIT $limit",
            owner_id=owner_id,
            kind=kind,
            subjects=subject_entity_ids,
            include_superseded=include_superseded,
            limit=int(limit),
        )
        return [_hydrate(row) for row in rows]

    def open_commitments(
        self,
        owner_id: str,
        *,
        due_before_ms: int | None = None,
        owed_by_entity_id: str | None = None,
        include_superseded: bool = False,
    ) -> list[StoredNode]:
        """Commitments still outstanding, newest deadline last.

        ``due_before_ms`` makes it the past-due read (a commitment with no
        deadline can never be past due, so it drops out). By default only
        epistemically active claims count: a commitment that was reassigned
        is still ``open``, but it is no longer what this owner is owed by
        that person, and returning both would double-count the obligation.
        """
        rows = self._run(
            "MATCH (c:Claim {owner_id: $owner_id}) "
            "WHERE c.commitment_fulfillment = 'open' "
            "  AND ($include_superseded OR c.claim_status = 'active') "
            "  AND ($due_before_ms IS NULL OR c.commitment_due_at_ms < $due_before_ms) "
            "  AND ($owed_by IS NULL OR c.commitment_owed_by = $owed_by) "
            "RETURN c.id AS id, labels(c) AS labels, c.payload AS payload, "
            "c.text AS text, c.occurred_at_ms AS occurred_at_ms "
            "ORDER BY c.commitment_due_at_ms, c.id",
            owner_id=owner_id,
            due_before_ms=due_before_ms,
            owed_by=owed_by_entity_id,
            include_superseded=include_superseded,
        )
        return [_hydrate(row) for row in rows]

    #: Hard ceiling on how far the owner search will escalate. Reaching it means
    #: returning fewer results than asked for rather than scanning the graph.
    _VECTOR_FETCH_CEILING = 4096

    def vector_search(
        self, owner_id: str, embedding: list[float], top_k: int
    ) -> list[tuple[StoredNode, float]]:
        """Nearest stored objects belonging to one owner.

        The owner filter is applied **after** the index returns, because a Neo4j
        vector index cannot pre-filter on a property. That makes the fetch size
        load-bearing, and a fixed over-fetch is not enough: the index is global, so
        in a database holding several owners the nearest `k` globally can be entirely
        somebody else's, and this returns nothing at all while the owner's own
        matching objects sit one rank below the cutoff.

        That is not hypothetical -- it is how this was found. A dev database with ~100
        objects across four owners made an owner with 20 objects retrieve zero, which
        read as an empty memory rather than as a tuning problem.

        So the fetch escalates: ask for more until enough of the answers belong to
        this owner, the index is exhausted, or the ceiling is hit. Costs one extra
        round trip in the crowded case and nothing in the common one.
        """
        wanted = max(top_k, 1)
        k = max(wanted * 4, wanted)
        while True:
            returned, mine = self._vector_query(owner_id, embedding, k)
            exhausted = returned < k
            at_ceiling = k >= self._VECTOR_FETCH_CEILING
            if len(mine) >= wanted or exhausted or at_ceiling:
                if len(mine) < wanted and at_ceiling and not exhausted:
                    log.warning(
                        "vector search for %s stopped at the fetch ceiling with %d of %d "
                        "results; this owner's objects are being crowded out of the global "
                        "index by other owners' vectors",
                        owner_id,
                        len(mine),
                        wanted,
                    )
                return mine[:wanted]
            k = min(k * 4, self._VECTOR_FETCH_CEILING)

    def _vector_query(
        self, owner_id: str, embedding: list[float], k: int
    ) -> tuple[int, list[tuple[StoredNode, float]]]:
        """``(how many the index returned, this owner's among them)``.

        The first number is what tells the caller whether asking for more could help:
        fewer than `k` means the index had no more to give.
        """
        rows = self._run(
            "CALL db.index.vector.queryNodes('kleos_memory_embedding', $k, $embedding) "
            "YIELD node, score "
            "RETURN node.id AS id, labels(node) AS labels, node.payload AS payload, "
            "node.text AS text, node.occurred_at_ms AS occurred_at_ms, score, "
            "node.owner_id AS owner_id",
            k=k,
            embedding=embedding,
        )
        mine = [
            (_hydrate(row), float(row["score"]))
            for row in rows
            if row["owner_id"] == owner_id
        ]
        return len(rows), mine

    def get_many(self, owner_id: str, node_ids: Iterable[str]) -> list[StoredNode]:
        """Bulk ``get``, constrained to one owner.

        ``get`` looks an id up globally, which is right for the resolver's
        "have I stored this already?" check. Anything that hands ids to a
        *reader* has to stay inside the owner's subgraph instead.
        """
        rows = self._run(
            "MATCH (n:Memory {owner_id: $owner_id}) WHERE n.id IN $ids "
            "RETURN n.id AS id, labels(n) AS labels, n.payload AS payload, "
            "n.text AS text, n.occurred_at_ms AS occurred_at_ms",
            owner_id=owner_id,
            ids=list(node_ids),
        )
        return [_hydrate(row) for row in rows]

    def supersession_chain(
        self, owner_id: str, claim_id: str, max_hops: int = 24
    ) -> list[StoredNode]:
        """Every claim in the supersession run containing ``claim_id``, oldest first.

        The walk is **undirected** on purpose: a caller holding a claim id
        may be holding the current claim, the original, or something in the
        middle, and all three have to answer the same question. Following
        ``SUPERSEDES`` only outward would answer it for one of the three.

        Every node on the path is owner-constrained, not just the endpoints:
        an intermediate hop through another owner's claim would pull their
        claims into the chain.
        """
        rows = self._run(
            f"MATCH (seed:Claim {{id: $id, owner_id: $owner_id}}) "
            f"OPTIONAL MATCH path = (seed)-[:SUPERSEDES*1..{int(max_hops)}]-(c:Claim) "
            "WHERE ALL(n IN nodes(path) WHERE n.owner_id = $owner_id) "
            "WITH seed, collect(DISTINCT c) AS others "
            "UNWIND (others + [seed]) AS n "
            "RETURN DISTINCT n.id AS id, labels(n) AS labels, n.payload AS payload, "
            "n.text AS text, n.occurred_at_ms AS occurred_at_ms "
            "ORDER BY occurred_at_ms, id",
            id=claim_id,
            owner_id=owner_id,
        )
        return [_hydrate(row) for row in rows]

    def conflict_links(self, owner_id: str, claim_ids: Iterable[str]) -> list[tuple[str, str]]:
        """``(claim, contradicted claim)`` pairs touching any of ``claim_ids``."""
        rows = self._run(
            "MATCH (a:Claim {owner_id: $owner_id})-[:CONTRADICTS]->(b:Claim {owner_id: $owner_id}) "
            "WHERE a.id IN $ids OR b.id IN $ids "
            "RETURN DISTINCT a.id AS from_id, b.id AS to_id ORDER BY from_id, to_id",
            owner_id=owner_id,
            ids=list(claim_ids),
        )
        return [(row["from_id"], row["to_id"]) for row in rows]

    def cites_chain(
        self, owner_id: str, node_id: str, hops: int = 3
    ) -> tuple[dict[str, int], list[tuple[str, str]]]:
        """``CITES`` neighbourhood of ``node_id``: hop distances and edges.

        ``CITES`` is the edge that means "this was derived from that", and it
        is keyed by event id rather than by source, so a chain over it
        crosses connectors wherever the underlying material does. Walked
        undirected: what an event was derived from and what was later derived
        from it are both context.
        """
        depth = int(hops)
        owner_ok = "ALL(n IN nodes(path) WHERE n.owner_id = $owner_id)"
        nodes = self._run(
            f"MATCH (seed:Memory {{id: $id, owner_id: $owner_id}}) "
            f"MATCH path = (seed)-[:CITES*1..{depth}]-(other:Memory) "
            f"WHERE {owner_ok} "
            "RETURN other.id AS id, min(length(path)) AS hops",
            id=node_id,
            owner_id=owner_id,
        )
        edges = self._run(
            f"MATCH (seed:Memory {{id: $id, owner_id: $owner_id}}) "
            f"MATCH path = (seed)-[:CITES*1..{depth}]-(:Memory) "
            f"WHERE {owner_ok} "
            "UNWIND relationships(path) AS r "
            "RETURN DISTINCT startNode(r).id AS from_id, endNode(r).id AS to_id "
            "ORDER BY from_id, to_id",
            id=node_id,
            owner_id=owner_id,
        )
        return (
            {row["id"]: int(row["hops"]) for row in nodes},
            [(row["from_id"], row["to_id"]) for row in edges],
        )

    def neighbour_ids(
        self, owner_id: str, node_ids: Iterable[str], hops: int = 2
    ) -> dict[str, int]:
        """Node id -> shortest hop distance from any of ``node_ids``.

        ``owner_id`` constrains both ends of the walk, not just the seed.
        Unconstrained, one owner's node id could pull back another owner's
        neighbours -- and since graph proximity feeds ranking before the
        permission check runs, nothing downstream would catch it.
        """
        rows = self._run(
            f"MATCH (seed:Memory {{owner_id: $owner_id}}) WHERE seed.id IN $ids "
            f"MATCH path = (seed)-[*1..{int(hops)}]-(other:Memory {{owner_id: $owner_id}}) "
            "RETURN other.id AS id, min(length(path)) AS hops",
            ids=list(node_ids),
            owner_id=owner_id,
        )
        return {row["id"]: int(row["hops"]) for row in rows}

    def edges_among(
        self, owner_id: str, node_ids: Iterable[str]
    ) -> list[tuple[str, str, str]]:
        """``(from_id, relationship_type, to_id)`` for edges whose **both**
        endpoints are in ``node_ids``, within one owner.

        Deliberately not a traversal: it is handed a closed set of ids and
        reports only the edges internal to it. A caller that has already
        dropped the objects a grant does not cover therefore cannot get back
        an edge pointing at one of them.
        """
        ids = list(node_ids)
        if not ids:
            return []
        rows = self._run(
            "MATCH (a:Memory {owner_id: $owner_id})-[r]->(b:Memory {owner_id: $owner_id}) "
            "WHERE a.id IN $ids AND b.id IN $ids "
            "RETURN DISTINCT a.id AS from_id, type(r) AS rel, b.id AS to_id "
            "ORDER BY from_id, rel, to_id",
            owner_id=owner_id,
            ids=ids,
        )
        return [(row["from_id"], row["rel"], row["to_id"]) for row in rows]

    # -- the read log ---------------------------------------------------
    #
    # Stored here, but deliberately *not* labelled `:Memory`. Every traversal
    # and the vector index above are keyed on that label, so staying off it is
    # what keeps audit entries out of retrieval and out of anything an agent
    # can reach. See `storage/reads.py` and ADR 0005.

    def append_read(self, entry) -> None:
        """Appends one read-log entry. Raises if it cannot be written."""
        from .reads import entry_to_row

        self._run(
            "CREATE (r:AgentRead) SET r = $row",
            row=entry_to_row(entry),
        )

    def recent_reads(self, owner_id: str, limit: int = 50) -> list:
        from .reads import row_to_entry

        rows = self._run(
            "MATCH (r:AgentRead {owner_id: $owner_id}) "
            "RETURN r.id AS id, r.owner_id AS owner_id, r.agent_id AS agent_id, "
            "r.device_id AS device_id, r.session_id AS session_id, "
            "r.grant_fp AS grant_fp, r.kind AS kind, r.disclosed_ids AS disclosed_ids, "
            "r.denied_json AS denied_json, r.considered AS considered, "
            "r.subject AS subject, r.at_ms AS at_ms "
            "ORDER BY r.at_ms DESC, r.id DESC LIMIT $limit",
            owner_id=owner_id,
            limit=int(limit),
        )
        return [row_to_entry(row) for row in rows]

    # -- the action log ---------------------------------------------------
    #
    # The fourth append-only record, and the only one about something that
    # happened *outside* this system. A read discloses and a mutation changes the
    # record; an action sends mail. It cannot be undone by rewriting a row, which
    # is why the record of it has to be complete. See `storage/actions.py`.

    _ACTION_COLUMNS = (
        "a.id AS id, a.owner_id AS owner_id, a.action_id AS action_id, "
        "a.agent_id AS agent_id, a.device_id AS device_id, "
        "a.session_id AS session_id, a.grant_fp AS grant_fp, a.ok AS ok, "
        "a.digest AS digest, a.summary AS summary, a.error AS error, "
        "a.args_fp AS args_fp, a.at_ms AS at_ms"
    )

    def append_action(self, entry) -> None:
        """Appends one action record. Raises if it cannot be written."""
        from .actions import entry_to_row

        self._run("CREATE (a:AgentAction) SET a = $row", row=entry_to_row(entry))

    def recent_actions(self, owner_id: str, limit: int = 50) -> list:
        from .actions import row_to_entry

        rows = self._run(
            "MATCH (a:AgentAction {owner_id: $owner_id}) "
            f"RETURN {self._ACTION_COLUMNS} "
            "ORDER BY a.at_ms DESC, a.id DESC LIMIT $limit",
            owner_id=owner_id,
            limit=int(limit),
        )
        return [row_to_entry(row) for row in rows]

    def wipe_actions(self, owner_id: str) -> None:
        """For tests and an explicit owner request. Never a side effect: nothing
        a re-ingest does un-sends a message."""
        self._run(
            "MATCH (a:AgentAction {owner_id: $owner_id}) DELETE a", owner_id=owner_id
        )

    # -- the mutation log -----------------------------------------------
    #
    # Beside the read log, off `:Memory` for the same reason, and the second
    # thing in this database that cannot be regenerated from source material.
    # See `storage/mutations.py`.

    _MUTATION_COLUMNS = (
        "m.id AS id, m.owner_id AS owner_id, m.object_id AS object_id, "
        "m.kind AS kind, m.field AS field, m.before AS before, m.after AS after, "
        "m.actor_agent_id AS actor_agent_id, m.actor_device_id AS actor_device_id, "
        "m.actor_session_id AS actor_session_id, m.reason AS reason, "
        "m.rule AS rule, m.grant_fp AS grant_fp, m.at_ms AS at_ms"
    )

    def append_mutation(self, entry) -> None:
        """Appends one mutation entry. Raises if it cannot be written."""
        from .mutations import entry_to_row

        self._run("CREATE (m:Mutation) SET m = $row", row=entry_to_row(entry))

    def recent_mutations(self, owner_id: str, limit: int = 50) -> list:
        from .mutations import row_to_entry

        rows = self._run(
            "MATCH (m:Mutation {owner_id: $owner_id}) "
            f"RETURN {self._MUTATION_COLUMNS} "
            "ORDER BY m.at_ms DESC, m.id DESC LIMIT $limit",
            owner_id=owner_id,
            limit=int(limit),
        )
        return [row_to_entry(row) for row in rows]

    def mutations_for_objects(self, owner_id: str, object_ids: list[str]) -> list:
        """Every recorded change to these objects, oldest first.

        Oldest first, unlike `recent_mutations`: this is read as a history of one
        object rather than as a feed, and a history reads forwards.
        """
        from .mutations import row_to_entry

        rows = self._run(
            "MATCH (m:Mutation {owner_id: $owner_id}) WHERE m.object_id IN $ids "
            f"RETURN {self._MUTATION_COLUMNS} "
            "ORDER BY m.at_ms ASC, m.id ASC",
            owner_id=owner_id,
            ids=list(object_ids),
        )
        return [row_to_entry(row) for row in rows]

    def wipe_mutations(self, owner_id: str) -> None:
        """For tests and an explicit owner request, like `wipe_read_log`. Not a
        side effect of re-ingesting: re-deriving a claim does not un-happen the
        change that was made to the one it replaced."""
        self._run("MATCH (m:Mutation {owner_id: $owner_id}) DELETE m", owner_id=owner_id)

    # -- agent sessions -------------------------------------------------
    #
    # Beside the read log, and off `:Memory` for the same reason. A session holds
    # an agent's working context; if it were retrievable as memory, one agent's
    # scratchpad would surface in another agent's answers through the very check
    # that is supposed to separate them. See `storage/sessions.py` and ADR 0016.

    def append_session(self, session) -> None:
        """Records an opened session. Raises if it cannot be written."""
        self._run(
            "CREATE (s:AgentSession) SET s = $row",
            row=_session_to_row(session),
        )

    def get_session(self, owner_id: str, session_id: str):
        """One session, scoped to its owner.

        Owner-scoped in the match rather than checked afterwards: a session id
        from another owner must not be an existence oracle, the same rule every
        traversal here follows.
        """
        rows = self._run(
            "MATCH (s:AgentSession {owner_id: $owner_id, id: $id}) "
            f"RETURN {_SESSION_COLUMNS}",
            owner_id=owner_id,
            id=session_id,
        )
        return _row_to_session(rows[0]) if rows else None

    def recent_sessions(self, owner_id: str, limit: int = 50) -> list:
        rows = self._run(
            "MATCH (s:AgentSession {owner_id: $owner_id}) "
            f"RETURN {_SESSION_COLUMNS} "
            "ORDER BY s.opened_at_ms DESC, s.id DESC LIMIT $limit",
            owner_id=owner_id,
            limit=int(limit),
        )
        return [_row_to_session(row) for row in rows]

    def close_session(self, owner_id: str, session_id: str, at_ms: int) -> bool:
        rows = self._run(
            "MATCH (s:AgentSession {owner_id: $owner_id, id: $id}) "
            "SET s.closed_at_ms = $at_ms RETURN s.id AS id",
            owner_id=owner_id,
            id=session_id,
            at_ms=int(at_ms),
        )
        return bool(rows)

    def bump_session_counters(
        self, owner_id: str, session_id: str, blocks: int, bytes_: int
    ) -> None:
        """Advances the bounds counters in the database, not in Python.

        A read-modify-write from the caller would lose an append whenever two
        arrive at once, and the counters are what the caps are checked against.
        """
        self._run(
            "MATCH (s:AgentSession {owner_id: $owner_id, id: $id}) "
            "SET s.block_count = coalesce(s.block_count, 0) + $blocks, "
            "    s.byte_len = coalesce(s.byte_len, 0) + $bytes",
            owner_id=owner_id,
            id=session_id,
            blocks=int(blocks),
            bytes=int(bytes_),
        )

    def set_session_consolidation(
        self, owner_id: str, session_id: str, claim_ids: list[str]
    ) -> None:
        """Records which claims this session produced. Additive, never replacing:
        a second consolidation of the same session adds to what the first found."""
        self._run(
            "MATCH (s:AgentSession {owner_id: $owner_id, id: $id}) "
            "SET s.consolidated_into = coalesce(s.consolidated_into, []) + "
            "  [x IN $ids WHERE NOT x IN coalesce(s.consolidated_into, [])]",
            owner_id=owner_id,
            id=session_id,
            ids=list(claim_ids),
        )

    def append_session_block(self, owner_id: str, block) -> None:
        """Records where one block landed. The bytes are in the blob store; this
        is the index into it, and it holds no content of any kind."""
        self._run(
            "CREATE (b:SessionBlock) SET b = $row",
            row={
                "owner_id": owner_id,
                "session_id": block.session_id,
                "index": int(block.index),
                "blob_id": block.blob_id,
                "patch_id": block.patch_id,
                "byte_len": int(block.byte_len),
                "backend": block.backend,
                "at_ms": int(block.at_ms),
                "key_id": block.key_id,
            },
        )

    def session_blocks(self, owner_id: str, session_id: str) -> list:
        from .sessions import StoredBlock

        rows = self._run(
            "MATCH (b:SessionBlock {owner_id: $owner_id, session_id: $session_id}) "
            "RETURN b.session_id AS session_id, b.index AS index, b.blob_id AS blob_id, "
            "b.patch_id AS patch_id, b.byte_len AS byte_len, b.backend AS backend, "
            "b.at_ms AS at_ms, b.key_id AS key_id ORDER BY b.index ASC",
            owner_id=owner_id,
            session_id=session_id,
        )
        return [
            StoredBlock(
                session_id=row["session_id"],
                index=int(row["index"]),
                blob_id=row["blob_id"],
                patch_id=row["patch_id"],
                byte_len=int(row["byte_len"]),
                backend=row["backend"],
                at_ms=int(row["at_ms"]),
                key_id=row.get("key_id"),
            )
            for row in rows
        ]

    def link_consolidation(self, owner_id: str, claim_id: str, session_id: str) -> bool:
        """``(:Claim)-[:CONSOLIDATED_FROM]->(:AgentSession)``.

        Its own method rather than `link`, because `link` matches both endpoints
        as `:Memory` and an `:AgentSession` deliberately is not one. That is the
        constraint working as intended: this is the only edge in the graph that
        crosses from memory to the harness's own record of itself, and it only
        goes one way. A traversal from a claim cannot follow it into a scratchpad,
        because every walk keys on `:Memory` too.

        Owner-scoped at both ends like every other write here.
        """
        rows = self._run(
            "MATCH (c:Claim {id: $claim_id, owner_id: $owner_id}), "
            "(s:AgentSession {id: $session_id, owner_id: $owner_id}) "
            "MERGE (c)-[r:CONSOLIDATED_FROM]->(s) "
            "RETURN count(r) AS n",
            owner_id=owner_id,
            claim_id=claim_id,
            session_id=session_id,
        )
        return bool(rows and rows[0]["n"])

    def consolidated_from(self, owner_id: str, session_id: str) -> list[str]:
        """Claim ids this session produced, read off the edges rather than the
        session's own property -- so the two can be compared."""
        rows = self._run(
            "MATCH (c:Claim {owner_id: $owner_id})-[:CONSOLIDATED_FROM]->"
            "(:AgentSession {id: $session_id, owner_id: $owner_id}) "
            "RETURN c.id AS id ORDER BY c.id",
            owner_id=owner_id,
            session_id=session_id,
        )
        return [row["id"] for row in rows]

    def wipe_sessions(self, owner_id: str) -> None:
        """For tests and an explicit owner request. Not a side effect of
        re-ingesting, like the read log and for the same reason."""
        self._run(
            "MATCH (s:AgentSession {owner_id: $owner_id}) DETACH DELETE s",
            owner_id=owner_id,
        )
        self._run(
            "MATCH (b:SessionBlock {owner_id: $owner_id}) DELETE b", owner_id=owner_id
        )

    def wipe_owner(self, owner_id: str) -> None:
        """Removes an owner's memory graph.

        The read log is left alone on purpose: it records what was disclosed
        to agents, and a re-ingest does not un-disclose it. Clearing it is
        `wipe_read_log`, which exists for tests and for an explicit owner
        request, not as a side effect of re-ingesting.
        """
        self._run("MATCH (n:Memory {owner_id: $owner_id}) DETACH DELETE n", owner_id=owner_id)

    def wipe_read_log(self, owner_id: str) -> None:
        self._run("MATCH (r:AgentRead {owner_id: $owner_id}) DELETE r", owner_id=owner_id)
