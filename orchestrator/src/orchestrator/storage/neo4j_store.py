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

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from neo4j import Driver, GraphDatabase

from ..enums import ClaimStatus, FulfillmentStatus
from ..schema import Claim, Entity, Event, MemoryNode

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
def _promoted(node: MemoryNode) -> dict[str, Any]:
    if not isinstance(node, Claim):
        return {
            "claim_status": None,
            "commitment_fulfillment": None,
            "commitment_due_at_ms": None,
            "commitment_owed_by": None,
            "commitment_owed_to": None,
        }
    c = node.commitment
    return {
        "claim_status": node.status.value,
        "commitment_fulfillment": c.fulfillment.value if c else None,
        "commitment_due_at_ms": c.due_at_ms if c else None,
        "commitment_owed_by": c.owed_by_entity_id if c else None,
        "commitment_owed_to": c.owed_to_entity_id if c else None,
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


class Neo4jStore:
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j") -> None:
        # Neo4j warns on every query that references a property or
        # relationship type not yet present in an empty database, which is
        # normal on a fresh store and drowns out real logs.
        self._driver: Driver = GraphDatabase.driver(
            uri, auth=(user, password), notifications_min_severity="OFF"
        )
        self._database = database

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

    def upsert(self, node: MemoryNode, embedding: list[float]) -> None:
        label = _label_of(node)
        cypher = f"""
        MERGE (n:{label} {{id: $id}})
        SET n:Memory,
            n.owner_id = $owner_id,
            n.payload = $payload,
            n.text = $text,
            n.occurred_at_ms = $occurred_at_ms,
            n.acl_sources = $acl_sources,
            n.acl_sensitivity = $acl_sensitivity,
            n.acl_entity_kinds = $acl_entity_kinds,
            n.embedding = $embedding,
            n.claim_status = $claim_status,
            n.commitment_fulfillment = $commitment_fulfillment,
            n.commitment_due_at_ms = $commitment_due_at_ms,
            n.commitment_owed_by = $commitment_owed_by,
            n.commitment_owed_to = $commitment_owed_to
        """
        self._run(
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

    def link(self, from_id: str, rel: str, to_id: str) -> None:
        if not rel.isidentifier():
            raise ValueError(f"illegal relationship type {rel!r}")
        self._run(
            f"MATCH (a:Memory {{id: $from_id}}), (b:Memory {{id: $to_id}}) "
            f"MERGE (a)-[:{rel}]->(b)",
            from_id=from_id,
            to_id=to_id,
        )

    def _mutate_claim(self, claim_id: str, mutate) -> Claim | None:
        """Read-modify-write a stored claim.

        The claim's fields live inside the opaque ``payload`` blob, so they
        cannot be patched in Cypher; the promoted properties are rewritten
        from the mutated model so the blob and the indexed columns can never
        disagree.
        """
        rows = self._run("MATCH (c:Claim {id: $id}) RETURN c.payload AS payload", id=claim_id)
        if not rows:
            return None
        claim = Claim.model_validate_json(rows[0]["payload"])
        mutate(claim)
        self._run(
            "MATCH (c:Claim {id: $id}) SET c.payload = $payload, "
            "c.claim_status = $claim_status, "
            "c.commitment_fulfillment = $commitment_fulfillment, "
            "c.commitment_due_at_ms = $commitment_due_at_ms, "
            "c.commitment_owed_by = $commitment_owed_by, "
            "c.commitment_owed_to = $commitment_owed_to",
            id=claim_id,
            payload=claim.model_dump_json(),
            **_promoted(claim),
        )
        return claim

    def set_claim_status(self, claim_id: str, status: str) -> None:
        """Moves the *epistemic* axis only. Fulfillment is untouched: a
        commitment that was reassigned is superseded and still open."""

        def mutate(claim: Claim) -> None:
            claim.status = ClaimStatus(status)

        self._mutate_claim(claim_id, mutate)

    def set_fulfillment(
        self, claim_id: str, fulfillment: str, settled_at_ms: int | None = None
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

        return self._mutate_claim(claim_id, mutate)

    def replace_payload(self, node: MemoryNode) -> None:
        self._run(
            "MATCH (n:Memory {id: $id}) SET n.payload = $payload, "
            "n.claim_status = $claim_status, "
            "n.commitment_fulfillment = $commitment_fulfillment, "
            "n.commitment_due_at_ms = $commitment_due_at_ms, "
            "n.commitment_owed_by = $commitment_owed_by, "
            "n.commitment_owed_to = $commitment_owed_to",
            id=node.id,
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

    def vector_search(
        self, owner_id: str, embedding: list[float], top_k: int
    ) -> list[tuple[StoredNode, float]]:
        rows = self._run(
            "CALL db.index.vector.queryNodes('memorai_memory_embedding', $k, $embedding) "
            "YIELD node, score "
            "WITH node, score WHERE node.owner_id = $owner_id "
            "RETURN node.id AS id, labels(node) AS labels, node.payload AS payload, "
            "node.text AS text, node.occurred_at_ms AS occurred_at_ms, score",
            # Over-fetch: the owner filter is applied after the index returns,
            # so asking for exactly top_k could come back short.
            k=max(top_k * 4, top_k),
            embedding=embedding,
            owner_id=owner_id,
        )
        return [(_hydrate(row), float(row["score"])) for row in rows[:top_k]]

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

    def wipe_owner(self, owner_id: str) -> None:
        self._run("MATCH (n:Memory {owner_id: $owner_id}) DETACH DELETE n", owner_id=owner_id)
