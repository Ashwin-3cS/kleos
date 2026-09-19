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

from ..enums import ClaimStatus
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
            n.embedding = $embedding
        """
        self._run(
            cypher,
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

    def set_claim_status(self, claim_id: str, status: str) -> None:
        """Status lives inside the ``payload`` blob, so the claim is re-read,
        mutated and written back rather than patched in Cypher."""
        rows = self._run("MATCH (c:Claim {id: $id}) RETURN c.payload AS payload", id=claim_id)
        if not rows:
            return
        claim = Claim.model_validate_json(rows[0]["payload"])
        claim.status = ClaimStatus(status)
        self._run(
            "MATCH (c:Claim {id: $id}) SET c.payload = $payload",
            id=claim_id,
            payload=claim.model_dump_json(),
        )

    def replace_payload(self, node: MemoryNode) -> None:
        self._run(
            "MATCH (n:Memory {id: $id}) SET n.payload = $payload",
            id=node.id,
            payload=node.model_dump_json(),
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
