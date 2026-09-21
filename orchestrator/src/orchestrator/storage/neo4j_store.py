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

    def wipe_owner(self, owner_id: str) -> None:
        self._run("MATCH (n:Memory {owner_id: $owner_id}) DETACH DELETE n", owner_id=owner_id)
