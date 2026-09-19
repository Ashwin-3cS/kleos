"""LlamaIndex wiring over Neo4j.

The retriever is a real ``BaseRetriever``, so anything in LlamaIndex that
consumes one (query engines, response synthesizers, re-rankers) works over
memorai memory unchanged. What it is *not* is a plain vector retriever: the
hybrid scoring in ``ranking.py`` runs inside ``_retrieve``, because
graph proximity needs the store, not just the vector index.

How a record should be split is a property of the source's shape (a chat
message, a code diff and a document are not the same object), so each
connector declares its own chunker and ``chunk_for_source`` only dispatches
through the registry. Retrieval knows nothing about any particular source.
"""

from __future__ import annotations

import time

from llama_index.core.retrievers import BaseRetriever
from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode

from ..config import Settings
from ..connectors.registry import REGISTRY, ConnectorRegistry
from ..enums import SourceId
from ..storage.neo4j_store import Neo4jStore
from .embeddings import Embedder
from .ranking import rank


def chunk_for_source(
    text: str, connector: SourceId, registry: ConnectorRegistry | None = None
) -> list[str]:
    """Splits raw text into retrieval-sized chunks according to source shape."""
    return (registry or REGISTRY).chunker(connector)(text)


class MemoryRetriever(BaseRetriever):
    """Hybrid retriever over resolved memory objects.

    Note what it does *not* do: filter by permission. Retrieval is
    deliberately permission-blind so that the query graph's permission node
    is the single enforcement point, and so a denial is visible as a denial
    rather than as an empty result set.
    """

    def __init__(
        self,
        store: Neo4jStore,
        embedder: Embedder,
        owner_id: str,
        top_k: int = 10,
    ) -> None:
        super().__init__()
        self._store = store
        self._embedder = embedder
        self._owner_id = owner_id
        self._top_k = top_k

    def _retrieve(self, query_bundle: QueryBundle) -> list[NodeWithScore]:
        now_ms = int(time.time() * 1000)
        embedding = self._embedder.embed(query_bundle.query_str)
        candidates = self._store.vector_search(self._owner_id, embedding, self._top_k * 2)
        if not candidates:
            return []

        # Seed graph proximity from the strongest semantic matches: what is
        # linked to an already-relevant object is itself likely relevant.
        seed_ids = [node.id for node, _ in candidates[: max(len(candidates) // 3, 1)]]
        hops = self._store.neighbour_ids(self._owner_id, seed_ids)

        ranked = rank(candidates, hops, now_ms)[: self._top_k]
        return [
            NodeWithScore(
                node=TextNode(
                    id_=r.node.id,
                    text=r.node.text,
                    metadata={
                        "label": r.node.label,
                        "occurred_at_ms": r.node.occurred_at_ms,
                        "semantic": round(r.semantic, 4),
                        "recency": round(r.recency, 4),
                        "proximity": round(r.proximity, 4),
                    },
                ),
                score=r.score,
            )
            for r in ranked
        ]

    def retrieve_stored(self, query: str):
        """Same ranking, but returns the stored pydantic objects.

        The query graph needs the full object -- ACL, provenance and all --
        not the flattened ``TextNode`` view, so it uses this instead.
        """
        now_ms = int(time.time() * 1000)
        embedding = self._embedder.embed(query)
        candidates = self._store.vector_search(self._owner_id, embedding, self._top_k * 2)
        if not candidates:
            return []
        seed_ids = [node.id for node, _ in candidates[: max(len(candidates) // 3, 1)]]
        hops = self._store.neighbour_ids(self._owner_id, seed_ids)
        return rank(candidates, hops, now_ms)[: self._top_k]


def property_graph_store(settings: Settings):
    """LlamaIndex's native property-graph store over the same database.

    Not on the retrieval path: memorai writes its own node shape (payload
    blobs plus flattened ACL columns) rather than LlamaIndex's triplet
    schema, so this is here for LlamaIndex-native graph queries and index
    construction against the same Neo4j instance.
    """
    from llama_index.graph_stores.neo4j import Neo4jPropertyGraphStore

    return Neo4jPropertyGraphStore(
        username=settings.neo4j_user,
        password=settings.neo4j_password,
        url=settings.neo4j_uri,
        database=settings.neo4j_database,
    )
