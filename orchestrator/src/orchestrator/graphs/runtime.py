"""Shared per-run wiring for both graphs.

Held in one place because a LangGraph node receives only its state, and
threading a driver, an embedder and a gateway client through the state dict
would make the state a bag of connections instead of a description of the
run.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Settings, get_settings
from ..connectors.registry import REGISTRY, ConnectorRegistry
from ..extraction import get_extractor
from ..extraction.base import Extractor
from ..gateway_client import GatewayClient
from ..retrieval.embeddings import Embedder, get_embedder, verify_dim
from ..retrieval.ranking import RankingWeights
from ..storage.blobs import BlobStore, get_blob_store
from ..storage.content import ContentCrypto, NullContentCrypto
from ..storage.migrations import apply_migrations
from ..storage.neo4j_store import Neo4jStore
from ..storage.reads import ReadLog


@dataclass(slots=True)
class Runtime:
    settings: Settings
    store: Neo4jStore
    embedder: Embedder
    extractor: Extractor
    gateway: GatewayClient
    #: Which sources this run can fetch from. A copy of the process-wide
    #: registry, so a caller can add a connector for one run without
    #: mutating global state.
    registry: ConnectorRegistry
    #: Where sealed ciphertext lands. See ADR 0002.
    blobs: BlobStore
    #: What every agent read actually returned. See ADR 0005.
    read_log: ReadLog
    #: Seals the record's text before it is stored, and unseals only what a read
    #: is about to disclose. See ADR 0010.
    content: ContentCrypto | NullContentCrypto
    weights: RankingWeights

    @classmethod
    def build(
        cls,
        settings: Settings | None = None,
        migrate: bool = True,
        registry: ConnectorRegistry | None = None,
    ) -> Runtime:
        settings = settings or get_settings()
        store = Neo4jStore(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password,
            settings.neo4j_database,
            embedding_dim=settings.embedding_dim,
        )
        # Built before the migration so a width mismatch fails here rather than
        # after an index has been created at the wrong dimension.
        embedder = get_embedder(settings)
        verify_dim(embedder, settings.embedding_dim)
        if migrate:
            apply_migrations(store.driver, settings.neo4j_database, settings.embedding_dim)
        gateway = GatewayClient(settings.gateway_url)
        return cls(
            settings=settings,
            store=store,
            embedder=embedder,
            extractor=get_extractor(settings),
            gateway=gateway,
            registry=registry or REGISTRY.copy(),
            blobs=get_blob_store(settings),
            read_log=ReadLog(store),
            content=(
                ContentCrypto(gateway)
                if settings.encrypt_content_at_rest
                else NullContentCrypto()
            ),
            weights=RankingWeights.from_settings(settings),
        )

    def close(self) -> None:
        self.store.close()
        self.gateway.close()
