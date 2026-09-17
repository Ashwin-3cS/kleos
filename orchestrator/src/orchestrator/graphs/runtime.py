"""Shared per-run wiring for both graphs.

Held in one place because a LangGraph node receives only its state, and
threading a driver, an embedder and a gateway client through the state dict
would make the state a bag of connections instead of a description of the
run.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Settings, get_settings
from ..extraction import get_extractor
from ..extraction.base import Extractor
from ..gateway_client import GatewayClient
from ..retrieval.embeddings import Embedder, get_embedder
from ..storage.migrations import apply_migrations
from ..storage.neo4j_store import Neo4jStore


@dataclass(slots=True)
class Runtime:
    settings: Settings
    store: Neo4jStore
    embedder: Embedder
    extractor: Extractor
    gateway: GatewayClient

    @classmethod
    def build(cls, settings: Settings | None = None, migrate: bool = True) -> Runtime:
        settings = settings or get_settings()
        store = Neo4jStore(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password,
            settings.neo4j_database,
        )
        if migrate:
            apply_migrations(store.driver, settings.neo4j_database, settings.embedding_dim)
        return cls(
            settings=settings,
            store=store,
            embedder=get_embedder(settings),
            extractor=get_extractor(settings),
            gateway=GatewayClient(settings.gateway_url),
        )

    def close(self) -> None:
        self.store.close()
        self.gateway.close()
