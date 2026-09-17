from __future__ import annotations

import os

import pytest

os.environ.setdefault("ORCHESTRATOR_MODE", "mock")

from orchestrator.config import Settings  # noqa: E402
from orchestrator.storage.migrations import apply_migrations  # noqa: E402
from orchestrator.storage.neo4j_store import Neo4jStore  # noqa: E402


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings()


@pytest.fixture
def store(settings: Settings):
    store = Neo4jStore(
        settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password, settings.neo4j_database
    )
    try:
        store.verify()
    except Exception as exc:  # noqa: BLE001
        store.close()
        pytest.skip(f"neo4j not reachable at {settings.neo4j_uri}: {exc}")
    apply_migrations(store.driver, settings.neo4j_database, settings.embedding_dim)
    yield store
    store.close()
