"""The registry's whole point, as an executable claim.

``test_a_new_source_needs_no_changes_outside_its_own_module`` registers a
connector that exists only in this file and ingests from it end to end,
touching no Rust, no ``enums.py`` and no ``retrieval/index.py``. If a future
change reintroduces a closed set of sources anywhere on that path -- an
enum, a chunking table keyed by source, a hardcoded ``if source ==`` -- that
test is what fails.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from orchestrator.api import IngestRequest, enqueue_ingest
from orchestrator.config import Settings
from orchestrator.connectors import REGISTRY, ConnectorSpec, MockConnector
from orchestrator.connectors.registry import ConnectorRegistry, UnknownSourceError
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.retrieval.index import chunk_for_source
from orchestrator.schema import RawRecord

OWNER = "owner-registry"
SOURCE = "acme-notes"


_FIXTURES = [
    RawRecord(
        external_id="acme-001",
        connector=SOURCE,
        occurred_at_ms=1_735_689_600_000,
        title="Zephyr datastore",
        body="Dana decided that project Zephyr will use Redis for its queue.",
        url="https://acme.local/notes/1",
        participants=["Dana"],
        metadata={"notebook": "eng", "starred": True},
    )
]


class AcmeNotesConnector:
    """A second fixture source, defined entirely in this test module."""

    name = SOURCE

    def fetch(self, owner_id: str, since_ms: int):
        return [r for r in _FIXTURES if r.occurred_at_ms >= since_ms]


def _split_on_rules(text: str) -> list[str]:
    return [part.strip() for part in text.split("\n---\n") if part.strip()]


ACME_SPEC = ConnectorSpec(
    source_id=SOURCE,
    display_name="Acme Notes",
    factory=lambda settings: AcmeNotesConnector(),
    chunker=_split_on_rules,
)


@pytest.fixture
def registry() -> ConnectorRegistry:
    registry = REGISTRY.copy()
    registry.register(ACME_SPEC)
    return registry


@pytest.fixture
def runtime(settings, store, registry):
    rt = Runtime.build(settings, registry=registry)
    rt.store.wipe_owner(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def test_a_new_source_needs_no_changes_outside_its_own_module(runtime, registry):
    result = run_ingestion(runtime, owner_id=OWNER, source=SOURCE)

    assert result.errors == []
    assert result.records == 1
    assert result.entities > 0
    assert result.claims > 0

    stored = runtime.store.count(OWNER)
    assert stored.get("Event", 0) == 1

    # Chunking dispatches to the connector's own chunker, with no entry for
    # this source anywhere in retrieval/.
    assert chunk_for_source("a\n---\nb", SOURCE, registry) == ["a", "b"]


def test_record_metadata_survives_the_connector_boundary():
    record = next(iter(AcmeNotesConnector().fetch(OWNER, 0)))
    assert record.metadata["notebook"] == "eng"
    assert RawRecord.model_validate(record.model_dump(mode="json")).metadata == record.metadata


def test_unknown_source_is_rejected_at_the_api_edge():
    with pytest.raises(HTTPException) as caught:
        enqueue_ingest(IngestRequest(owner_id=OWNER, source="does-not-exist"))
    assert caught.value.status_code == 400
    assert "unknown source" in caught.value.detail
    assert "mock" in caught.value.detail


def test_unknown_source_names_what_is_known():
    with pytest.raises(UnknownSourceError) as caught:
        REGISTRY.spec("does-not-exist")
    assert "known sources" in str(caught.value)


def test_registration_fails_loudly_on_a_duplicate_or_a_malformed_id():
    registry = REGISTRY.copy()
    with pytest.raises(ValueError, match="already registered"):
        registry.register(ConnectorSpec("mock", "Impostor", lambda s: MockConnector()))
    with pytest.raises(ValueError, match="invalid source id"):
        registry.register(ConnectorSpec("Acme Notes!", "Bad", lambda s: MockConnector()))


def test_mock_mode_does_not_substitute_fixtures_for_a_real_source():
    """Mock mode is per source, not global.

    A connector with no fixture stand-in behaves the same in both modes, so a
    half-built connector cannot look like it works.
    """
    settings = Settings(mode="mock")
    assert settings.is_mock
    connector = REGISTRY.connector("google", settings)
    with pytest.raises(NotImplementedError):
        list(connector.fetch(OWNER, 0))


def test_disabled_sources_are_refused_before_the_graph_runs(store, registry, settings):
    narrowed = settings.model_copy(update={"enabled_sources": ["mock"]})
    rt = Runtime.build(narrowed, registry=registry)
    try:
        with pytest.raises(Exception, match="not enabled"):
            run_ingestion(rt, owner_id=OWNER, source=SOURCE)
    finally:
        rt.store.wipe_owner(OWNER)
        rt.close()


def test_a_real_connector_can_run_without_llm_credentials():
    """Checking a parser must not require an LLM key.

    ``mode`` used to be one switch over three unrelated things -- connector,
    extractor, embedder -- so pointing a real connector at real data forced
    ``live``, which demands ANTHROPIC_API_KEY for an extraction step that has
    nothing to do with reading a file.
    """
    s = Settings(CONNECTOR_FIXTURES="never")

    assert s.use_fixture_connectors is False
    assert s.use_llm_extractor is False, "extraction must stay keyless"
    assert s.use_real_embedder is False

    # ...while the axes still follow `mode` when left alone.
    assert Settings().use_fixture_connectors is True
    live = Settings(ORCHESTRATOR_MODE="live", ANTHROPIC_API_KEY="x")
    assert live.use_llm_extractor is True
    assert live.use_fixture_connectors is False
    # ...and a single axis can be pinned against the mode.
    assert Settings(ORCHESTRATOR_MODE="live", EXTRACTOR="mock").use_llm_extractor is False
