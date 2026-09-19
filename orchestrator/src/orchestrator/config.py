from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    mode: str = Field(default="mock", validation_alias="ORCHESTRATOR_MODE")

    #: Per-axis overrides of `mode`. "auto" follows it; anything else wins.
    #: `CONNECTOR_FIXTURES=never` is what lets a real connector be pointed at
    #: real data while extraction and embedding stay keyless -- the way to
    #: check a parser without paying for an LLM call.
    connector_fixtures: str = Field(default="auto", validation_alias="CONNECTOR_FIXTURES")
    extractor: str = Field(default="auto", validation_alias="EXTRACTOR")
    embedder: str = Field(default="auto", validation_alias="EMBEDDER")

    host: str = Field(default="127.0.0.1", validation_alias="ORCHESTRATOR_HOST")
    port: int = Field(default=8090, validation_alias="ORCHESTRATOR_PORT")

    gateway_url: str = Field(default="http://127.0.0.1:8080", validation_alias="GATEWAY_URL")

    neo4j_uri: str = Field(default="bolt://127.0.0.1:7688", validation_alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", validation_alias="NEO4J_USER")
    neo4j_password: str = Field(default="memoraidev", validation_alias="NEO4J_PASSWORD")
    neo4j_database: str = Field(default="neo4j", validation_alias="NEO4J_DATABASE")

    redis_url: str = Field(default="redis://127.0.0.1:6380/0", validation_alias="REDIS_URL")
    ingestion_queue: str = Field(default="memorai-ingestion", validation_alias="INGESTION_QUEUE")

    embedding_dim: int = Field(default=256, validation_alias="EMBEDDING_DIM")

    #: Optional allow-list of source ids this deployment will ingest from.
    #: Empty means every registered connector is enabled -- a deployment that
    #: wants to narrow that says so explicitly, and registering a connector
    #: stays a one-module change.
    enabled_sources: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias="ENABLED_SOURCES"
    )

    #: Directory holding ChatGPT data exports, one per owner (see
    #: connectors/chatgpt.py for the layout). There is no conversation-history
    #: API to authorise against, so the file is the only way in.
    chatgpt_export_dir: str | None = Field(
        default=None, validation_alias="CHATGPT_EXPORT_DIR"
    )
    #: Whether ChatGPT transcripts are sealed in the enclave before storage.
    #: Defaults to true: a ChatGPT history is an undifferentiated stream of
    #: medical, legal, financial and work questions, there is no reliable way
    #: to tell which conversation is which, and the two errors are not
    #: symmetric -- a needless seal costs one gateway round trip, while a
    #: missed one writes the transcript into Neo4j in the clear, where the
    #: operator can read it (see the README's confidentiality model).
    chatgpt_sensitive: bool = Field(default=True, validation_alias="CHATGPT_SENSITIVE")

    anthropic_api_key: str | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    extraction_model: str = Field(default="claude-sonnet-5", validation_alias="EXTRACTION_MODEL")
    embedding_model: str = Field(default="voyage-3", validation_alias="EMBEDDING_MODEL")

    walrus_publisher_url: str | None = Field(default=None, validation_alias="WALRUS_PUBLISHER_URL")
    walrus_aggregator_url: str | None = Field(
        default=None, validation_alias="WALRUS_AGGREGATOR_URL"
    )

    @field_validator("enabled_sources", mode="before")
    @classmethod
    def _split_csv(cls, value):
        # pydantic-settings would otherwise demand JSON for a list-typed env var.
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @property
    def is_mock(self) -> bool:
        return self.mode != "live"

    # `mode` conflates three independent choices: which connector
    # implementation runs, which extractor, and which embedder. Keeping them
    # welded together means validating a real connector against real data
    # requires an LLM key for extraction, which has nothing to do with
    # reading a file -- so each axis can be overridden on its own, and
    # "auto" keeps the single-switch behaviour as the default.
    def _resolve(self, override: str, live_value: str, mock_value: str) -> str:
        if override != "auto":
            return override
        return live_value if self.mode == "live" else mock_value

    @property
    def use_fixture_connectors(self) -> bool:
        """Whether a connector with a fixture implementation should use it."""
        return self._resolve(self.connector_fixtures, "never", "auto") != "never"

    @property
    def use_llm_extractor(self) -> bool:
        return self._resolve(self.extractor, "llm", "mock") == "llm"

    @property
    def use_real_embedder(self) -> bool:
        return self._resolve(self.embedder, "real", "fake") == "real"

    def source_enabled(self, source: str) -> bool:
        return not self.enabled_sources or source in self.enabled_sources


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
