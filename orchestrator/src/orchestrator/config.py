from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    mode: str = Field(default="mock", validation_alias="ORCHESTRATOR_MODE")

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

    def source_enabled(self, source: str) -> bool:
        return not self.enabled_sources or source in self.enabled_sources


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
