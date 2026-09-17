from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    anthropic_api_key: str | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    extraction_model: str = Field(default="claude-sonnet-5", validation_alias="EXTRACTION_MODEL")
    embedding_model: str = Field(default="voyage-3", validation_alias="EMBEDDING_MODEL")

    walrus_publisher_url: str | None = Field(default=None, validation_alias="WALRUS_PUBLISHER_URL")
    walrus_aggregator_url: str | None = Field(
        default=None, validation_alias="WALRUS_AGGREGATOR_URL"
    )

    @property
    def is_mock(self) -> bool:
        return self.mode != "live"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
