from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import AliasChoices, Field, field_validator, model_validator
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

    #: Must match the embedder's actual output width -- the Neo4j vector index is
    #: built from this value, so a mismatch makes every write silently unindexed.
    #: `verify_dim` checks it at startup and `apply_migrations` recreates the index
    #: when it changes. 384 is bge-small-en-v1.5; the hashed-token mock follows
    #: whatever this says.
    embedding_dim: int = Field(default=384, validation_alias="EMBEDDING_DIM")

    #: Optional allow-list of source ids this deployment will ingest from.
    #: Empty means every registered connector is enabled -- a deployment that
    #: wants to narrow that says so explicitly, and registering a connector
    #: stays a one-module change.
    enabled_sources: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias="ENABLED_SOURCES"
    )

    #: Optional allow-list of tool ids this deployment will run. Empty (the default)
    #: means every registered tool, mirroring ENABLED_SOURCES. Narrowing here is how
    #: a deployment switches off outbound fetching entirely.
    enabled_tools: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias="ENABLED_TOOLS"
    )

    #: Bounds on one agent session (ADR 0016). Guards, not tuning.
    #:
    #: 400 blocks and not 660: `MAX_PATCHES_PER_QUILT` is 660 in
    #: `storage/blobs.py`, and a session that overran it would silently split
    #: across two Quilts. Correct for a backfill, wrong for a thing that is
    #: supposed to be one coherent context, so the session cap sits below the
    #: storage cap rather than on it.
    agent_session_max_blocks: int = Field(
        default=400, validation_alias="AGENT_SESSION_MAX_BLOCKS", gt=0
    )
    #: Per block, and a block over it is refused rather than truncated: a
    #: truncated scratchpad is one that silently lost the part the decision
    #: turned on.
    agent_session_max_bytes: int = Field(
        default=2_000_000, validation_alias="AGENT_SESSION_MAX_BYTES", gt=0
    )
    #: Clamped by the grant's own expiry, never extending past it.
    agent_session_ttl_secs: int = Field(
        default=3600, validation_alias="AGENT_SESSION_TTL_SECS", gt=0
    )

    #: Limits on fetching a page the person referred to. All three are guards rather
    #: than tuning: a body cap because Content-Length is a claim and not a fact, a
    #: redirect limit because the usual SSRF is a public URL that redirects to a
    #: private one, and a timeout because a hostile endpoint that never finishes is
    #: free denial of service. See tools/fetch_url.py.
    fetch_timeout_secs: float = Field(default=15.0, validation_alias="FETCH_TIMEOUT_SECS", gt=0)
    fetch_max_bytes: int = Field(default=2_000_000, validation_alias="FETCH_MAX_BYTES", gt=0)
    fetch_max_redirects: int = Field(default=3, validation_alias="FETCH_MAX_REDIRECTS", ge=0)
    #: Whether an utterance containing a URL causes that URL to be fetched. Off by
    #: default: it reaches the open web on the person's behalf, which should be an
    #: explicit choice rather than something a fresh checkout does.
    enrich_from_urls: bool = Field(default=False, validation_alias="ENRICH_FROM_URLS")
    #: Whether a new entity name may be folded into one already stored. On by
    #: default, unlike enrichment: this changes nothing about what the service
    #: reaches out to, only whether the graph joins up names that mean the same
    #: thing, and a record that silently keeps two of every entity is the
    #: behaviour worth needing a flag to get back. Off is for a deployment that
    #: would rather audit duplicates than trust a rule.
    canonicalise_entities: bool = Field(
        default=True, validation_alias="CANONICALISE_ENTITIES"
    )
    #: How many of an owner's entities are considered as merge targets, most
    #: recently seen first. A real bound: past it an entity nobody has mentioned
    #: lately stops being a merge target and a duplicate is created instead,
    #: which is the correct direction to fail in.
    canonicalise_max_entities: int = Field(
        default=2_000, validation_alias="CANONICALISE_MAX_ENTITIES", gt=0
    )
    #: How many pages one ingestion run may fetch. A note with forty links is a
    #: reading list, not forty things to go and read, and an unbounded fetch loop
    #: driven by text someone else may have written is the shape of an amplification
    #: attack.
    enrich_max_pages: int = Field(default=3, validation_alias="ENRICH_MAX_PAGES", ge=0)
    #: How much of a fetched page is read. A full Wikipedia article is ~24k characters
    #: of text, which exceeded the provider's request limit outright on the first live
    #: run. Reference pages front-load their definitions, so the opening is where the
    #: answer to "what is this" lives; the rest is history, criticism and navigation.
    #: The stored event body is truncated to the same budget, so what is kept is
    #: exactly what the extractor saw.
    extract_page_max_chars: int = Field(
        default=8_000, validation_alias="EXTRACT_PAGE_MAX_CHARS", gt=0
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

    #: The LLM used for extraction, over an OpenAI-compatible `/chat/completions`
    #: API. The dependency is the API shape, not the vendor -- Groq, OpenAI,
    #: Together and a local vLLM all speak it -- so switching provider is this
    #: URL plus a model name.
    llm_base_url: str = Field(
        default="https://api.groq.com/openai/v1", validation_alias="LLM_BASE_URL"
    )
    extraction_model: str = Field(
        default="openai/gpt-oss-120b", validation_alias="EXTRACTION_MODEL"
    )
    llm_timeout_secs: float = Field(default=60.0, validation_alias="LLM_TIMEOUT_SECS", gt=0)
    #: Rate limits are the normal case for a backfill rather than an exception --
    #: a provider's per-minute token budget is smaller than one person's export --
    #: so the extractor retries 429 and 5xx, honouring the delay the provider
    #: states. This caps how long it keeps trying one record.
    llm_max_attempts: int = Field(default=6, validation_alias="LLM_MAX_ATTEMPTS", ge=1)

    #: Read from the environment by preference. `GROQ_API_KEY` is accepted as the
    #: provider-specific name people actually have set.
    llm_api_key: str | None = Field(
        default=None, validation_alias=AliasChoices("LLM_API_KEY", "GROQ_API_KEY")
    )
    #: A file holding the key instead, which is how a key ends up next to a
    #: checkout in practice. Read at settings time so the secret is never an
    #: argument on a command line or a row in a process list. `.gitignore` covers
    #: the obvious filenames; a real deployment uses the env var or a secret
    #: manager and leaves this unset.
    llm_api_key_file: str | None = Field(
        default="api_key.txt", validation_alias="LLM_API_KEY_FILE"
    )
    #: A fastembed model name. Local ONNX on CPU, no key. Changing it almost
    #: certainly changes EMBEDDING_DIM too.
    embedding_model: str = Field(
        default="BAAI/bge-small-en-v1.5", validation_alias="EMBEDDING_MODEL"
    )

    #: Encrypt the resolved record's text at rest (ADR 0010). Needs a reachable
    #: gateway and an owner session, because the key never leaves the enclave --
    #: every seal and unseal is a round trip into the TEE. Default off while the
    #: smoke script and the eval run without a gateway; a deployment that holds
    #: real memory turns it on. There is deliberately no automatic fallback: if
    #: this is on and the gateway is unreachable, ingestion fails rather than
    #: quietly writing plaintext.
    encrypt_content_at_rest: bool = Field(
        default=False, validation_alias="ENCRYPT_CONTENT_AT_REST"
    )

    #: Where sealed ciphertext is written when Walrus is not configured. The
    #: bytes arrive already encrypted by the enclave, so this directory holds
    #: no plaintext -- but it holds the *only* copy of a sensitive body, so it
    #: belongs on storage that is backed up. See ADR 0002.
    blob_store_dir: str = Field(default=".local/blobs", validation_alias="BLOB_STORE_DIR")

    walrus_publisher_url: str | None = Field(default=None, validation_alias="WALRUS_PUBLISHER_URL")
    walrus_aggregator_url: str | None = Field(
        default=None, validation_alias="WALRUS_AGGREGATOR_URL"
    )

    #: Half-life of the retrieval recency term, in days. See ADR 0003: the
    #: old constant was 30 days applied as a plain exponential, which is a
    #: 1/e point rather than a half-life and scored a year-old decision at
    #: ~0 -- backwards for a record whose signature read is "why did this
    #: change". Tunable because the right value is an empirical question the
    #: eval harness answers, not a constant to be argued about.
    recency_half_life_days: float = Field(
        default=180.0, validation_alias="RECENCY_HALF_LIFE_DAYS", gt=0
    )
    #: Hybrid ranking weights. Normalised at use, so these are ratios.
    semantic_weight: float = Field(default=0.6, validation_alias="SEMANTIC_WEIGHT", ge=0)
    recency_weight: float = Field(default=0.15, validation_alias="RECENCY_WEIGHT", ge=0)
    proximity_weight: float = Field(default=0.25, validation_alias="PROXIMITY_WEIGHT", ge=0)

    @model_validator(mode="after")
    def _load_key_from_file(self):
        """Falls back to the key file when no key is in the environment.

        After the env var, never over it: an explicitly exported key is the more
        deliberate of the two, and a stale file silently winning would be a bad
        afternoon.
        """
        if self.llm_api_key or not self.llm_api_key_file:
            return self
        path = Path(self.llm_api_key_file)
        if not path.is_absolute():
            # Relative to the repo root rather than the working directory, so the
            # orchestrator finds it whether it was started from `orchestrator/`
            # or from the top.
            for base in (Path.cwd(), *Path(__file__).resolve().parents):
                candidate = base / path
                if candidate.is_file():
                    path = candidate
                    break
        try:
            key = path.read_text().strip()
        except OSError:
            return self
        if key:
            object.__setattr__(self, "llm_api_key", key)
        return self

    @field_validator("enabled_sources", "enabled_tools", mode="before")
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

    def tool_enabled(self, tool: str) -> bool:
        return not self.enabled_tools or tool in self.enabled_tools


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
