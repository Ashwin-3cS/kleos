"""Pydantic mirror of ``shared/src/memory.rs``.

Field names and enum values are identical on the wire in both directions;
the Rust side uses ``#[serde(rename_all = "snake_case")]`` throughout and
these models must not drift from it. ``tests/test_schema_parity.py`` checks
the two definitions against each other.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .enums import ClaimStatus, EntityKind, SourceId
from .permissions import ObjectAcl

__all__ = [
    "Candidate",
    "Citation",
    "Claim",
    "ClaimStatus",
    "EncryptedContentRef",
    "Entity",
    "EntityKind",
    "Event",
    "MemoryNode",
    "Provenance",
    "RawRecord",
    "SourceId",
    "SourceRef",
]


class SourceRef(BaseModel):
    connector: SourceId
    external_id: str
    url: str | None = None
    #: when the thing happened
    occurred_at_ms: int
    #: when we learned about it
    ingested_at_ms: int


class Citation(BaseModel):
    event_id: str
    source: SourceRef
    quote: str | None = None


class Provenance(BaseModel):
    citations: list[Citation] = Field(default_factory=list)
    derived_by: str
    confidence: float = 1.0
    created_at_ms: int


class EncryptedContentRef(BaseModel):
    key_id: str
    scheme: str
    #: Walrus blob id once Walrus is wired; ``None`` until then.
    blob_id: str | None = None
    byte_len: int


class Entity(BaseModel):
    id: str
    owner_id: str
    kind: EntityKind
    name: str
    aliases: list[str] = Field(default_factory=list)
    first_seen_at_ms: int
    last_seen_at_ms: int
    provenance: Provenance
    acl: ObjectAcl


class Event(BaseModel):
    id: str
    owner_id: str
    summary: str
    body: str | None = None
    entity_ids: list[str] = Field(default_factory=list)
    source: SourceRef
    encrypted_content: EncryptedContentRef | None = None
    provenance: Provenance
    acl: ObjectAcl


class Claim(BaseModel):
    id: str
    owner_id: str
    statement: str
    subject_entity_ids: list[str] = Field(default_factory=list)
    status: ClaimStatus = ClaimStatus.ACTIVE
    supersedes: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    reconciled_into: str | None = None
    asserted_at_ms: int
    provenance: Provenance
    acl: ObjectAcl


MemoryNode = Entity | Event | Claim


class RawRecord(BaseModel):
    """One unit of raw source activity, as a connector yields it.

    Not part of the Rust schema: raw records never cross the enclave
    boundary as a structured object -- only their sensitive bytes do, via
    the seal endpoint.
    """

    external_id: str
    connector: SourceId
    occurred_at_ms: int
    title: str
    body: str
    url: str | None = None
    #: Raw body is sealed in the enclave before storage when this is set.
    sensitive: bool = False
    participants: list[str] = Field(default_factory=list)
    #: Source-specific fields that do not fit the common shape (labels, repo,
    #: thread id, ...). Carried through extraction untouched so a richer
    #: connector does not need a schema change; nothing downstream interprets
    #: it generically.
    metadata: dict[str, Any] = Field(default_factory=dict)


class Candidate(BaseModel):
    """Extractor output, before resolution against what is already stored."""

    entities: list[Entity] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
