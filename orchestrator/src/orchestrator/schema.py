"""Pydantic mirror of ``shared/src/memory.rs``.

Field names and enum values are identical on the wire in both directions;
the Rust side uses ``#[serde(rename_all = "snake_case")]`` throughout and
these models must not drift from it. ``tests/test_schema_parity.py`` checks
the two definitions against each other.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .enums import AffectTone, ClaimStatus, EntityKind, FulfillmentStatus, SourceId
from .permissions import ObjectAcl

__all__ = [
    "Affect",
    "AffectTone",
    "Candidate",
    "Citation",
    "Claim",
    "ClaimStatus",
    "Commitment",
    "EncryptedContentRef",
    "Entity",
    "EntityKind",
    "Event",
    "FulfillmentStatus",
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
    #: What the store holds: a Quilt, or a standalone blob.
    blob_id: str | None = None
    #: This body within that batch; ``None`` when stored on its own. ADR 0008.
    patch_id: str | None = None
    byte_len: int


class Affect(BaseModel):
    """The affective facet of an ``Event``: what register its content sits in.

    A facet rather than a node type, for the same reason ``Commitment`` is one:
    it is a property of something already stored, and a parallel node type would
    duplicate the provenance and ACL machinery that already governs it.

    Deliberately has no free-text field of any kind.
    """

    tone: AffectTone
    #: How strongly, in 0.0..=1.0. Separate from ``tone`` because "mildly
    #: frustrated" and "furious" are the same register and want different
    #: ordering; not separate enough to deserve its own axis.
    intensity: float = 0.5
    confidence: float = 0.5
    #: Which extractor decided. Same contract as ``Provenance.derived_by``: an
    #: affect label is a derived claim about content, and a reader is entitled
    #: to know what derived it.
    detected_by: str


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
    #: Sits next to ``encrypted_content`` because together they answer "what kind
    #: of thing is in that blob" -- the question the blob store itself must never
    #: be able to answer. See ADR 0009.
    affect: Affect | None = None
    provenance: Provenance
    acl: ObjectAcl


class Commitment(BaseModel):
    """The commitment facet of a ``Claim``: someone owes something.

    A facet rather than a node type because a commitment is a claim in every
    respect that matters -- it can be superseded ("actually Bob will"),
    contradicted and reconciled, which is machinery the resolver already has.
    """

    owed_by_entity_id: str
    #: Optional: plenty of commitments are to oneself.
    owed_to_entity_id: str | None = None
    #: Optional: plenty of commitments have no deadline.
    due_at_ms: int | None = None
    fulfillment: FulfillmentStatus = FulfillmentStatus.OPEN
    #: When fulfillment last moved off ``OPEN``.
    settled_at_ms: int | None = None


class Claim(BaseModel):
    id: str
    owner_id: str
    statement: str
    subject_entity_ids: list[str] = Field(default_factory=list)
    status: ClaimStatus = ClaimStatus.ACTIVE
    supersedes: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    reconciled_into: str | None = None
    #: Everything above is the epistemic axis; this is the lifecycle one.
    commitment: Commitment | None = None
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
