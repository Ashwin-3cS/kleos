"""Wire-level enums shared by the memory schema and the permission model.

These live in their own module only because Rust tolerates the
``memory.rs`` <-> ``permissions.rs`` import cycle and Python does not; the
values are exactly the ``snake_case`` serde representations used on the
Rust side.
"""

from __future__ import annotations

from enum import StrEnum


class SourceKind(StrEnum):
    GOOGLE = "google"
    GITHUB = "github"
    MOCK = "mock"
    MANUAL = "manual"


class EntityKind(StrEnum):
    PERSON = "person"
    PROJECT = "project"
    ARTIFACT = "artifact"
    ORGANIZATION = "organization"
    TOPIC = "topic"


class ClaimStatus(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    CONTRADICTED = "contradicted"
    RECONCILED = "reconciled"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    PERSONAL = "personal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _SENSITIVITY_RANK[self]


_SENSITIVITY_RANK = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.PERSONAL: 1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.RESTRICTED: 3,
}


class DenyReason(StrEnum):
    WRONG_OWNER = "wrong_owner"
    GRANT_EXPIRED = "grant_expired"
    AGENT_REVOKED = "agent_revoked"
    SOURCE_NOT_IN_SCOPE = "source_not_in_scope"
    ENTITY_KIND_NOT_IN_SCOPE = "entity_kind_not_in_scope"
    OUTSIDE_TIME_WINDOW = "outside_time_window"
    TOO_SENSITIVE = "too_sensitive"
