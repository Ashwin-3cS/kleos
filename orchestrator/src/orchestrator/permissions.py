"""Query-time permission model, mirroring ``shared/src/permissions.rs``.

The check is pure and total: it decides from ``(scope, acl)`` alone, with no
lookups, so the identical evaluation can later be performed on-chain. The
enforcement point that matters today is the query graph, which runs this per
retrieved candidate before anything reaches an answer.
"""

from __future__ import annotations

import time

from pydantic import BaseModel, Field

from .enums import DenyReason, EntityKind, Sensitivity, SourceId

__all__ = [
    "DenyReason",
    "ObjectAcl",
    "PermissionDecision",
    "Scope",
    "Sensitivity",
    "evaluate",
    "permits",
]


class ObjectAcl(BaseModel):
    owner_id: str
    # Plural: a resolved object can draw on several sources, and a scope
    # covering only one of them must not see it.
    sources: list[SourceId] = Field(default_factory=list)
    sensitivity: Sensitivity = Sensitivity.PERSONAL
    entity_kinds: list[EntityKind] = Field(default_factory=list)
    occurred_at_ms: int
    denied_agents: list[str] = Field(default_factory=list)


class Scope(BaseModel):
    agent_id: str
    owner_id: str
    sources: list[SourceId] = Field(default_factory=list)
    entity_kinds: list[EntityKind] = Field(default_factory=list)
    not_before_ms: int | None = None
    not_after_ms: int | None = None
    max_sensitivity: Sensitivity = Sensitivity.PERSONAL
    expires_at_ms: int | None = None


class PermissionDecision(BaseModel):
    decision: str
    reason: DenyReason | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


_ALLOW = PermissionDecision(decision="allow")


def _deny(reason: DenyReason) -> PermissionDecision:
    return PermissionDecision(decision="deny", reason=reason)


def evaluate(scope: Scope, acl: ObjectAcl, now_ms: int | None = None) -> PermissionDecision:
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms

    if scope.owner_id != acl.owner_id:
        return _deny(DenyReason.WRONG_OWNER)
    if scope.expires_at_ms is not None and now_ms >= scope.expires_at_ms:
        return _deny(DenyReason.GRANT_EXPIRED)
    if scope.agent_id in acl.denied_agents:
        return _deny(DenyReason.AGENT_REVOKED)
    # `all`, not `any`: an object derived from two sources is only visible to
    # a scope covering both, or the resolved statement leaks the un-granted
    # source's contribution. Empty denies, as everywhere else here.
    if not acl.sources or not all(s in scope.sources for s in acl.sources):
        return _deny(DenyReason.SOURCE_NOT_IN_SCOPE)
    # Deny by default: an object with no entity kinds, or a scope with none,
    # grants nothing rather than everything.
    if not acl.entity_kinds or not all(k in scope.entity_kinds for k in acl.entity_kinds):
        return _deny(DenyReason.ENTITY_KIND_NOT_IN_SCOPE)
    if scope.not_before_ms is not None and acl.occurred_at_ms < scope.not_before_ms:
        return _deny(DenyReason.OUTSIDE_TIME_WINDOW)
    if scope.not_after_ms is not None and acl.occurred_at_ms > scope.not_after_ms:
        return _deny(DenyReason.OUTSIDE_TIME_WINDOW)
    if acl.sensitivity.rank > scope.max_sensitivity.rank:
        return _deny(DenyReason.TOO_SENSITIVE)
    return _ALLOW


def permits(scope: Scope, acl: ObjectAcl, now_ms: int | None = None) -> bool:
    return evaluate(scope, acl, now_ms).allowed
