"""Query-time permission model, mirroring ``shared/src/permissions.rs``.

The check is pure and total: it decides from ``(scope, acl)`` alone, with no
lookups, so the identical evaluation can later be performed on-chain. The
enforcement point that matters today is the query graph, which runs this per
retrieved candidate before anything reaches an answer.
"""

from __future__ import annotations

import time

from pydantic import BaseModel, Field

from .enums import DenyReason, EntityKind, MemoryKind, Sensitivity, SourceId

__all__ = [
    "DenyReason",
    "ObjectAcl",
    "PermissionDecision",
    "Scope",
    "Sensitivity",
    "WriteIntent",
    "evaluate",
    "evaluate_action",
    "evaluate_unseal",
    "evaluate_write",
    "permits",
    "permits_write",
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
    #: Denormalised here for the same reason everything else is: the check must
    #: be decidable from ``(scope, acl)`` alone, so a scope granting procedures
    #: and not episodes needs the kind here rather than behind a lookup.
    memory_kind: MemoryKind | None = None


class Scope(BaseModel):
    agent_id: str
    owner_id: str
    sources: list[SourceId] = Field(default_factory=list)
    entity_kinds: list[EntityKind] = Field(default_factory=list)
    not_before_ms: int | None = None
    not_after_ms: int | None = None
    max_sensitivity: Sensitivity = Sensitivity.PERSONAL
    expires_at_ms: int | None = None
    # Appended, and every one defaults to false or empty. A grant signed before
    # these existed deserialises as read-only rather than failing to verify --
    # the signature covers the bytes as signed, and there is no way to reissue a
    # grant without the owner's device in hand.
    may_write: bool = False
    #: A separate axis from ``may_write``: one changes the person's record, the
    #: other produces plaintext the operator cannot otherwise read.
    may_unseal: bool = False
    #: Off by default, so an agent's claim contradicts the owner's rather than
    #: replacing it. An agent granted this is a delegate; a fetched page never
    #: is (ADR 0014).
    may_supersede_owner: bool = False
    #: Which sources this agent may write *as* -- deliberately not ``sources``.
    #: Read scope and write scope are not one set.
    write_sources: list[SourceId] = Field(default_factory=list)
    memory_kinds: list[MemoryKind] = Field(default_factory=list)
    #: May it ask the enclave to perform a sensitive action. The agent never
    #: receives the credential; it submits an intent and gets an acknowledgement.
    may_act: bool = False
    act_actions: list[str] = Field(default_factory=list)


class WriteIntent(BaseModel):
    """What an agent proposes to write: the ACL the object *would* carry.

    A write cannot share ``evaluate``'s signature, because there is no
    ``ObjectAcl`` yet -- there is no object. The asymmetry is in the type: reads
    evaluate ``(scope, acl)``, writes evaluate ``(scope, intent)``.
    """

    owner_id: str
    source: SourceId
    entity_kinds: list[EntityKind] = Field(default_factory=list)
    sensitivity: Sensitivity = Sensitivity.PERSONAL
    memory_kind: MemoryKind | None = None


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
    # **The one deliberate exception to deny-by-default here**, and it is on the
    # object side only. A kinded object requires its kind in scope, so an empty
    # ``memory_kinds`` grants no kinded object -- the scope side stays strict.
    # An unkinded object passes any kind scope, which is the exception.
    #
    # It has to be this way round: every claim in every existing database has no
    # kind, so the strict reading would retroactively hide the whole stored
    # graph behind a field nothing has set. Backfilling a kind instead would
    # assert something nothing derived, which is what ADR 0015 refuses in the
    # merge case -- an uncertain case fails towards the recoverable outcome, and
    # a wrong label on a million claims is not recoverable.
    #
    # Narrow on purpose: an exception for *absence*, not for mismatch. A claim
    # labelled tacit is never visible to a scope that did not ask for tacit.
    if acl.memory_kind is not None and acl.memory_kind not in scope.memory_kinds:
        return _deny(DenyReason.MEMORY_KIND_NOT_IN_SCOPE)
    return _ALLOW


def permits(scope: Scope, acl: ObjectAcl, now_ms: int | None = None) -> bool:
    return evaluate(scope, acl, now_ms).allowed


def evaluate_write(
    scope: Scope, intent: WriteIntent, now_ms: int | None = None
) -> PermissionDecision:
    """Pure, total write check. Deny-by-default, like ``evaluate``.

    A sibling function rather than a mode on ``evaluate``. A mode parameter
    would mean every existing call site has to say "read", and the one that
    forgets gets whatever the default is -- a deny-by-default violation waiting
    for someone to add a fifth read path.
    """
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms

    if scope.owner_id != intent.owner_id:
        return _deny(DenyReason.WRONG_OWNER)
    if scope.expires_at_ms is not None and now_ms >= scope.expires_at_ms:
        return _deny(DenyReason.GRANT_EXPIRED)
    if not scope.may_write:
        return _deny(DenyReason.WRITE_NOT_PERMITTED)
    if intent.source not in scope.write_sources:
        return _deny(DenyReason.WRITE_SOURCE_NOT_IN_SCOPE)
    # `all` and empty-denies, exactly as the read check does: an agent writing a
    # claim about a person and a project needs both kinds in scope.
    if not intent.entity_kinds or not all(
        k in scope.entity_kinds for k in intent.entity_kinds
    ):
        return _deny(DenyReason.ENTITY_KIND_NOT_IN_SCOPE)
    # An agent must not write something it could not then read: a claim above its
    # own ceiling would be invisible to the agent that asserted it, and would be
    # a way to put material into the record that no grant accounts for.
    if intent.sensitivity.rank > scope.max_sensitivity.rank:
        return _deny(DenyReason.TOO_SENSITIVE)
    if intent.memory_kind is not None:
        if intent.memory_kind not in scope.memory_kinds:
            return _deny(DenyReason.MEMORY_KIND_NOT_IN_SCOPE)
        if intent.sensitivity.rank < intent.memory_kind.sensitivity_floor.rank:
            return _deny(DenyReason.TOO_SENSITIVE)
    return _ALLOW


def permits_write(scope: Scope, intent: WriteIntent, now_ms: int | None = None) -> bool:
    return evaluate_write(scope, intent, now_ms).allowed


def evaluate_unseal(
    scope: Scope, acl: ObjectAcl, now_ms: int | None = None
) -> PermissionDecision:
    """Whether this grant may turn a sealed body back into plaintext.

    Layered on top of ``evaluate`` rather than folded into it: seeing a resolved
    claim and pulling the raw transcript it was derived from are different
    disclosures, and the body is the one the enclave exists for. An object the
    grant cannot read comes back with the *read* check's reason, so
    ``may_unseal`` is never a way around it.
    """
    decision = evaluate(scope, acl, now_ms)
    if not decision.allowed:
        return decision
    if not scope.may_unseal:
        return _deny(DenyReason.UNSEAL_NOT_PERMITTED)
    return _ALLOW


def evaluate_action(
    scope: Scope, action_id: str, now_ms: int | None = None
) -> PermissionDecision:
    """Whether this grant may ask for one named action.

    No ``ObjectAcl``, because an action is not a stored object. What is checked
    is the capability and the specific id: ``may_act`` alone names no action.
    """
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms

    if scope.expires_at_ms is not None and now_ms >= scope.expires_at_ms:
        return _deny(DenyReason.GRANT_EXPIRED)
    if not scope.may_act or action_id not in scope.act_actions:
        return _deny(DenyReason.ACTION_NOT_PERMITTED)
    return _ALLOW
