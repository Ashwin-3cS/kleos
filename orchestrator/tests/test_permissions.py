from __future__ import annotations

from orchestrator.enums import DenyReason, EntityKind, Sensitivity, SourceKind
from orchestrator.permissions import ObjectAcl, Scope, evaluate, permits


def acl(**overrides) -> ObjectAcl:
    base = dict(
        owner_id="owner-1",
        source=SourceKind.MOCK,
        sensitivity=Sensitivity.PERSONAL,
        entity_kinds=[EntityKind.PROJECT],
        occurred_at_ms=1_000,
        denied_agents=[],
    )
    return ObjectAcl(**{**base, **overrides})


def scope(**overrides) -> Scope:
    base = dict(
        agent_id="agent-1",
        owner_id="owner-1",
        sources=[SourceKind.MOCK],
        entity_kinds=[EntityKind.PROJECT],
        max_sensitivity=Sensitivity.PERSONAL,
    )
    return Scope(**{**base, **overrides})


def test_allows_matching_scope():
    assert permits(scope(), acl(), 2_000)


def test_denies_other_owner():
    assert evaluate(scope(owner_id="owner-2"), acl(), 0).reason is DenyReason.WRONG_OWNER


def test_denies_more_sensitive_object():
    decision = evaluate(scope(), acl(sensitivity=Sensitivity.RESTRICTED), 0)
    assert decision.reason is DenyReason.TOO_SENSITIVE


def test_denies_entity_kind_outside_scope():
    decision = evaluate(scope(), acl(entity_kinds=[EntityKind.PROJECT, EntityKind.PERSON]), 0)
    assert decision.reason is DenyReason.ENTITY_KIND_NOT_IN_SCOPE


def test_empty_scope_grants_nothing():
    assert not permits(scope(sources=[]), acl(), 0)


def test_denies_revoked_agent():
    decision = evaluate(scope(), acl(denied_agents=["agent-1"]), 0)
    assert decision.reason is DenyReason.AGENT_REVOKED


def test_denies_expired_grant():
    decision = evaluate(scope(expires_at_ms=1_000), acl(), 1_000)
    assert decision.reason is DenyReason.GRANT_EXPIRED


def test_denies_outside_time_window():
    decision = evaluate(scope(not_before_ms=5_000), acl(), 0)
    assert decision.reason is DenyReason.OUTSIDE_TIME_WINDOW
