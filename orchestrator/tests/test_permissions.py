from __future__ import annotations

from orchestrator.enums import DenyReason, EntityKind, MemoryKind, Sensitivity
from orchestrator.permissions import (
    ObjectAcl,
    Scope,
    WriteIntent,
    evaluate,
    evaluate_action,
    evaluate_unseal,
    evaluate_write,
    permits,
    permits_write,
)


def acl(**overrides) -> ObjectAcl:
    base = dict(
        owner_id="owner-1",
        sources=["mock"],
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
        sources=["mock"],
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


# -- writing, unsealing, acting -----------------------------------------
#
# Three capabilities an agent can be granted, each its own axis and each off by
# default. The Rust side holds the same properties; these are the mirror, and
# `test_schema_parity.py` is what keeps the two from drifting apart.


def intent(**overrides) -> WriteIntent:
    base = dict(
        owner_id="owner-1",
        source="agent",
        entity_kinds=[EntityKind.PROJECT],
        sensitivity=Sensitivity.PERSONAL,
        memory_kind=MemoryKind.EPISODIC,
    )
    return WriteIntent(**{**base, **overrides})


def writer(**overrides) -> Scope:
    base = dict(
        may_write=True,
        write_sources=["agent"],
        memory_kinds=[MemoryKind.EPISODIC],
    )
    return scope(**{**base, **overrides})


def test_a_scope_with_no_capabilities_grants_none_of_them():
    """The one test that fails if a capability is ever added with a permissive
    default."""
    s = scope()
    assert s.may_write is False
    assert s.may_unseal is False
    assert s.may_supersede_owner is False
    assert s.may_act is False
    assert s.write_sources == []
    assert s.memory_kinds == []
    assert s.act_actions == []
    assert not permits_write(s, intent(), 2_000)
    assert not evaluate_unseal(s, acl(), 2_000).allowed
    assert not evaluate_action(s, "anything", 2_000).allowed


def test_an_old_grant_is_read_only():
    """A grant signed before these fields existed must still resolve, and must
    be read-only. The signature covers the bytes as signed, and there is no way
    to reissue a grant without the owner's device."""
    old = Scope.model_validate(
        {
            "agent_id": "agent-1",
            "owner_id": "owner-1",
            "sources": ["mock"],
            "entity_kinds": ["project"],
            "max_sensitivity": "personal",
        }
    )
    assert permits(old, acl(), 2_000), "reads must keep working"
    assert evaluate_write(old, intent(), 2_000).reason is DenyReason.WRITE_NOT_PERMITTED
    assert evaluate_unseal(old, acl(), 2_000).reason is DenyReason.UNSEAL_NOT_PERMITTED


def test_may_write_alone_says_nothing_about_what_it_may_write_as():
    s = scope(may_write=True, memory_kinds=[MemoryKind.EPISODIC])
    assert evaluate_write(s, intent(), 2_000).reason is DenyReason.WRITE_SOURCE_NOT_IN_SCOPE
    assert permits_write(writer(), intent(), 2_000)


def test_read_scope_does_not_confer_write_scope():
    """An agent permitted to read the person's typed notes must not thereby be
    able to write a claim that claims to be one."""
    s = writer(sources=["text"])
    assert (
        evaluate_write(s, intent(source="text"), 2_000).reason
        is DenyReason.WRITE_SOURCE_NOT_IN_SCOPE
    )


def test_a_kind_outside_the_scope_cannot_be_written():
    s = writer()
    assert (
        evaluate_write(s, intent(memory_kind=MemoryKind.PROCEDURAL), 2_000).reason
        is DenyReason.MEMORY_KIND_NOT_IN_SCOPE
    )


def test_a_tacit_claim_cannot_be_written_below_its_floor():
    """A tacit claim is an inference about a person rather than something they
    said, so labelling one may only narrow who can read it."""
    s = writer(memory_kinds=[MemoryKind.TACIT], max_sensitivity=Sensitivity.CONFIDENTIAL)
    too_open = intent(memory_kind=MemoryKind.TACIT, sensitivity=Sensitivity.PERSONAL)
    assert evaluate_write(s, too_open, 2_000).reason is DenyReason.TOO_SENSITIVE

    at_floor = intent(memory_kind=MemoryKind.TACIT, sensitivity=Sensitivity.CONFIDENTIAL)
    assert permits_write(s, at_floor, 2_000)


def test_no_kind_lowers_the_floor_below_personal():
    for kind in MemoryKind:
        assert kind.sensitivity_floor.rank >= Sensitivity.PERSONAL.rank


def test_an_agent_cannot_write_above_its_own_ceiling():
    """A claim above the writer's ceiling would be invisible to the agent that
    asserted it, and would put material in the record no grant accounts for."""
    assert (
        evaluate_write(writer(), intent(sensitivity=Sensitivity.RESTRICTED), 2_000).reason
        is DenyReason.TOO_SENSITIVE
    )


def test_a_write_for_another_owner_is_refused():
    assert (
        evaluate_write(writer(), intent(owner_id="owner-2"), 2_000).reason
        is DenyReason.WRONG_OWNER
    )


def test_reading_an_object_does_not_confer_unsealing_it():
    assert permits(scope(), acl(), 2_000)
    assert evaluate_unseal(scope(), acl(), 2_000).reason is DenyReason.UNSEAL_NOT_PERMITTED
    assert evaluate_unseal(scope(may_unseal=True), acl(), 2_000).allowed


def test_may_unseal_does_not_bypass_the_read_check():
    """An object the grant cannot see stays unseen, and comes back with the
    read check's own reason rather than an unseal reason."""
    s = scope(may_unseal=True, sources=[])
    assert evaluate_unseal(s, acl(), 2_000).reason is DenyReason.SOURCE_NOT_IN_SCOPE


def test_an_action_must_be_named_in_the_grant():
    assert evaluate_action(scope(), "gmail.send", 2_000).reason is DenyReason.ACTION_NOT_PERMITTED
    assert (
        evaluate_action(scope(may_act=True), "gmail.send", 2_000).reason
        is DenyReason.ACTION_NOT_PERMITTED
    ), "may_act alone names no action"

    granted = scope(may_act=True, act_actions=["gmail.send"])
    assert evaluate_action(granted, "gmail.send", 2_000).allowed
    assert not evaluate_action(granted, "gmail.delete", 2_000).allowed


def test_an_expired_grant_writes_and_acts_no_more_than_it_reads():
    s = writer(expires_at_ms=1_500, may_act=True, act_actions=["gmail.send"])
    assert evaluate_write(s, intent(), 2_000).reason is DenyReason.GRANT_EXPIRED
    assert evaluate_action(s, "gmail.send", 2_000).reason is DenyReason.GRANT_EXPIRED
