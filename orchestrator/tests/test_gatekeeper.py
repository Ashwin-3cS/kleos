"""Who computes the verdict, and what happens when it cannot be asked (ADR 0028).

The interesting tests here are the refusals. A permission check that degrades
when the thing it asks is unreachable is a permission check an operator obtains
by turning that thing off, so "could not be decided" has to behave like a
closed door and not like an allow.
"""

from __future__ import annotations

import pytest

from orchestrator.enums import EntityKind, MemoryKind, Sensitivity
from orchestrator.gatekeeper import Gatekeeper, GatekeeperUnavailable
from orchestrator.permissions import ObjectAcl, Scope, WriteIntent

OWNER = "owner-gatekeeper"
GRANT = "a-grant-token"


def _scope(**overrides) -> Scope:
    base = {
        "agent_id": "agent-under-test",
        "owner_id": OWNER,
        "sources": ["mock"],
        "entity_kinds": [EntityKind.PROJECT],
        "max_sensitivity": Sensitivity.CONFIDENTIAL,
        "may_write": True,
        "write_sources": ["agent"],
        "memory_kinds": [MemoryKind.EPISODIC],
    }
    return Scope.model_validate({**base, **overrides})


def _acl(**overrides) -> ObjectAcl:
    base = {
        "owner_id": OWNER,
        "sources": ["mock"],
        "sensitivity": Sensitivity.PERSONAL,
        "entity_kinds": [EntityKind.PROJECT],
        "occurred_at_ms": 1_700_000_000_000,
    }
    return ObjectAcl.model_validate({**base, **overrides})


class _Gateway:
    """Answers like the enclave, or fails like an unreachable one."""

    def __init__(self, verdicts=None, fail: bool = False, drop: int = 0) -> None:
        self.verdicts = verdicts
        self.fail = fail
        self.drop = drop
        self.calls: list[dict] = []

    def evaluate(self, grant_token: str, objects: list[dict]) -> dict:
        self.calls.append({"grant_token": grant_token, "objects": objects})
        if self.fail:
            raise RuntimeError("enclave unreachable")
        verdicts = self.verdicts
        if verdicts is None:
            verdicts = [{"id": o["id"], "allowed": True, "reason": None} for o in objects]
        return {"verdicts": verdicts[self.drop :], "now_ms": 1_700_000_000_000}

    def evaluate_write(self, grant_token: str, intent: dict) -> dict:
        self.calls.append({"grant_token": grant_token, "intent": intent})
        if self.fail:
            raise RuntimeError("enclave unreachable")
        return {"allowed": True, "reason": None, "now_ms": 1_700_000_000_000}


# -- on the host --------------------------------------------------------


def test_on_the_host_it_decides_locally_and_asks_nothing():
    gateway = _Gateway()
    keeper = Gatekeeper(gateway, in_enclave=False)
    verdicts = keeper.evaluate_objects(_scope(), [("a", _acl())])
    assert verdicts["a"].allowed
    assert gateway.calls == [], "the host path must not need a gateway at all"
    assert keeper.where == "host"


def test_on_the_host_a_denial_still_carries_its_reason():
    keeper = Gatekeeper(_Gateway(), in_enclave=False)
    # Out of scope by source, which is the cheapest real denial to construct.
    verdicts = keeper.evaluate_objects(_scope(), [("a", _acl(sources=["github"]))])
    assert not verdicts["a"].allowed
    assert verdicts["a"].reason == "source_not_in_scope"


# -- in the enclave -----------------------------------------------------


def test_in_the_enclave_it_sends_acls_and_not_nodes():
    """`evaluate` is decidable from `(scope, acl, now_ms)` alone.

    That property was deliberate from the start and this is what it buys:
    sealed content stays out of a call that has no use for it.
    """
    gateway = _Gateway()
    keeper = Gatekeeper(gateway, in_enclave=True)
    keeper.evaluate_objects(_scope(), [("a", _acl())], grant_token=GRANT)
    sent = gateway.calls[0]
    assert sent["grant_token"] == GRANT
    assert set(sent["objects"][0]) == {"id", "acl"}
    assert "payload" not in sent["objects"][0]
    assert keeper.where == "enclave"


def test_it_never_sends_a_clock():
    """A host that supplies `now_ms` can rewind it.

    Every time-window check and every grant expiry is measured against it, so a
    rewound clock resurrects an expired grant and leaves nothing looking wrong:
    the verdict is correct for the time it was given.
    """
    gateway = _Gateway()
    Gatekeeper(gateway, in_enclave=True).evaluate_objects(
        _scope(), [("a", _acl())], grant_token=GRANT
    )
    assert "now_ms" not in gateway.calls[0]
    assert "now_ms" not in gateway.calls[0]["objects"][0]


def test_the_enclaves_verdict_is_the_one_applied():
    """Including when it disagrees with what the host would have said.

    The host path allows this object. The enclave denies it. The point of the
    route is that the second answer is the one that governs.
    """
    gateway = _Gateway(verdicts=[{"id": "a", "allowed": False, "reason": "too_sensitive"}])
    keeper = Gatekeeper(gateway, in_enclave=True)
    verdict = keeper.evaluate_objects(_scope(), [("a", _acl())], grant_token=GRANT)["a"]
    assert not verdict.allowed
    assert verdict.reason == "too_sensitive"
    # ...and the host, asked the same question, would have allowed it.
    assert Gatekeeper(gateway, in_enclave=False).evaluate_objects(
        _scope(), [("a", _acl())]
    )["a"].allowed


def test_nothing_is_asked_for_an_empty_batch():
    gateway = _Gateway()
    assert Gatekeeper(gateway, in_enclave=True).evaluate_objects(_scope(), []) == {}
    assert gateway.calls == [], "a read that retrieved nothing costs no round trip"


# -- the refusals -------------------------------------------------------


def test_an_unreachable_enclave_refuses_rather_than_falling_back():
    """The test that matters.

    A fallback to the host would be a permission check an operator obtains by
    turning the enclave off. `ENCRYPT_CONTENT_AT_REST` set the precedent:
    ingestion fails rather than quietly writing plaintext.
    """
    keeper = Gatekeeper(_Gateway(fail=True), in_enclave=True)
    with pytest.raises(GatekeeperUnavailable, match="nothing is disclosed"):
        keeper.evaluate_objects(_scope(), [("a", _acl())], grant_token=GRANT)


def test_a_truncated_response_refuses_the_whole_read():
    """Deny-by-default, applied to the transport.

    A missing verdict is the one failure a verdict map cannot represent: read as
    "not denied", a dropped entry becomes an allow. So the response is refused
    outright rather than partly believed.
    """
    gateway = _Gateway(drop=1)
    keeper = Gatekeeper(gateway, in_enclave=True)
    with pytest.raises(GatekeeperUnavailable, match="no verdict for 1 of 2"):
        keeper.evaluate_objects(
            _scope(), [("a", _acl()), ("b", _acl())], grant_token=GRANT
        )


def test_a_missing_grant_token_refuses_rather_than_deciding_here():
    """The call site forgot the token. Guessing is not available: the only other
    option is to decide on the host, which is what this exists to stop."""
    keeper = Gatekeeper(_Gateway(), in_enclave=True)
    with pytest.raises(GatekeeperUnavailable, match="did not pass one"):
        keeper.evaluate_objects(_scope(), [("a", _acl())])


# -- the write gate -----------------------------------------------------


def _intent(**overrides) -> WriteIntent:
    base = {
        "owner_id": OWNER,
        "source": "agent",
        "entity_kinds": [EntityKind.PROJECT],
        "sensitivity": Sensitivity.PERSONAL,
        "memory_kind": MemoryKind.EPISODIC,
    }
    return WriteIntent.model_validate({**base, **overrides})


def test_the_write_gate_decides_locally_when_configured_to():
    keeper = Gatekeeper(_Gateway(), in_enclave=False)
    assert keeper.evaluate_one_write(_scope(), _intent()).allowed
    refused = keeper.evaluate_one_write(_scope(may_write=False), _intent())
    assert not refused.allowed
    assert refused.reason == "write_not_permitted"


def test_the_write_gate_asks_the_enclave_when_configured_to():
    gateway = _Gateway()
    keeper = Gatekeeper(gateway, in_enclave=True)
    assert keeper.evaluate_one_write(_scope(), _intent(), grant_token=GRANT).allowed
    assert gateway.calls[0]["grant_token"] == GRANT
    assert "now_ms" not in gateway.calls[0]["intent"]


def test_an_unreachable_enclave_refuses_the_write():
    keeper = Gatekeeper(_Gateway(fail=True), in_enclave=True)
    with pytest.raises(GatekeeperUnavailable, match="not performed"):
        keeper.evaluate_one_write(_scope(), _intent(), grant_token=GRANT)


# -- what a caller is told ----------------------------------------------


def test_the_api_answers_503_and_not_500_or_403(monkeypatch) -> None:
    """The status has to say which kind of refusal this is.

    403 would tell an agent its scope is too narrow; 500 would read as a bug in
    this service. Both have a client doing the wrong thing next -- re-requesting
    a narrower read, or paging someone.
    """
    from fastapi.testclient import TestClient

    from orchestrator import api as api_module

    @api_module.app.get("/_test/gatekeeper-down", include_in_schema=False)
    def _boom() -> dict:
        raise GatekeeperUnavailable("the enclave could not be asked")

    with TestClient(api_module.app, raise_server_exceptions=False) as client:
        response = client.get("/_test/gatekeeper-down")
    assert response.status_code == 503
    assert response.json()["retryable"] is True
    assert "could not be asked" in response.json()["detail"]
