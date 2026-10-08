"""Which identity in an agent's request is actually authenticated.

Two identities arrive with every grant, and only one of them means anything.
`Scope.agent_id` is a string the owner typed into a scope file before running
`kleos-device sign`; nothing checks it, two agents handed the same file are
indistinguishable, and one agent handed two files looks like two agents. The
signing device key is different: the gateway looked it up among the owner's
registered keys and verified the signature against it.

Attribution -- "device 1 decided this" -- rests entirely on the second, so these
tests hold that the orchestrator receives it and never substitutes a guess for it.
See ADR 0016.
"""

from __future__ import annotations

import json

import httpx
import pytest

from orchestrator.gateway_client import GatewayClient, GatewayError
from orchestrator.storage.reads import grant_fingerprint

SCOPE = {
    "agent_id": "claude-code",
    "owner_id": "owner-1",
    "sources": ["mock"],
    "entity_kinds": ["person", "project"],
    "not_before_ms": None,
    "not_after_ms": None,
    "max_sensitivity": "personal",
    "expires_at_ms": None,
}


def _client(handler) -> GatewayClient:
    client = GatewayClient("http://gateway.invalid")
    client._http.close()
    client._http = httpx.Client(
        base_url="http://gateway.invalid", transport=httpx.MockTransport(handler)
    )
    return client


def _responder(payload: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/memory/scope/introspect"
        assert json.loads(request.content)["grant_token"]
        return httpx.Response(200, json=payload)

    return handler


def test_introspect_grant_reports_the_signing_device() -> None:
    gateway = _client(_responder({"active": True, "scope": SCOPE, "key_id": "3f9adead1c"}))
    resolved = gateway.introspect_grant("grant-token-1")

    assert resolved.device_id == "3f9adead1c"
    assert resolved.scope.agent_id == "claude-code"
    assert resolved.grant_fp == grant_fingerprint("grant-token-1")


def test_the_device_is_never_guessed_from_the_label() -> None:
    """A gateway that does not report a key id yields an empty device, not the
    agent label and not a derived string. A fabricated device id would be
    indistinguishable from an authenticated one in every record that stores it,
    which is worse than a missing one."""
    gateway = _client(_responder({"active": True, "scope": SCOPE}))
    resolved = gateway.introspect_grant("grant-token-1")

    assert resolved.device_id == ""
    assert resolved.scope.agent_id == "claude-code"


def test_the_same_label_on_two_devices_stays_two_devices() -> None:
    """The collision `agent_id` permits by design must not survive into what the
    orchestrator records."""
    seen = set()
    for key_id in ("device-one", "device-two"):
        gateway = _client(_responder({"active": True, "scope": SCOPE, "key_id": key_id}))
        resolved = gateway.introspect_grant(f"token-{key_id}")
        assert resolved.scope.agent_id == "claude-code"
        seen.add(resolved.device_id)

    assert seen == {"device-one", "device-two"}


def test_an_inactive_grant_resolves_to_nothing() -> None:
    gateway = _client(_responder({"active": False}))
    with pytest.raises(GatewayError, match="not active"):
        gateway.introspect_grant("expired")


def test_introspect_scope_still_answers_for_the_paths_that_only_need_a_scope() -> None:
    """Kept as a wrapper so adding the device to one read path is not a change to
    all four at once -- and so every existing test stub keeps working."""
    gateway = _client(_responder({"active": True, "scope": SCOPE, "key_id": "3f9adead1c"}))
    assert gateway.introspect_scope("grant-token-1").owner_id == "owner-1"
