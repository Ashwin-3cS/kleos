"""Asking the enclave to do something, and what must never come back.

The rule the broker exists for: an agent submits an intent and receives an
acknowledgement. It never receives the credential the action needed, and never
the material that credential unlocks.

The orchestrator's half is thin on purpose -- resolve the grant, hand the intent
over, record the attempt -- so most of what is worth testing here is the
recording, and the fact that the thin layer does not quietly become a second
gate or a second copy of the content.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.gateway_client import ResolvedGrant
from orchestrator.graphs.act import request_action
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope
from orchestrator.storage.actions import args_digest
from orchestrator.storage.reads import grant_fingerprint
from orchestrator.storage.sessions import SessionError

OWNER = "owner-act"
DEVICE = "device-1a2b3c"
TOKEN = "grant-for-acting"

#: What a credential-bearing action would be handling. None of it may appear in
#: the record or in the result.
SECRET_BODY = "the quarterly numbers, which nobody outside should read"
FAKE_REFRESH_TOKEN = "1//0gFAKE-refresh-token-value"


class _Gateway:
    """Stands in for the gateway, which stands in front of the enclave.

    The ack is what the enclave would return. It deliberately does *not* contain
    the credential or the content, because that is the shape under test -- and
    `seen_args` records what crossed, so a test can assert what the orchestrator
    did and did not pass on.
    """

    def __init__(self, scope: Scope, ack: dict) -> None:
        self._scope = scope
        self._ack = ack
        self.calls = 0
        self.seen: list[tuple[str, str, dict]] = []

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scope

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        return ResolvedGrant(
            scope=self._scope,
            device_id=DEVICE,
            grant_fp=grant_fingerprint(grant_token),
        )

    def request_action(self, grant_token: str, action_id: str, args: dict) -> dict:
        self.calls += 1
        self.seen.append((grant_token, action_id, args))
        return dict(self._ack)

    def close(self) -> None:
        pass


def _scope(**overrides) -> Scope:
    base = dict(
        agent_id="claude-code",
        owner_id=OWNER,
        sources=["mock"],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.PERSONAL,
        may_act=True,
        act_actions=["attest.digest"],
    )
    return Scope(**{**base, **overrides})


OK_ACK = {
    "ok": True,
    "action_id": "attest.digest",
    "at_ms": 1_700_000_000_000,
    "digest": "3f9adead1c0f2b77",
    "summary": "attested 8 characters of digest; document is 96 bytes",
    "sealed_ref": None,
    "error": None,
}

REFUSED_ACK = {
    "ok": False,
    "action_id": "google.gmail.send",
    "at_ms": 1_700_000_000_000,
    "digest": "",
    "summary": "action is declared and not wired",
    "sealed_ref": None,
    "error": "action \"google.gmail.send\" is declared and not wired",
}


def _runtime(settings: Settings, ack: dict, **scope_overrides) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    rt.gateway = _Gateway(_scope(**scope_overrides), ack)
    rt.store.wipe_actions(OWNER)
    rt.store.wipe_sessions(OWNER)
    return rt


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = _runtime(settings, OK_ACK)
    yield rt
    rt.store.wipe_actions(OWNER)
    rt.store.wipe_sessions(OWNER)
    rt.close()


# -- the ack ------------------------------------------------------------


def test_an_action_returns_an_ack_and_never_the_credential(runtime: Runtime) -> None:
    """The whole rule, as one assertion. Whatever the action handled, what comes
    back is a digest and a line of summary."""
    result = request_action(
        runtime, TOKEN, "attest.digest", {"digest": "deadbeef", "body": SECRET_BODY}
    )

    assert result.ok
    assert result.digest == "3f9adead1c0f2b77"
    rendered = str(result.as_dict())
    assert SECRET_BODY not in rendered
    assert FAKE_REFRESH_TOKEN not in rendered
    assert "refresh" not in rendered.lower()


def test_the_record_keeps_no_arguments(runtime: Runtime) -> None:
    """An action's arguments are the content it acted on. A log that kept them
    would be a second uncontrolled copy of exactly the material the enclave
    exists to keep out of the operator's hands."""
    request_action(
        runtime, TOKEN, "attest.digest", {"digest": "deadbeef", "body": SECRET_BODY}
    )

    rows = runtime.store._run(
        "MATCH (a:AgentAction {owner_id: $o}) RETURN properties(a) AS props", o=OWNER
    )
    assert rows
    serialised = repr(rows[0]["props"])
    assert SECRET_BODY not in serialised
    assert "deadbeef" not in serialised, "not even the argument values"
    # What is kept instead: a handle, so a repeat is recognisable without being
    # readable.
    assert rows[0]["props"]["args_fp"] == args_digest(
        {"digest": "deadbeef", "body": SECRET_BODY}
    )


def test_the_grant_token_is_never_stored(runtime: Runtime) -> None:
    request_action(runtime, TOKEN, "attest.digest", {"digest": "a"})

    rows = runtime.store._run(
        "MATCH (a:AgentAction {owner_id: $o}) RETURN properties(a) AS props", o=OWNER
    )
    assert TOKEN not in repr(rows[0]["props"])
    assert rows[0]["props"]["grant_fp"] == grant_fingerprint(TOKEN)


def test_the_same_action_twice_is_recognisable_as_a_repeat(runtime: Runtime) -> None:
    """The question an owner reading this log actually has: did it send that
    message once, or forty times?"""
    request_action(runtime, TOKEN, "attest.digest", {"digest": "a"})
    request_action(runtime, TOKEN, "attest.digest", {"digest": "a"})
    request_action(runtime, TOKEN, "attest.digest", {"digest": "b"})

    entries = runtime.actions.recent(OWNER)
    assert len(entries) == 3, "every attempt is its own row; nothing is deduplicated"
    fingerprints = [e.args_fp for e in entries]
    assert len(set(fingerprints)) == 2


# -- the record ---------------------------------------------------------


def test_the_record_names_the_device(runtime: Runtime) -> None:
    request_action(runtime, TOKEN, "attest.digest", {"digest": "a"})

    entry = runtime.actions.recent(OWNER)[0]
    assert entry.device_id == DEVICE
    assert entry.agent_id == "claude-code"
    assert entry.action_id == "attest.digest"
    assert entry.ok is True


def test_a_failed_action_is_recorded_as_attempted(
    settings: Settings, store
) -> None:
    """"Tried and failed" is a different fact from "never tried", and only the
    first is something an owner needs to know about."""
    rt = _runtime(settings, REFUSED_ACK, act_actions=["google.gmail.send"])
    try:
        result = request_action(rt, TOKEN, "google.gmail.send", {"to": "x@example.com"})

        assert result.ok is False
        assert result.error

        entry = rt.actions.recent(OWNER)[0]
        assert entry.ok is False
        assert entry.error
        assert entry.digest == ""
    finally:
        rt.store.wipe_actions(OWNER)
        rt.close()


def test_a_session_from_another_owner_is_refused(runtime: Runtime) -> None:
    """An id naming nothing must not end up on an audit row as though it were a
    real trace of where the action came from."""
    with pytest.raises(SessionError):
        request_action(
            runtime, TOKEN, "attest.digest", {"digest": "a"}, session_id="ses_nope"
        )
    assert runtime.actions.recent(OWNER) == []
    assert runtime.gateway.calls == 0, "and nothing was asked for"


def test_the_session_rides_into_the_record(runtime: Runtime) -> None:
    session = runtime.sessions.open_session(
        owner_id=OWNER,
        agent_id="claude-code",
        device_id=DEVICE,
        grant_fp=grant_fingerprint(TOKEN),
        ttl_secs=600,
    )
    request_action(
        runtime, TOKEN, "attest.digest", {"digest": "a"}, session_id=session.id
    )

    assert runtime.actions.recent(OWNER)[0].session_id == session.id


def test_an_empty_action_id_is_refused_before_anything_is_asked(
    runtime: Runtime,
) -> None:
    with pytest.raises(ValueError, match="needs an id"):
        request_action(runtime, TOKEN, "   ", {})
    assert runtime.gateway.calls == 0


def test_the_orchestrator_does_not_second_guess_the_gate(runtime: Runtime) -> None:
    """`evaluate_action` exists in Python and this path still does not call it.

    A check here would be advisory: the gateway verifies the grant's *signature*
    and the orchestrator cannot, so a Python-side check would pass on a forged
    token the gateway would reject, while reading in the code as though it were
    the gate. One gate, in the place that can hold it.

    So an action the local scope does not name is still forwarded, and the
    gateway is what refuses it.
    """
    request_action(runtime, TOKEN, "github.issue.comment", {"body": "hi"})

    assert runtime.gateway.calls == 1
    _token, action_id, _args = runtime.gateway.seen[0]
    assert action_id == "github.issue.comment"


def test_the_log_never_crosses_owners(runtime: Runtime) -> None:
    request_action(runtime, TOKEN, "attest.digest", {"digest": "a"})
    assert runtime.actions.recent("someone-else") == []


def test_a_long_summary_is_capped(runtime: Runtime, settings: Settings) -> None:
    """An ack goes into an agent's context window. The enclave bounds it, and
    this side re-caps because it must not trust a length it did not enforce."""
    rt = _runtime(settings, {**OK_ACK, "summary": "x" * 5_000})
    try:
        result = request_action(rt, TOKEN, "attest.digest", {"digest": "a"})
        assert len(result.summary) < 600
    finally:
        rt.store.wipe_actions(OWNER)
        rt.close()
