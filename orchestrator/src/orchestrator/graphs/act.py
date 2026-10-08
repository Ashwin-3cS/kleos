"""Asking the enclave to do something, and recording that it was asked.

The agent-facing half of the TEE action broker. The design is in
`enclave/src/services/actions.rs`; what lives here is the part outside the trust
boundary, which is deliberately thin:

- resolve the grant, so the record names the authenticated device;
- hand the intent to the gateway, which verifies the capability and forwards;
- record the attempt and its outcome, whichever it was.

**It does not check the capability itself.** `evaluate_action` exists in Python
and is tested there, and this path still does not call it -- because the gateway
verifies the grant's signature and the orchestrator cannot. A check here would be
advisory, would pass on a forged token the gateway would reject, and would read
in the code as though it were the gate. One gate, in the place that can actually
hold it.

**It records after the fact, and the write failing is a failure.** For a read, an
unrecordable disclosure is one the owner cannot audit. For an action it is
something that happened in the world with no trace, so the ordering is the
opposite of the read log's: ask first, then record, and let the record failing
propagate. An agent told "this may have happened and was not recorded" can go and
check; one told "done" cannot.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any

from ..storage.actions import ActionEntry, args_digest
from ..storage.sessions import SessionError
from .runtime import Runtime

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ActionResult:
    """What the agent is told: an acknowledgement, and nothing else."""

    action_id: str
    ok: bool
    #: The enclave's hash over what it did, so a repeat is recognisable.
    digest: str
    #: The enclave's one line. Stored and returned as it arrived.
    summary: str
    error: str | None = None
    #: Set when the result was too large to summarise. Reading it is a second,
    #: separately granted step -- the agent must pass the `may_unseal` gate.
    sealed_ref: dict[str, Any] | None = None
    #: The audit row this produced, so a caller can point at it.
    record_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def request_action(
    runtime: Runtime,
    grant_token: str,
    action_id: str,
    args: dict[str, Any] | None = None,
    *,
    session_id: str | None = None,
) -> ActionResult:
    """Submits an intent and returns the acknowledgement."""
    action_id = action_id.strip()
    if not action_id:
        raise ValueError("an action needs an id")
    args = args or {}

    resolved = runtime.gateway.introspect_grant(grant_token)
    scope = resolved.scope

    if session_id is not None and runtime.sessions.get(scope.owner_id, session_id) is None:
        # Verified rather than merely recorded, like a decision's session: an id
        # naming nothing must not end up on an audit row as though it were a real
        # trace of where the action came from.
        raise SessionError(f"no session {session_id} for this owner")

    ack = runtime.gateway.request_action(grant_token, action_id, args)

    entry = runtime.actions.record(
        ActionEntry(
            owner_id=scope.owner_id,
            action_id=action_id,
            agent_id=scope.agent_id,
            device_id=resolved.device_id or None,
            session_id=session_id,
            grant_fp=resolved.grant_fp,
            ok=bool(ack.get("ok")),
            digest=str(ack.get("digest") or ""),
            summary=str(ack.get("summary") or ""),
            error=ack.get("error"),
            # Over the arguments, which are not stored: an action's arguments are
            # the content it acted on, and a log that kept them would be a second
            # uncontrolled copy of what the enclave exists to keep from the
            # operator.
            args_fp=args_digest(args),
        )
    )

    log.info(
        "act.requested id=%s ok=%s device=%s record=%s",
        action_id,
        entry.ok,
        resolved.device_id,
        entry.id,
    )
    return ActionResult(
        action_id=action_id,
        ok=entry.ok,
        digest=entry.digest,
        summary=entry.summary,
        error=entry.error,
        sealed_ref=ack.get("sealed_ref"),
        record_id=entry.id,
    )
