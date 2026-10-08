"""Every action an agent asked the enclave to perform, and what came back.

The fourth append-only record in this database, after reads, sessions and
mutations, and off the ``:Memory`` label for the same reason as all of them: the
harness's record of its own activity must never be retrievable as memory.

What makes this one different from the other three is that it records something
that happened **outside** the system. A read discloses, a mutation changes the
record, a session holds working context -- all recoverable, all internal. An
action sends mail, or posts a comment, or signs something. It cannot be undone
by rewriting a row, which is exactly why the record of it has to be
unfalsifiable and complete.

So two properties the others do not need as sharply:

**A failed action is recorded.** "Tried and failed" is a different fact from
"never tried", and only the first is a thing the owner needs to know about. The
enclave returns `200` with `ok: false` rather than an error precisely so this
distinction survives the transport; dropping the failures here would throw it
away one layer later.

**The ack is stored as it arrived.** The digest and the summary are the
enclave's statement about what it did. The orchestrator does not interpret them
and must not improve them -- an operator-side process that rewrote an
acknowledgement would be editing the record of what was done on somebody's
behalf.

What is *not* stored: the arguments. An action's arguments are the content it
acted on -- the body of a message, the text of a comment -- and a log that kept
them would be a second uncontrolled copy of exactly the material the enclave
exists to keep out of the operator's hands. The digest is what makes an action
identifiable without being readable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

log = logging.getLogger(__name__)

#: One line, bounded, as the enclave already bounds it. Re-capped here because
#: this side must not trust a length it did not enforce.
_SUMMARY_MAX = 500


def args_digest(args: dict[str, Any]) -> str:
    """A stable handle for one action's arguments, which are never stored.

    Content-addressed over the canonical JSON, so the same action asked twice is
    recognisable as a repeat -- which is the question an owner reading this log
    actually has ("did it send that message once or forty times?") -- while the
    message itself stays out of the log.

    Domain-separated, so a digest here cannot be compared against a hash of the
    same arguments computed anywhere else for another purpose.
    """
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(
        canonical.encode(), key=b"kleos-action-args-v1", digest_size=16
    ).hexdigest()


@dataclass(slots=True)
class ActionEntry:
    """One action an agent asked for, and what the enclave said it did."""

    owner_id: str
    action_id: str
    #: The label the owner put in the scope they signed. Not authenticated.
    agent_id: str
    #: The registered device key the gateway verified. The only authenticated
    #: identity, and the one that answers "which of my agents did this".
    device_id: str | None = None
    session_id: str | None = None
    grant_fp: str | None = None
    #: Whether the enclave performed it. False is a real and recorded outcome.
    ok: bool = False
    #: The enclave's hash over what it did. Empty on a refusal.
    digest: str = ""
    #: The enclave's one line, stored as it arrived.
    summary: str = ""
    #: Present on a refusal. The enclave's reason, never a provider's raw error.
    error: str | None = None
    #: Over the arguments, which are not stored. See `args_digest`.
    args_fp: str = ""
    at_ms: int = 0
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"act-{uuid.uuid4().hex}"
        if not self.at_ms:
            self.at_ms = int(time.time() * 1000)
        for field_name in ("summary", "error"):
            value = getattr(self, field_name)
            if value and len(value) > _SUMMARY_MAX:
                setattr(self, field_name, value[:_SUMMARY_MAX] + "...")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ActionLog:
    """Append-only action log. Writes fail closed.

    Fail-closed matters more here than anywhere else in this codebase. For a
    read, an unrecordable disclosure is a disclosure the owner cannot audit --
    bad. For an action, it is something that *happened in the world* with no
    trace. So the record is written **after** the enclave answers and the write
    failing propagates: an action whose outcome cannot be recorded is reported as
    a failure to the agent, even though it may have succeeded. That is the honest
    direction, because an agent told "this may have happened and was not
    recorded" can check, while one told "done" cannot.
    """

    def __init__(self, store) -> None:
        self._store = store

    def record(self, entry: ActionEntry) -> ActionEntry:
        self._store.append_action(entry)
        log.info(
            "action.log id=%s ok=%s agent=%s device=%s",
            entry.action_id,
            entry.ok,
            entry.agent_id,
            entry.device_id,
        )
        return entry

    def recent(self, owner_id: str, limit: int = 50) -> list[ActionEntry]:
        """The owner's most recent actions, newest first."""
        return self._store.recent_actions(owner_id, limit)


def entry_to_row(entry: ActionEntry) -> dict[str, Any]:
    return {
        "id": entry.id,
        "owner_id": entry.owner_id,
        "action_id": entry.action_id,
        "agent_id": entry.agent_id,
        "device_id": entry.device_id,
        "session_id": entry.session_id,
        "grant_fp": entry.grant_fp,
        "ok": bool(entry.ok),
        "digest": entry.digest,
        "summary": entry.summary,
        "error": entry.error,
        "args_fp": entry.args_fp,
        "at_ms": entry.at_ms,
    }


def row_to_entry(row: dict[str, Any]) -> ActionEntry:
    return ActionEntry(
        id=row["id"],
        owner_id=row["owner_id"],
        action_id=row["action_id"],
        agent_id=row["agent_id"],
        device_id=row.get("device_id"),
        session_id=row.get("session_id"),
        grant_fp=row.get("grant_fp"),
        ok=bool(row.get("ok")),
        digest=row.get("digest") or "",
        summary=row.get("summary") or "",
        error=row.get("error"),
        args_fp=row.get("args_fp") or "",
        at_ms=int(row["at_ms"]),
    )
