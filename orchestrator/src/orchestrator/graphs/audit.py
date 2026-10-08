"""Recording a disclosure, for all four read paths.

One function, called from each graph's assembler, so there is exactly one
place that decides what an audit entry contains. Four near-identical copies
inside four assemblers is how an audit log ends up recording three of the
four reads.

It is called from the **assembler**, not from the permission node, and that
placement is the point: the permission node decides what *may* be disclosed,
the assembler decides what *is*. Logging the former would record intent;
these entries record the response. See ADR 0005.
"""

from __future__ import annotations

from ..permissions import Scope
from ..storage.reads import ReadEntry, grant_fingerprint
from .runtime import Runtime


def record_read(
    runtime: Runtime,
    scope: Scope,
    grant_token: str,
    kind: str,
    disclosed_ids: list[str],
    denied: list[dict],
    considered: int,
    subject: str | None = None,
    device_id: str | None = None,
    session_id: str | None = None,
) -> None:
    """Appends one entry for a read that is about to be returned.

    Raises if the entry cannot be stored, which fails the read. A disclosure
    that cannot be recorded is one the owner can never audit, and this is the
    component whose entire claim is that they can -- so the write is not
    best-effort. In practice the cost is nil: the read already needed this
    database to retrieve anything at all.
    """
    runtime.read_log.record(
        ReadEntry(
            owner_id=scope.owner_id,
            agent_id=scope.agent_id,
            # Taken from the introspection that authorised this read, not from
            # anything the caller sent. `scope.agent_id` is a label the owner
            # chose; this is the key the gateway checked a signature against.
            device_id=device_id,
            session_id=session_id,
            grant_fp=grant_fingerprint(grant_token),
            kind=kind,
            disclosed_ids=list(disclosed_ids),
            # Normalised to {id, reason}: each graph shapes its denials
            # slightly differently, and the log should not inherit that.
            denied=[
                {"id": str(d.get("id", "")), "reason": str(d.get("reason", ""))}
                for d in denied
            ],
            considered=considered,
            subject=subject,
        )
    )
