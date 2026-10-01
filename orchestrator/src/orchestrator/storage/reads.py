"""The agent read log: what each grant actually disclosed, and when.

The product's claim is "you can see exactly what an agent can see". The
explorer delivered the *can*: paste a grant, see the permission-filtered
subgraph. Nothing delivered the *did*. A grant with a 1-hour TTL and no
revocation list is a capability you cannot withdraw, so the only way an owner
can reason about one after the fact is a record of what it was used for --
and there was none. See ADR 0005.

Three decisions shape what is stored:

**What was returned, not what was asked.** A log of requests answers "what
did this agent want", which is not the question. A disclosure is the event
worth recording, so entries carry the ids that were actually assembled into
an answer.

**Denials are logged too, and are the more interesting entry.** One query
that returns nothing is a misconfigured grant. Two hundred of them walking
the id space is an agent mapping a memory it cannot read. Only the second is
visible, and only if denials are recorded.

**The grant is fingerprinted, never stored.** A grant token is a bearer
credential; an audit log that holds live credentials is a vulnerability
wearing an accountability costume. The fingerprint is enough to group every
read made under one grant and to match an entry against a token the owner
still holds, and it is useless to anyone who steals the log.

The log is owner-readable only. There is no MCP tool and no grant-authorised
route that reads it: an agent that could read the log could see which objects
*other* agents were shown, which is a disclosure channel around the
permission check rather than a record of it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

log = logging.getLogger(__name__)

#: Spoken questions and agent prompts can be long; the log stores a prefix.
#: Enough to recognise what was asked, not a transcript store.
_QUESTION_MAX = 500


def grant_fingerprint(grant_token: str) -> str:
    """A stable, non-reversible handle for one grant token.

    Domain-separated so a fingerprint from this log cannot be compared
    against a hash of the same token computed anywhere else for another
    purpose.
    """
    digest = hashlib.blake2b(
        grant_token.encode(), key=b"kleos-read-log-v1", digest_size=16
    )
    return digest.hexdigest()


@dataclass(slots=True)
class ReadEntry:
    """One disclosure decision, as it was made."""

    owner_id: str
    agent_id: str
    grant_fp: str
    #: ``query`` | ``shift`` | ``context`` | ``neighbourhood``
    kind: str
    #: Ids assembled into the response. Empty on a decline.
    disclosed_ids: list[str] = field(default_factory=list)
    #: ``{"id": ..., "reason": ...}`` per object the grant did not cover.
    denied: list[dict[str, str]] = field(default_factory=list)
    #: How many objects the permission check evaluated.
    considered: int = 0
    #: The question or seed that produced this read, truncated.
    subject: str | None = None
    at_ms: int = 0
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"read-{uuid.uuid4().hex}"
        if not self.at_ms:
            self.at_ms = int(time.time() * 1000)
        if self.subject is not None and len(self.subject) > _QUESTION_MAX:
            self.subject = self.subject[:_QUESTION_MAX] + "..."

    @property
    def answered(self) -> bool:
        return bool(self.disclosed_ids)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReadLog:
    """Append-only read log, stored in Neo4j beside the memory it records.

    **Why Neo4j, when Neo4j is explicitly not the system of record.** That
    property is scoped to the ``:Memory`` graph, which is rebuildable from
    source material. An audit log is not rebuildable -- it is the one thing in
    this database that cannot be regenerated, and it therefore has to be in
    whatever backup policy covers the deployment. Accepted anyway, because the
    alternative is a fourth datastore for a few hundred bytes per read, and
    because an audit record of a graph read is most useful where the graph is.

    ``:AgentRead`` deliberately does **not** carry the ``:Memory`` label. One
    vector index and every traversal in `neo4j_store` are keyed on
    ``:Memory``, so staying off that label is what keeps the log out of
    retrieval, out of neighbourhood walks, and out of anything an agent can
    reach. A log entry that could be retrieved as memory would disclose other
    agents' reads through the very check it exists to audit.

    Writes **fail closed**: if the entry cannot be stored, the read raises
    rather than returning data that was never recorded. In practice this costs
    nothing, because every read already needed the same database to retrieve
    at all -- but the ordering matters, so the record is written before the
    answer is assembled, not after it is returned.
    """

    def __init__(self, store) -> None:
        self._store = store

    def record(self, entry: ReadEntry) -> ReadEntry:
        self._store.append_read(entry)
        log.info(
            "read.log kind=%s agent=%s disclosed=%d denied=%d",
            entry.kind,
            entry.agent_id,
            len(entry.disclosed_ids),
            len(entry.denied),
        )
        return entry

    def recent(self, owner_id: str, limit: int = 50) -> list[ReadEntry]:
        """The owner's most recent reads, newest first."""
        return self._store.recent_reads(owner_id, limit)

    def summary(self, owner_id: str, limit: int = 50) -> dict[str, Any]:
        """Per-grant rollup for display: who read, how much, how often.

        Grouped by grant rather than by agent because the grant is the
        capability. The same agent id holding two grants is two different
        authorisations, and an owner deciding whether to stop issuing one
        needs them apart.
        """
        entries = self.recent(owner_id, limit)
        by_grant: dict[str, dict[str, Any]] = {}
        for entry in entries:
            row = by_grant.setdefault(
                entry.grant_fp,
                {
                    "grant_fp": entry.grant_fp,
                    "agent_id": entry.agent_id,
                    "reads": 0,
                    "disclosed": 0,
                    "declined": 0,
                    "kinds": set(),
                    "first_at_ms": entry.at_ms,
                    "last_at_ms": entry.at_ms,
                },
            )
            row["reads"] += 1
            row["disclosed"] += len(entry.disclosed_ids)
            row["declined"] += 0 if entry.answered else 1
            row["kinds"].add(entry.kind)
            row["first_at_ms"] = min(row["first_at_ms"], entry.at_ms)
            row["last_at_ms"] = max(row["last_at_ms"], entry.at_ms)
        grants = []
        for row in by_grant.values():
            row["kinds"] = sorted(row["kinds"])
            grants.append(row)
        grants.sort(key=lambda r: r["last_at_ms"], reverse=True)
        return {
            "owner_id": owner_id,
            "reads": len(entries),
            "grants": grants,
            "entries": [e.as_dict() for e in entries],
        }


def entry_to_row(entry: ReadEntry) -> dict[str, Any]:
    """Flattens an entry for Cypher.

    ``denied`` is JSON because Neo4j has no map-list property type, and
    because nothing queries inside it -- it is read back whole for display.
    The scalar fields an owner filters on stay real properties.
    """
    return {
        "id": entry.id,
        "owner_id": entry.owner_id,
        "agent_id": entry.agent_id,
        "grant_fp": entry.grant_fp,
        "kind": entry.kind,
        "disclosed_ids": list(entry.disclosed_ids),
        "denied_json": json.dumps(entry.denied),
        "considered": entry.considered,
        "subject": entry.subject,
        "at_ms": entry.at_ms,
    }


def row_to_entry(row: dict[str, Any]) -> ReadEntry:
    return ReadEntry(
        id=row["id"],
        owner_id=row["owner_id"],
        agent_id=row["agent_id"],
        grant_fp=row["grant_fp"],
        kind=row["kind"],
        disclosed_ids=list(row["disclosed_ids"] or []),
        denied=json.loads(row["denied_json"] or "[]"),
        considered=int(row["considered"] or 0),
        subject=row["subject"],
        at_ms=int(row["at_ms"]),
    )
