"""The mutation log: every state change, who made it, and which rule decided.

The read log answers "what was this agent shown". Nothing answered the other
half -- what *changed*, and why -- and the gap was not a missing feature so much
as four `if` statements that decided and forgot.

A claim's status moved through `_mutate_claim`, which loads the payload, mutates
the model and writes it back, **discarding the prior value**. The resolver's
reasons lived entirely in control flow: newer `asserted_at_ms` wins, equal
timestamps contradict, an older claim arriving late is born superseded, a
weaker-sourced claim may not supersede a stronger one. None of it was stored, so
"B replaced A" was visible in the graph and *why* was not recoverable from
anything.

**Append-only, and that is the whole shape.** Three candidate designs, and the
first two are insufficient rather than wrong:

- *An actor on `Provenance`* is necessary and not sufficient. Provenance is
  created once with the object, so it answers "who wrote this" and structurally
  cannot answer "who later changed its status" -- the second writer would have to
  overwrite the first's actor, which is the failure mode, not the fix. It exists
  too, for the question it does answer.
- *Properties on the `SUPERSEDES` and `CONTRADICTS` edges* are attractive,
  because the edge *is* the state change. Insufficient on three counts: a status
  change with no edge (a fulfillment move, a reconciliation, a correction) has
  nowhere to go; `MERGE` means a re-link silently overwrites the first writer's
  properties; and `edges_among` feeds the neighbourhood read, which deliberately
  discloses edge *types* only, so edge properties would be a new disclosure
  surface in the one read that drops rather than withholds. They are written
  anyway, as a denormalisation, so a history read can render an actor without a
  second query -- but `ON CREATE` only, and this is the authority.
- *An append-only record*, like `:AgentRead`. Nothing overwrites a prior actor,
  and the same property that justified putting the read log in Neo4j applies:
  it cannot be regenerated from source material. The read log used to be the
  only such thing in this database; now there are two.

``:Mutation`` carries **no ``:Memory`` label**, so the system's record of its own
changes can never be retrieved as memory. Same single mechanism as the read log
and agent sessions, and the same parametrised test covers all of them.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

log = logging.getLogger(__name__)

#: A reason is a sentence, not an argument. Capped like ``ReadEntry.subject``,
#: and for a second reason: an uncapped reason field is where a model dumps its
#: entire chain of thought, and what is wanted here is the consolidated
#: statement of why -- a stored rationale, not a transcript.
_REASON_MAX = 500


@dataclass(frozen=True, slots=True)
class Actor:
    """Who caused a write.

    ``agent_id`` is a label the owner typed into the scope they signed and is
    not authenticated; ``device_id`` is the registered key whose signature the
    gateway verified. Both are kept because an owner reads the first and relies
    on the second.

    The ingestion pipeline's own writes use :meth:`pipeline`, which names no
    device -- there is no device, and a fabricated one would be
    indistinguishable from an authenticated one in every row that stores it.
    """

    agent_id: str
    device_id: str | None = None
    session_id: str | None = None
    grant_fp: str | None = None

    @classmethod
    def pipeline(cls) -> Actor:
        """The owner's own ingestion run: a connector, an extractor, a resolver."""
        return cls(agent_id="owner")


#: Why a change happened, as a closed set of rule names rather than prose.
#:
#: Each one is a branch that already existed in the resolver and already threw
#: its reason away. Naming them is what makes "every state change and why"
#: true -- and a closed set rather than free text because these are compared,
#: counted and filtered, and the prose that explains a particular case belongs
#: in ``reason``.
RULE_NEWER_ASSERTED_AT = "newer_asserted_at"
RULE_EQUAL_ASSERTED_AT_CONTRADICTS = "equal_asserted_at_contradicts"
RULE_ARRIVED_LATE_BORN_SUPERSEDED = "arrived_late_born_superseded"
RULE_WEAKER_SOURCE_CONTRADICTS = "weaker_source_contradicts"
RULE_DUPLICATE_ID = "duplicate_id"
RULE_AGENT_DELEGATE_SUPERSEDES = "agent_delegate_supersedes"
RULE_OWNER_EXPLICIT = "owner_explicit"
RULE_ENTITY_MERGE = "entity_merge"

RULES = frozenset(
    {
        RULE_NEWER_ASSERTED_AT,
        RULE_EQUAL_ASSERTED_AT_CONTRADICTS,
        RULE_ARRIVED_LATE_BORN_SUPERSEDED,
        RULE_WEAKER_SOURCE_CONTRADICTS,
        RULE_DUPLICATE_ID,
        RULE_AGENT_DELEGATE_SUPERSEDES,
        RULE_OWNER_EXPLICIT,
        RULE_ENTITY_MERGE,
    }
)

#: What kind of change this was.
KIND_CREATE = "create"
KIND_STATUS = "status"
KIND_SUPERSEDE = "supersede"
KIND_CONTRADICT = "contradict"
KIND_RECONCILE = "reconcile"
KIND_FULFILLMENT = "fulfillment"
KIND_PAYLOAD = "payload"


@dataclass(slots=True)
class MutationEntry:
    """One state change, as it was made."""

    owner_id: str
    #: The object that changed.
    object_id: str
    kind: str
    #: Which field, when the change was to one: ``status``,
    #: ``commitment.fulfillment``, ``reconciled_into``.
    field_name: str | None = None
    #: The value before and after. ``before`` is what was actually read back
    #: from the store, not what the caller believed was there.
    before: str | None = None
    after: str | None = None
    actor_agent_id: str = "owner"
    actor_device_id: str | None = None
    actor_session_id: str | None = None
    #: Prose, capped. Why this particular change, in the writer's words.
    reason: str = ""
    #: Which branch decided, from ``RULES``. The field that makes a history read
    #: able to say "superseded because the newer claim was asserted later"
    #: rather than only "superseded".
    rule: str | None = None
    grant_fp: str | None = None
    at_ms: int = 0
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"mut-{uuid.uuid4().hex}"
        if not self.at_ms:
            self.at_ms = int(time.time() * 1000)
        if self.reason and len(self.reason) > _REASON_MAX:
            self.reason = self.reason[:_REASON_MAX] + "..."
        if self.rule is not None and self.rule not in RULES:
            # Loudly, because an unrecognised rule is either a typo that would
            # read as a real reason forever, or a new branch whose name belongs
            # in `RULES` beside the others.
            raise ValueError(
                f"unknown rule {self.rule!r}; add it to mutations.RULES if it is a "
                f"new one. Known: {sorted(RULES)}"
            )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def for_actor(
        cls, actor: Actor, *, owner_id: str, object_id: str, kind: str, **rest
    ) -> MutationEntry:
        """Builds an entry from an :class:`Actor`, so no call site spells the
        three identity fields out and none of them can be filled in by halves."""
        return cls(
            owner_id=owner_id,
            object_id=object_id,
            kind=kind,
            actor_agent_id=actor.agent_id,
            actor_device_id=actor.device_id,
            actor_session_id=actor.session_id,
            grant_fp=actor.grant_fp,
            **rest,
        )


class MutationLog:
    """Append-only mutation log, stored in Neo4j beside the memory it records.

    Writes **fail closed**, like the read log: a change that cannot be recorded
    is one the owner can never account for. In practice the cost is nil, because
    the write already needed this database.
    """

    def __init__(self, store) -> None:
        self._store = store

    def record(self, entry: MutationEntry) -> MutationEntry:
        self._store.append_mutation(entry)
        log.info(
            "mutation.log kind=%s object=%s rule=%s actor=%s device=%s",
            entry.kind,
            entry.object_id,
            entry.rule,
            entry.actor_agent_id,
            entry.actor_device_id,
        )
        return entry

    def record_all(self, entries: list[MutationEntry]) -> list[MutationEntry]:
        for entry in entries:
            self.record(entry)
        return entries

    def recent(self, owner_id: str, limit: int = 50) -> list[MutationEntry]:
        """The owner's most recent changes, newest first."""
        return self._store.recent_mutations(owner_id, limit)

    def for_objects(self, owner_id: str, object_ids: list[str]) -> list[MutationEntry]:
        """Every recorded change to these objects, oldest first.

        Per object rather than as a log, because this is what a briefing is
        allowed to surface: the changes to objects the asking agent has *just
        been permitted to see*. An agent reading the log wholesale would learn
        what other agents have been doing, which is a disclosure channel around
        the permission check rather than a record of it -- the same reason there
        is no MCP tool for the read log.
        """
        if not object_ids:
            return []
        return self._store.mutations_for_objects(owner_id, object_ids)


def entry_to_row(entry: MutationEntry) -> dict[str, Any]:
    """Flattens an entry for Cypher.

    ``field_name`` on the dataclass and ``field`` as the stored property:
    ``field`` is a dataclasses builtin and shadowing it in a module full of
    dataclasses is a trap, while the Cypher should read the way the concept does.
    """
    return {
        "id": entry.id,
        "owner_id": entry.owner_id,
        "object_id": entry.object_id,
        "kind": entry.kind,
        "field": entry.field_name,
        "before": entry.before,
        "after": entry.after,
        "actor_agent_id": entry.actor_agent_id,
        "actor_device_id": entry.actor_device_id,
        "actor_session_id": entry.actor_session_id,
        "reason": entry.reason,
        "rule": entry.rule,
        "grant_fp": entry.grant_fp,
        "at_ms": entry.at_ms,
    }


def row_to_entry(row: dict[str, Any]) -> MutationEntry:
    return MutationEntry(
        id=row["id"],
        owner_id=row["owner_id"],
        object_id=row["object_id"],
        kind=row["kind"],
        field_name=row.get("field"),
        before=row.get("before"),
        after=row.get("after"),
        actor_agent_id=row.get("actor_agent_id") or "owner",
        actor_device_id=row.get("actor_device_id"),
        actor_session_id=row.get("actor_session_id"),
        reason=row.get("reason") or "",
        rule=row.get("rule"),
        grant_fp=row.get("grant_fp"),
        at_ms=int(row["at_ms"]),
    )
