"""An agent writing into the record: the gate, and what it is allowed to claim.

Until now the only way into memory was the owner's own sources, or the owner
typing. This is the path for an agent that has just concluded something and has
a grant that says it may say so.

Three things have to be true before anything is written, and they are checked
here rather than inside the graph:

**The grant must permit it.** `permits_write` is pure, total and deny-by-default,
and it is called before a `RawRecord` is even built -- a refusal has to be a
refusal rather than a run that ingests nothing. The reason is returned, because a
decline that says "no" is indistinguishable from a bug.

**The write takes the `agent` source, whatever the caller says.** The source is
not a parameter. An agent able to choose its own source could write a claim that
claims to be a typed note from the person, and `Scope.write_sources` exists
precisely to make read scope and write scope different sets.

**Authority comes from the grant, not from the agent.** A grant with
`may_supersede_owner` produces `Delegate`, and without it `Reference`. The
resolver then does the rest with machinery that already existed: a `Reference`
claim contradicts the person's claim rather than replacing it, and the person's
later claim may always supersede either. So the resolver needs to know nothing
about grants, and the asymmetry ADR 0014 established for fetched pages extends to
agents without being re-argued.

What this deliberately does **not** do is run a second ingestion path. The record
goes through the ordinary graph -- extraction, canonicalisation, resolution,
sealing, the write -- because a thing an agent concluded is a record like any
other once it exists, and two graphs resolving the same material is two chances
to diverge. ADR 0013's reasoning, applied to a different writer.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from ..connectors.agent import AGENT, build_record
from ..enums import Authority, MemoryKind, Sensitivity
from ..permissions import WriteIntent, evaluate_write
from ..storage.mutations import Actor
from ..storage.sessions import SessionError
from .ingestion import run_ingestion
from .runtime import Runtime

log = logging.getLogger(__name__)


class WriteRefused(PermissionError):
    """The grant does not permit this write. Carries the deny reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"write refused: {reason}")
        self.reason = reason


@dataclass(slots=True)
class DecisionRecorded:
    """What a recorded decision actually produced."""

    owner_id: str
    #: The content-addressed id of the record, so a caller can recognise a retry.
    external_id: str
    #: Who it is attributed to. `identity_basis` says how much that is worth.
    agent_id: str
    device_id: str
    identity_basis: str
    authority: str
    memory_kind: str | None
    #: Counts of what landed, not of what was considered.
    entities: int = 0
    events: int = 0
    claims: int = 0
    #: Claim ids this decision superseded, and claims it now contradicts. The
    #: second is the interesting one: it is what the resolver does when an agent
    #: disagrees with the person and was not granted precedence over them.
    superseded: list[str] = field(default_factory=list)
    contradicted: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def record_decision(
    runtime: Runtime,
    grant_token: str,
    statement: str,
    reason: str,
    *,
    session_id: str | None = None,
    memory_kind: str = MemoryKind.EPISODIC.value,
    sensitive: bool = False,
    occurred_at_ms: int | None = None,
) -> DecisionRecorded:
    """Records what an agent decided, and why, under a write-capable grant.

    ``reason`` is required rather than optional. A decision with no stated basis
    is the thing this whole layer exists to stop being the only thing in the
    record: the next agent's briefing is built out of these, and "Postgres" with
    no reason tells it nothing it can act on.
    """
    statement = statement.strip()
    reason = reason.strip()
    if not statement:
        raise ValueError("a decision needs a statement")
    if not reason:
        raise ValueError(
            "a decision needs a reason: the next agent's briefing is built out of "
            "it, and a stored decision with no stated basis is what this records "
            "exist to replace"
        )

    if sensitive:
        # Refused here rather than inside the graph. Sealing needs an owner
        # session on the gateway and an agent holds a grant, so there is no path
        # by which this can be sealed today -- and the graph's own behaviour would
        # be to skip the event and put a line in `errors`, which reads as a
        # partial success. ADR 0013 made the same choice for `POST /remember`:
        # refuse up front rather than fail somewhere it surfaces as a skipped
        # record. Step 8's grant-authorised unseal is what makes the symmetric
        # grant-authorised seal possible.
        raise WriteRefused(
            "sensitive_not_supported: sealing a body needs an owner session, and "
            "an agent holds a grant. Record the decision without the sensitive "
            "detail, or have the owner push it through POST /remember."
        )

    resolved = runtime.gateway.introspect_grant(grant_token)
    scope = resolved.scope
    kind = MemoryKind(memory_kind)

    # The floor is applied before the check, not after: a tacit claim is an
    # inference *about* a person rather than something they said, so labelling
    # one raises its sensitivity, and the grant is then asked whether it may
    # write at *that* level. The other order would let a caller launder a tacit
    # claim in at `personal`.
    sensitivity = max(
        Sensitivity.PERSONAL, kind.sensitivity_floor, key=lambda s: s.rank
    )

    intent = WriteIntent(
        owner_id=scope.owner_id,
        # Not a parameter. An agent that could name its own source could write a
        # claim that claims to be a typed note from the person.
        source=AGENT,
        # Deliberately the whole of the grant's own entity scope rather than a
        # guess at what the extractor will produce: the extractor has not run
        # yet, and refusing here on kinds the claim may not even be about would
        # make the gate depend on extraction output. The per-object check at read
        # time is what narrows it afterwards.
        entity_kinds=list(scope.entity_kinds),
        sensitivity=sensitivity,
        memory_kind=kind,
    )
    decision = evaluate_write(scope, intent, None)
    if not decision.allowed:
        reason_code = decision.reason.value if decision.reason else "unknown"
        log.info(
            "decide.refused agent=%s device=%s reason=%s",
            scope.agent_id,
            resolved.device_id,
            reason_code,
        )
        raise WriteRefused(reason_code)

    if session_id is not None:
        # Verified, not merely recorded: an id that names nothing, or names
        # another owner's session, must not end up on a stored claim as though
        # it were a real trace. The session store's own owner scoping does the
        # work; this only turns its absence into a refusal here rather than a
        # dangling reference later.
        if runtime.sessions.get(scope.owner_id, session_id) is None:
            raise SessionError(f"no session {session_id} for this owner")

    authority = (
        Authority.DELEGATE if scope.may_supersede_owner else Authority.REFERENCE
    )
    record = build_record(
        scope.owner_id,
        statement,
        reason,
        occurred_at_ms=occurred_at_ms,
        sensitive=sensitive,
        agent_id=scope.agent_id,
        device_id=resolved.device_id,
        session_id=session_id or "",
    )
    actor = Actor(
        agent_id=scope.agent_id,
        device_id=resolved.device_id or None,
        session_id=session_id,
        grant_fp=resolved.grant_fp,
    )

    result = run_ingestion(
        runtime=runtime,
        owner_id=scope.owner_id,
        source=AGENT,
        # Keyed by the record, not by owner and source: two decisions sharing a
        # thread would have the second resume the first's state (ADR 0013).
        thread_id=f"decide:{record.external_id}",
        records=[record],
        actor=actor,
        authority=authority,
        # The statement is taken as given rather than rediscovered by the
        # extractor. See `_declared_claim`.
        declared={record.external_id: _as_statement(statement)},
    )

    # The kind is applied after resolution, on what actually landed. Setting it
    # on the candidate before `resolve` would mean the resolver compared a kinded
    # claim against stored ones using a field it does not read, and the promoted
    # column would then be written from whatever the extractor happened to
    # produce rather than from what the caller asked for.
    claim_ids = _kinded(runtime, scope.owner_id, result, kind, actor, reason)

    log.info(
        "decide.recorded agent=%s device=%s claims=%d superseded=%d contradicted=%d",
        scope.agent_id,
        resolved.device_id,
        len(claim_ids),
        len(result.supersessions),
        len(result.contradictions),
    )
    return DecisionRecorded(
        owner_id=scope.owner_id,
        external_id=record.external_id,
        agent_id=scope.agent_id,
        device_id=resolved.device_id,
        identity_basis="device_key" if resolved.device_id else "label",
        authority=authority.value,
        memory_kind=kind.value,
        entities=result.entities,
        events=result.events,
        claims=result.claims,
        superseded=[pair[1] for pair in result.supersessions],
        contradicted=[pair[1] for pair in result.contradictions],
        errors=list(result.errors),
    )


def _as_statement(statement: str) -> str:
    """The decision as a durable assertion, ending in a full stop.

    Only the punctuation is normalised. Nothing rewrites the agent's words: a
    stored claim has to be what was actually asserted, and "tidying" it is how a
    record ends up saying something nobody said.
    """
    text = " ".join(statement.split())
    return text if text.endswith((".", "!", "?")) else f"{text}."


def _kinded(
    runtime: Runtime,
    owner_id: str,
    result,
    kind: MemoryKind,
    actor: Actor,
    reason: str,
) -> list[str]:
    """Labels the claims this run wrote with the caller's memory kind.

    Only the claims, and only the ones this run actually wrote: a decision
    recorded as procedural says nothing about the episodic claims already in the
    record, and `written_by_label` counts what landed rather than what was
    considered.
    """
    from ..schema import Claim
    from ..storage.mutations import KIND_PAYLOAD, MutationEntry

    labelled: list[str] = []
    for node_id in result.written:
        stored = runtime.store.get_many(owner_id, [node_id])
        if not stored or not isinstance(stored[0].node, Claim):
            continue
        claim = stored[0].node
        if claim.memory_kind is kind and claim.acl.memory_kind is kind:
            continue
        claim.memory_kind = kind
        claim.acl.memory_kind = kind
        # And the floor, on the object. Checking it at the gate alone was a hole:
        # a tacit claim stored at `personal` is readable by a scope that never
        # asked for confidential material, which is exactly the disclosure the
        # floor exists to prevent. Raised rather than set, so a claim already
        # above the floor keeps its own level.
        if claim.acl.sensitivity.rank < kind.sensitivity_floor.rank:
            claim.acl.sensitivity = kind.sensitivity_floor
        runtime.store.replace_payload(claim)
        runtime.store.append_mutation(
            MutationEntry.for_actor(
                actor,
                owner_id=owner_id,
                object_id=claim.id,
                kind=KIND_PAYLOAD,
                field_name="memory_kind",
                before=None,
                after=kind.value,
                reason=reason,
            )
        )
        labelled.append(claim.id)
    return labelled
