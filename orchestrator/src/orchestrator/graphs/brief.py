"""The briefing: telling an agent what another one already decided, and why.

This is the point of the harness. Claude Code on one device decides something
and records it; ChatGPT on another is about to act on the same subject and has no
idea. A shared memory that only answers direct questions does not help, because
the second agent does not know there is a question to ask.

So `brief_before_acting` is read *before* acting, on an intent rather than a
question: "I am about to pick a database for Lantern." What comes back is what is
relevant, what is in conflict, **who decided it and on what basis**, and a line
the agent can put straight into its context without parsing anything.

**It composes existing reads rather than adding one.** `run_query` for what is
relevant, `why_did_this_shift` for how a decision got where it is,
`mutations.for_objects` for who moved it. That is not thrift: each of those has a
permission check inside it and a read-log entry after it, and a briefing that
retrieved for itself would be a fifth read path to keep correct -- and the first
one whose disclosure was not recorded the same way as the others.

**What it does not compose is the neighbourhood.** That read has no MCP tool on
purpose: an adjacency list answers no question an agent has, and handing one over
is a cheap structure-enumeration primitive -- seed, walk, re-seed. A briefing
returning adjacency would hand back exactly that under a friendlier name. Where
structure matters here it is reported as a count, never as ids.

**A conflict the grant cannot read is withheld, not dropped.** The history reads'
contract, for the reason they adopted it: the agent named a subject, so the
conflict's existence is already implied by the question, and an agent told "no
conflicts" acts while an agent told "a conflict exists you may not read" asks.
The residual is that "a conflict exists" is itself information -- but it is the
same information `why_did_this_shifted` already discloses to the same grant, so
this adds no channel it did not have.

**A briefing is only as selective as the ranking underneath it.** Retrieval
returns its best ``top_k`` candidates rather than gating on relevance, so an
agent briefing on an unrelated intent is still told about the decisions that
exist. That is the right failure direction -- too much context rather than a
missed conflict, which is the whole point -- but it is a property of the ranking
and not of this read, and in mock mode the embeddings are hashed tokens and
barely selective at all. A test asserts the behaviour so it is a known shape
rather than a surprise.

**Being briefed is not deciding.** The only trace is a read-log entry. If a
briefing were itself memory, agent B reading about agent A's decision would
create a claim that agent C's briefing would surface, which would create another
-- a record whose growth is a function of how often it is read rather than of
what happened. Within a week the graph is mostly the system's commentary on
itself, and the resolver is comparing agent-about-agent material against the
person's real decisions in the same subject neighbourhood.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from ..enums import ClaimStatus
from ..permissions import Scope
from ..schema import Claim
from ..storage.bodies import load_body
from .audit import record_read
from .history import why_did_this_shift
from .query import run_query
from .runtime import Runtime

log = logging.getLogger(__name__)

#: Enough of a decision to recognise it in a one-line advisory.
_ADVISORY_CHARS = 120


@dataclass(slots=True)
class Attribution:
    """Who moved one object, and on what basis.

    `identity_basis` is the honest part. `device_key` means the gateway verified
    an Ed25519 signature against a key the owner registered -- rely on it.
    `label` means all that is known is the `agent_id` the owner typed into a
    scope before signing it, which nothing authenticates.
    """

    object_id: str
    actor_agent_id: str
    actor_device_id: str | None
    actor_session_id: str | None
    identity_basis: str
    kind: str
    before: str | None
    after: str | None
    reason: str
    rule: str | None
    at_ms: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Briefing:
    """What an agent is told before it acts."""

    intent: str
    #: False when nothing relevant was both found and permitted. Not an error:
    #: a first agent on a fresh subject should be told there is nothing to know.
    answered: bool
    text: str
    #: The relevant claims, with citations, exactly as the query graph assembled
    #: them.
    relevant: list[dict] = field(default_factory=list)
    #: Supersession chains for the relevant claims that have one. Withheld steps
    #: ride along as the history read produced them.
    conflicts: list[dict] = field(default_factory=list)
    #: Who changed what, per disclosed object.
    attributions: list[Attribution] = field(default_factory=list)
    #: One line each, ready to drop into a context window.
    advisories: list[str] = field(default_factory=list)
    #: Only with `include_body` and a grant that may unseal.
    bodies: list[dict] = field(default_factory=list)
    denied: list[dict] = field(default_factory=list)
    considered: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "answered": self.answered,
            "text": self.text,
            "relevant": self.relevant,
            "conflicts": self.conflicts,
            "attributions": [a.as_dict() for a in self.attributions],
            "advisories": self.advisories,
            "bodies": self.bodies,
            "denied": self.denied,
            "considered": self.considered,
        }


def brief_before_acting(
    runtime: Runtime,
    intent: str,
    grant_token: str,
    *,
    session_id: str | None = None,
    top_k: int = 8,
    include_body: bool = False,
) -> Briefing:
    """What this agent should know before acting on ``intent``."""
    intent = intent.strip()
    if not intent:
        raise ValueError("a briefing needs an intent: what are you about to do?")

    resolved = runtime.gateway.introspect_grant(grant_token)
    scope = resolved.scope

    # Composed, not reimplemented: this read runs the query graph, so retrieval
    # stays permission-blind and the check stays its own node inside it.
    answer = run_query(runtime, intent, grant_token, top_k=top_k)

    disclosed = [c.object_id for c in answer.citations]
    claims = _claims_among(runtime, scope.owner_id, disclosed)

    conflicts = _conflicts(runtime, claims, grant_token)
    attributions = _attributions(runtime, scope.owner_id, disclosed)
    advisories = _advisories(claims, conflicts, attributions)
    bodies = (
        _bodies(runtime, scope, grant_token, disclosed)
        if include_body and scope.may_unseal
        else []
    )

    # One entry for the composite, on top of the entries each composed read
    # wrote for itself. The owner's log should show the shift read that actually
    # happened *and* what the agent was about to do -- a composite that replaced
    # them would hide which objects each underlying read disclosed.
    record_read(
        runtime,
        scope,
        grant_token,
        kind="brief",
        disclosed_ids=disclosed,
        denied=answer.denied,
        considered=answer.considered,
        subject=intent,
        device_id=resolved.device_id,
        session_id=session_id,
    )

    answered = bool(disclosed)
    return Briefing(
        intent=intent,
        answered=answered,
        text=(
            answer.text
            if answered
            else "Nothing in memory bears on this yet; nothing to be aware of."
        ),
        relevant=[asdict(c) for c in answer.citations],
        conflicts=conflicts,
        attributions=attributions,
        advisories=advisories,
        bodies=bodies,
        denied=answer.denied,
        considered=answer.considered,
    )


def _claims_among(runtime: Runtime, owner_id: str, ids: list[str]) -> list[Claim]:
    """The claims among what the query disclosed.

    Only claims: an entity is a referent and an event is a fact arriving, while a
    briefing is about assertions somebody made.
    """
    if not ids:
        return []
    return [
        stored.node
        for stored in runtime.store.get_many(owner_id, ids)
        if isinstance(stored.node, Claim)
    ]


def _conflicts(runtime: Runtime, claims: list[Claim], grant_token: str) -> list[dict]:
    """Supersession chains for claims that are in one.

    Asked only for claims that already carry a `supersedes`, `contradicts` or
    non-active status, because the shift read logs every call and briefing on a
    quiet subject should not fill the owner's log with reads that found nothing.
    """
    out: list[dict] = []
    for claim in claims:
        interesting = (
            claim.supersedes
            or claim.contradicts
            or claim.status is not ClaimStatus.ACTIVE
        )
        if not interesting:
            continue
        history = why_did_this_shift(runtime, claim.id, grant_token)
        if history.answered:
            out.append(history.as_dict())
    return out


def _attributions(runtime: Runtime, owner_id: str, ids: list[str]) -> list[Attribution]:
    """Who changed each disclosed object.

    Per object, and only for objects this agent was **just permitted to see**.
    The mutation log read wholesale would tell one agent what every other agent
    has been writing to the same memory, which is why it has an
    owner-authenticated route and no MCP tool.
    """
    return [
        Attribution(
            object_id=entry.object_id,
            actor_agent_id=entry.actor_agent_id,
            actor_device_id=entry.actor_device_id,
            actor_session_id=entry.actor_session_id,
            identity_basis="device_key" if entry.actor_device_id else "label",
            kind=entry.kind,
            before=entry.before,
            after=entry.after,
            reason=entry.reason,
            rule=entry.rule,
            at_ms=entry.at_ms,
        )
        for entry in runtime.mutations.for_objects(owner_id, ids)
    ]


def _bodies(
    runtime: Runtime, scope: Scope, grant_token: str, ids: list[str]
) -> list[dict]:
    """The raw material behind disclosed events, for a grant that may unseal.

    Off by default and gated twice -- the caller has to ask, and the grant has to
    permit it. Seeing a resolved claim and reading the transcript it came from
    are different disclosures.
    """
    from ..schema import Event

    out = []
    for stored in runtime.store.get_many(scope.owner_id, ids):
        if not isinstance(stored.node, Event):
            continue
        loaded = load_body(
            runtime,
            scope.owner_id,
            stored.node,
            scope=scope,
            grant_token=grant_token,
        )
        out.append({"object_id": stored.node.id, **loaded.as_dict()})
    return out


def _advisories(
    claims: list[Claim], conflicts: list[dict], attributions: list[Attribution]
) -> list[str]:
    """One line per thing worth knowing, rendered rather than structured.

    Because an agent with a tight context window should be able to use a briefing
    without parsing it, and because the sentence is what gets pasted into a
    prompt. The structure stays available above for anything that wants it.

    Every line names the device and says whether that identity is authenticated,
    so a reader is never left to assume the agent label means something.
    """
    by_object: dict[str, Attribution] = {}
    for attribution in attributions:
        # The latest change to each object: a briefing is about what holds now.
        current = by_object.get(attribution.object_id)
        if current is None or attribution.at_ms >= current.at_ms:
            by_object[attribution.object_id] = attribution

    lines: list[str] = []
    for claim in claims:
        who = by_object.get(claim.id)
        if who is None:
            continue
        lines.append(_advisory_line(claim, who))

    for history in conflicts:
        for step in history.get("steps", []):
            superseded = step.get("superseded") or {}
            if superseded.get("withheld"):
                lines.append(
                    "A superseded decision on this subject is outside your grant "
                    f"({superseded.get('reason', 'denied')}). It exists; you cannot "
                    "read it."
                )
    return lines


def _advisory_line(claim: Claim, who: Attribution) -> str:
    statement = " ".join(claim.statement.split())
    if len(statement) > _ADVISORY_CHARS:
        statement = statement[:_ADVISORY_CHARS].rsplit(" ", 1)[0] + "..."

    if who.actor_device_id:
        actor = (
            f"device {who.actor_device_id[:12]} (labelled {who.actor_agent_id!r}, "
            "device-authenticated)"
        )
    else:
        actor = f"{who.actor_agent_id!r} (label only, not authenticated)"

    verb = {
        "create": "recorded",
        "status": "changed the status of",
        "supersede": "superseded",
        "contradict": "contradicted",
        "reconcile": "reconciled",
        "fulfillment": "updated the fulfillment of",
        "payload": "amended",
    }.get(who.kind, "changed")

    line = f"{actor} {verb} “{statement}”"
    if who.reason:
        line += f" because “{who.reason}”"
    if who.rule:
        line += f" [rule: {who.rule}]"
    if claim.status is ClaimStatus.SUPERSEDED:
        line += " — this one no longer holds"
    elif claim.status is ClaimStatus.CONTRADICTED:
        line += " — this is in unresolved conflict"
    return line + ". Be aware of this before acting."
