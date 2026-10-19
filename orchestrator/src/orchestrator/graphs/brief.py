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

**This read is not sealed yet, and it refuses rather than pretending.** ADR 0024
moved the query assembler into the enclave, and a briefing cannot simply relay
what that produces: it reads the disclosed claims' *statements* to write its
advisories, on the host, in this process. Composing a sealed answer would mean
reaching into the blob, and there is nothing out here that can open one.

So with `ENCRYPT_CONTENT_AT_REST` on, `brief_before_acting` declines and says
why. The alternative was to keep unsealing the claims out here, which would
leave the sharpest host-side read exposure open behind a feature that *looks*
like it moved -- the query path sealed, the briefing quietly reading the same
content through a different door. Closing it properly means the advisory logic
moving into the enclave, which is its own step: the advisories are generated
text, not a relay, and the enclave's assembler is deliberately formatting only.

Nothing in use depends on the combination today, because content sealing is off
by default and no deployment holds real memory yet.

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
from ..storage.mutations import Actor
from .audit import record_read
from .history import why_did_this_shift
from .query import run_query
from .runtime import Runtime

log = logging.getLogger(__name__)


class SealedBriefingUnsupported(RuntimeError):
    """Raised when a briefing is asked for against sealed content.

    Its own type rather than a `ValueError`, so a caller can tell "you asked for
    something this build cannot do yet" apart from "your request was malformed".
    The MCP tool and the HTTP route turn it into a refusal with the reason
    attached, which is what an agent can act on.
    """


#: Enough of a decision to recognise it in a one-line advisory.
_ADVISORY_CHARS = 120

#: What the owner's own ingestion is recorded as. Named here so the rendering
#: below can tell it apart from an agent whose label nobody checked.
PIPELINE_ACTOR = Actor.pipeline().agent_id

#: What a conclusion the harness drew across sessions is recorded as (ADR 0025).
#: Like the pipeline it has no device, and for the same reason -- but unlike the
#: pipeline it is the *least* authoritative writer here rather than the most, so
#: the two cannot share a rendering.
HARNESS_ACTOR = Actor.harness().agent_id


@dataclass(slots=True)
class Attribution:
    """Who moved one object, and on what basis.

    `identity_basis` is the honest part. `device_key` means the gateway verified
    an Ed25519 signature against a key the owner registered -- rely on it.
    `label` means all that is known is the `agent_id` the owner typed into a
    scope before signing it, which nothing authenticates. `derived` means the
    harness concluded it across sessions and no identity was involved at all
    (ADR 0025) -- the one value that says *nobody asserted this*.
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

    # Checked before anything is read, so a refusal costs no retrieval and
    # writes no read-log entry for a read that did not happen.
    if runtime.content.seals_content:
        raise SealedBriefingUnsupported(
            "a briefing cannot be assembled while content is sealed at rest: it "
            "writes its advisories from the claims' own text, which since ADR "
            "0024 only exists inside the enclave. Use the query tool, which "
            "relays a sealed answer your device can open, or run with "
            "ENCRYPT_CONTENT_AT_REST off. Moving the advisory logic into the "
            "enclave is tracked as its own step."
        )

    resolved = runtime.gateway.introspect_grant(grant_token)
    scope = resolved.scope

    # Composed, not reimplemented: this read runs the query graph, so retrieval
    # stays permission-blind and the check stays its own node inside it.
    answer = run_query(runtime, intent, grant_token, top_k=top_k)

    # Deduplicated, order preserved. A disclosure list can name the same object
    # twice -- retrieval scores an object once per pass and the assembler reports
    # what it was given -- and every line downstream is per object, so a repeat
    # becomes the same advisory twice in an agent's context window. Which is the
    # one resource this read exists to spend carefully.
    #
    # `disclosed_ids` rather than the citations it used to mine: the two agree on
    # the unsealed path, and only the former means anything on the sealed one.
    # Reading it here keeps this composition honest about what it depends on.
    disclosed = list(dict.fromkeys(answer.disclosed_ids))
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
            identity_basis=(
                "derived"
                if entry.actor_agent_id == HARNESS_ACTOR
                else "device_key"
                if entry.actor_device_id
                else "label"
            ),
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
        # The latest *substantive* change to each object, not simply the latest.
        #
        # Labelling a claim with its memory kind is a `payload` mutation that
        # lands after the write, so "the most recent change" is reliably the
        # relabel -- and an advisory then says an agent "amended" a decision it
        # had in fact just recorded. True of the row and false about what
        # happened, which is the worse kind of wrong for a line an agent reads
        # and acts on.
        current = by_object.get(attribution.object_id)
        if current is None or _outranks(attribution, current):
            by_object[attribution.object_id] = attribution

    lines: list[str] = []
    for claim in claims:
        who = by_object.get(claim.id)
        if who is None:
            continue
        line = _advisory_line(claim, who)
        if line not in lines:
            # Two claims can render the same sentence -- a restatement that the
            # resolver linked, say -- and the second copy tells the agent
            # nothing it did not already read.
            lines.append(line)

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


#: How substantive each kind of change is, for choosing which one an advisory
#: describes. A relabel ranks below everything, because it is bookkeeping about a
#: claim rather than a change to what the record says.
_KIND_RANK = {
    "payload": 0,
    "fulfillment": 1,
    "create": 2,
    "status": 3,
    "contradict": 4,
    "reconcile": 5,
    "supersede": 6,
}


def _outranks(candidate: Attribution, current: Attribution) -> bool:
    """Whether `candidate` is the change an advisory should describe.

    Substance first, recency second. Two relabels in a row still pick the later
    one; a relabel never displaces the write it followed.
    """
    rank = (_KIND_RANK.get(candidate.kind, 2), candidate.at_ms)
    against = (_KIND_RANK.get(current.kind, 2), current.at_ms)
    return rank >= against


def _advisory_line(claim: Claim, who: Attribution) -> str:
    statement = " ".join(claim.statement.split())
    if len(statement) > _ADVISORY_CHARS:
        statement = statement[:_ADVISORY_CHARS].rsplit(" ", 1)[0] + "..."

    if who.actor_device_id:
        actor = (
            f"device {who.actor_device_id[:12]} (labelled {who.actor_agent_id!r}, "
            "device-authenticated)"
        )
    elif who.actor_agent_id == HARNESS_ACTOR:
        # Nobody said this. It is a pattern the harness read off several
        # sessions, so the line has to carry its own warrant: an agent that
        # cannot tell a derived inference from a decision somebody made will
        # treat them alike, and these are the ones it should push back on.
        actor = "the harness, reasoning across sessions (derived, nobody asserted it)"
    elif who.actor_agent_id == PIPELINE_ACTOR:
        # The owner's own ingestion -- a connector pulling their mailbox, their
        # own typing. It has no device because there is no device, and rendering
        # that as "label only, not authenticated" inverts how much a reader
        # should trust it: this is the most trustworthy writer in the system, not
        # an agent whose name nobody checked.
        actor = "the owner's own ingestion"
    else:
        actor = f"{who.actor_agent_id!r} (label only, not authenticated)"

    verb = {
        "create": "recorded",
        # Deliberately plain: an agent reading this needs to know a decision was
        # made, not which internal write recorded it.
        "payload": "relabelled",
        "status": "changed the status of",
        "supersede": "superseded",
        "contradict": "contradicted",
        "reconcile": "reconciled",
        "fulfillment": "updated the fulfillment of",
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
