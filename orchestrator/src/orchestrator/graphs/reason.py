"""The pass that looks at more than one session (ADR 0025).

Everything else in this service reasons narrowly. The resolver compares one new
statement against stored claims about the same subject, pairwise and at write
time. ``consolidate_session`` asks what one session concluded, with no stored
memory and no other sessions in view. Nothing had ever looked at a *subject* and
asked what the sessions about it add up to.

This does, and three things about how are decisions:

**It writes claims, not blocks.** The whole of ADR 0025. A conclusion stored as
prose cannot be superseded, so it goes stale with an authenticated actor
attached and nothing in the service can correct it. As a claim, a later pass's
conclusion on the same topic supersedes it through machinery that already works.
Note how directly that applies here: "decisions about X have been reversed three
times" is a statement with a shelf life, and this design is what gives it one.

**It goes through `record_decision`, with the authority capped.** Not a second
write path -- the same gate, the same forced `agent` source, the same resolver.
What `derived=True` changes is the precedence class, which is pinned to
`Reference` whatever the grant says, so an inference the harness drew can
contradict what somebody decided but never replace it.

**Its dates come from the claims it read, not from the clock.** The record's
id is content-addressed over the statement, the reason and the timestamp, so a
pass that stamped `now()` would write a fresh copy of the same conclusion every
time it ran. Dating the conclusion to the most recent claim it was drawn from
makes a re-run over unchanged memory idempotent and a run after new claims
arrive produce something new -- which is the behaviour you want anyway, since a
conclusion belongs to when the material it came from was asserted.
``consolidate_session`` made the same choice for the same reason.

**What this reads is the sharpest plaintext exposure in the service.** Not one
incoming record: every stored claim about a subject, unsealed, in a host
process. That is `resolver.py:221` with a wider aperture, and it is why ADR 0025
gates *shipping* this on step 5 -- the model call going out from inside the
enclave over the TLS tunnel `services/http.rs` already runs. Running it here is
correct for development and is not the end state.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from ..extraction.reasoning import (
    MIN_SESSIONS,
    CrossSessionConclusion,
    Observation,
    get_reasoner,
)
from ..resolution.entities import match as name_match
from ..schema import Claim, Entity
from .decide import WriteRefused, record_decision
from .runtime import Runtime

log = logging.getLogger(__name__)


class SubjectNotFound(LookupError):
    """No stored entity matches the subject asked about."""


@dataclass(slots=True)
class ReasoningPass:
    """What one pass looked at, concluded and wrote.

    ``considered`` and ``sessions`` are reported even when nothing was written,
    because "ran and found nothing" is the common outcome and a different fact
    from "did not run" -- the same distinction `consolidate_session` draws.
    """

    owner_id: str
    subject: str
    subject_entity_ids: list[str]
    #: Claims read. Not an answer to "how much was disclosed" -- that is the
    #: read log's job -- but the denominator for anything this concluded.
    considered: int
    #: Distinct sessions those claims came from. Below `MIN_SESSIONS` the pass
    #: declines, because one session's claims were already reasoned over.
    sessions: int
    devices: int
    reasoner: str
    ran: bool
    conclusions: list[dict[str, Any]] = field(default_factory=list)
    #: Claims this pass wrote. Empty with `conclusions` non-empty and no
    #: `errors` means it reached the same conclusions as a previous pass and
    #: wrote none of them again -- which is what idempotence looks like from
    #: here, and a different outcome from concluding nothing.
    written: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    declined: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def reason_about(
    runtime: Runtime,
    grant_token: str,
    subject: str,
    *,
    min_sessions: int = MIN_SESSIONS,
) -> ReasoningPass:
    """Reasons across every session that touched one subject.

    Gated by the same `may_write` an agent's own write is, and checked by
    `record_decision` per conclusion rather than here: a pass that pre-checked
    and then wrote through a different door would be two places deciding one
    thing. What *is* checked here is the subject and the threshold, because both
    are cheap and both make the difference between a pass worth running and a
    model call over nothing.
    """
    resolved = runtime.gateway.introspect_grant(grant_token)
    owner_id = resolved.scope.owner_id

    entity_ids = _subject_entities(runtime, owner_id, subject)
    if not entity_ids:
        raise SubjectNotFound(
            f"no stored entity matches {subject!r} for this owner. The subject has "
            "to be something memory already knows about -- this pass reasons over "
            "what was written, it does not go looking."
        )

    observations = _observations(runtime, owner_id, entity_ids)
    sessions = {o.session_id for o in observations if o.session_id}
    devices = {o.device_id for o in observations if o.device_id}
    reasoner = get_reasoner(runtime.settings)

    base = ReasoningPass(
        owner_id=owner_id,
        subject=subject,
        subject_entity_ids=entity_ids,
        considered=len(observations),
        sessions=len(sessions),
        devices=len(devices),
        reasoner=reasoner.name,
        ran=False,
    )

    if len(sessions) < min_sessions:
        # Declined rather than run-and-found-nothing, and the two are reported
        # differently on purpose. A pass over one session cannot find anything
        # consolidation did not already have in view, so running it would spend
        # a model call to restate that session's own conclusions -- and a
        # restatement written as *derived* is worse than no conclusion at all.
        reasoner.close()
        base.declined = (
            f"too_few_sessions: {len(sessions)} session(s) have written about "
            f"{subject!r} and this pass needs {min_sessions}. One session's "
            "claims were already reasoned over when it closed."
        )
        log.info(
            "reason.declined subject=%r sessions=%d considered=%d",
            subject,
            len(sessions),
            len(observations),
        )
        return base

    try:
        conclusions = reasoner.reason(subject, observations)
    finally:
        reasoner.close()

    base.ran = True
    base.conclusions = [c.as_dict() for c in conclusions]
    # The newest claim this was drawn from. See the module docstring: this is
    # what makes a re-run over unchanged memory write nothing new.
    stamp = max((o.asserted_at_ms for o in observations), default=None)

    for conclusion in conclusions:
        try:
            result = record_decision(
                runtime,
                grant_token,
                conclusion.statement,
                _reason_text(conclusion),
                memory_kind=conclusion.kind.value,
                occurred_at_ms=stamp,
                derived=True,
            )
        except (WriteRefused, ValueError) as exc:
            # One refusal does not refuse the rest, same as consolidation: a
            # grant covering procedures but not tacit claims should keep the
            # procedures, and the refusal is reported rather than swallowed.
            base.errors.append(f"{conclusion.kind.value}: {exc}")
            continue
        base.written += [cid for cid in result.claim_ids if cid not in base.written]

    log.info(
        "reason.ran subject=%r reasoner=%s considered=%d sessions=%d devices=%d "
        "concluded=%d written=%d errors=%d",
        subject,
        reasoner.name,
        len(observations),
        len(sessions),
        len(devices),
        len(conclusions),
        len(base.written),
        len(base.errors),
    )
    return base


def _reason_text(conclusion: CrossSessionConclusion) -> str:
    """The reason, with the claims it was drawn from named in it.

    ``basis`` has nowhere structural to live until claims can cite claims, and
    leaving it only in a log would mean the one kind of claim nobody asserted is
    also the one whose grounds an owner cannot see. So it goes in the reason,
    which the briefing already quotes -- bounded, because an advisory is a line
    an agent reads and a list of forty ids is not one.
    """
    text = conclusion.reason.strip()
    if not conclusion.basis:
        return text
    shown = list(conclusion.basis[:3])
    more = len(conclusion.basis) - len(shown)
    suffix = ", ".join(shown) + (f" and {more} more" if more > 0 else "")
    return f"{text} [drawn across {suffix}]"


def _subject_entities(runtime: Runtime, owner_id: str, subject: str) -> list[str]:
    """Every stored entity the subject names.

    By name rather than by id, because a caller asking about "Lantern" has a
    project in mind and not a content address. `entities.match` is the same
    comparison canonicalisation uses, so "Lantern" and "project Lantern" and an
    alias all land on the same entity -- and reusing it means the subject
    lookup cannot drift from the merge rule that produced the entity.

    Several ids can come back, and that is correct rather than ambiguous:
    canonicalisation is best-effort past its cap, so one project genuinely can
    exist as two entities, and reasoning over one half of a split subject would
    silently see less than the owner thinks it did.
    """
    wanted = subject.strip()
    if not wanted:
        return []
    out: list[str] = []
    for stored in runtime.store.recent_entities(owner_id):
        node = stored.node
        if not isinstance(node, Entity):
            continue
        entity = runtime.content.unseal_node(node)
        names = [entity.name, *entity.aliases]
        if any(name_match(wanted, name) for name in names if name):
            out.append(entity.id)
    return out


def _observations(
    runtime: Runtime, owner_id: str, entity_ids: list[str]
) -> list[Observation]:
    """The claims about those entities, unsealed, flattened, oldest first.

    Ordered by assertion time because a pattern across sessions is a pattern
    over time -- "reversed three times" is only legible in order, and handing a
    model an arbitrary order invites it to invent one.
    """
    observations: list[Observation] = []
    for stored in runtime.store.claims_about(owner_id, entity_ids):
        if not isinstance(stored.node, Claim):
            continue
        # The exposure named in the module docstring. Every claim about the
        # subject, in the clear, in this process.
        claim: Claim = runtime.content.unseal_node(stored.node)
        observations.append(
            Observation(
                claim_id=claim.id,
                statement=claim.statement,
                status=claim.status.value,
                asserted_at_ms=claim.asserted_at_ms,
                agent_id=claim.provenance.actor_agent_id,
                device_id=claim.provenance.actor_device_id,
                session_id=claim.provenance.actor_session_id,
            )
        )
    observations.sort(key=lambda o: (o.asserted_at_ms, o.claim_id))
    return observations
