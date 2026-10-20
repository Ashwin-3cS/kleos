"""Reasoning across sessions, over claims rather than over scratchpads.

ADR 0025. The harness reasoned twice and both times narrowly: the resolver
pairwise at write time, subject-scoped by design, and ``consolidate(blocks)`` at
session close with no stored memory, no other sessions and no other devices in
view. Four sessions across two devices can all be about one project and the
harness will have formed a view of each separately and of none of them together.

This is the pass that looks at all of them. Two things about its shape are
decisions rather than convenience:

**It reads stored claims, not session blocks.** ADR 0025's sketch had both. On
implementation the blocks came out, because consolidation already decided what
of a session was worth keeping and "almost nothing should" -- re-reading the
scratchpad here would quietly reverse that, and would mean the one component
with the widest view is also the one reading the rawest material. Claims carry
what this needs anyway: the statement, the status the resolver assigned, and the
device and session that produced them.

**Its output is a conclusion that becomes a claim**, so it can be superseded.
That is the whole argument of ADR 0025 and it is load-bearing here in a way
worth spelling out: a derived conclusion about the *state* of memory goes stale
exactly as a cached prose block would -- "decisions about this have been reversed
three times" is wrong once there are four. The difference is that a claim on the
same topic from a later pass supersedes it through machinery that already works,
and a stored paragraph has nothing that can.

Mirrors ``consolidate.py`` deliberately: a rule-based implementation for mock
mode and an LLM one for live, chosen by ``EXTRACTOR`` rather than a switch of
its own, for the reason ``get_consolidator`` gives -- a deployment reasoning
with a model while extracting with regexes would produce memory whose halves
disagree about how much they can be trusted.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from ..config import Settings
from ..enums import ClaimStatus, MemoryKind

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Observation:
    """One stored claim, as a reasoner sees it.

    Flattened on purpose. A reasoner that took `Claim` would be handed the ACL,
    the provenance citations and the sealed fields, and the LLM one would then
    decide for itself what to put in a prompt -- which is the kind of choice that
    belongs in one place and not in a prompt builder.
    """

    claim_id: str
    statement: str
    status: str
    asserted_at_ms: int
    #: From provenance. `device_id` is the only one of the three that was
    #: authenticated; the label and the session are what the writer said.
    agent_id: str | None = None
    device_id: str | None = None
    session_id: str | None = None

    @property
    def stands(self) -> bool:
        return self.status == ClaimStatus.ACTIVE.value


@dataclass(frozen=True, slots=True)
class CrossSessionConclusion:
    """Something that holds across several sessions and that none of them said.

    ``basis`` names the claims it was derived from. It is not stored as edges
    yet -- that needs a schema change -- but it is returned and logged, because a
    derived claim whose inputs cannot be named is one nobody can check.
    """

    statement: str
    kind: MemoryKind
    reason: str
    basis: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["kind"] = self.kind.value
        out["basis"] = list(self.basis)
        return out


#: Fewer than this and there is nothing cross-session to find: one session's
#: claims were already reasoned over by consolidation, and a "pattern" drawn
#: from a single session is that session's conclusion restated.
MIN_SESSIONS = 2

#: How many reversals make churn worth telling the next agent about. Two is a
#: decision that changed its mind once, which is ordinary. Three is a pattern.
CHURN_THRESHOLD = 3


class RuleBasedReasoner:
    """Deterministic cross-session reasoning. Finds only what is structural.

    Two patterns, both readable off the claim set with no judgement involved:
    repeated reversal, and a standing disagreement between two devices. It finds
    nothing else, and that limitation is the feature -- the same stance
    `RuleBasedConsolidator` takes. A regex cannot tell what several sessions add
    up to, and one that guessed would write invented claims into a real person's
    memory.

    It is not only a mock-mode stand-in: both patterns are facts about the graph
    rather than readings of it, so they are the two a model should never be
    *needed* for.
    """

    name = "rule-based-reasoner@v1"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def close(self) -> None:  # symmetry with the LLM reasoner
        return None

    def reason(
        self,
        subject: str,
        observations: list[Observation],
        *,
        also_known: list[str] | None = None,
    ) -> list[CrossSessionConclusion]:
        out: list[CrossSessionConclusion] = []

        known = {_normalise(k) for k in (also_known or [])}
        reversed_ids = tuple(
            o.claim_id
            for o in observations
            if o.status == ClaimStatus.SUPERSEDED.value
        )
        churn = (
            f"Decisions about {subject} have been reversed {len(reversed_ids)} times."
        )
        if len(reversed_ids) >= CHURN_THRESHOLD and _normalise(churn) not in known:
            out.append(
                CrossSessionConclusion(
                    statement=churn,
                    kind=MemoryKind.PROCEDURAL,
                    reason=(
                        "the subject has a history of reversal, so the current "
                        "decision should be treated as provisional rather than "
                        "settled"
                    ),
                    basis=reversed_ids,
                )
            )

        contradicted = [
            o for o in observations if o.status == ClaimStatus.CONTRADICTED.value
        ]
        devices = {o.device_id for o in contradicted if o.device_id}
        split = f"Two devices hold incompatible positions about {subject}."
        if len(contradicted) >= 2 and len(devices) >= 2 and _normalise(split) not in known:
            out.append(
                CrossSessionConclusion(
                    statement=split,
                    kind=MemoryKind.PROCEDURAL,
                    reason=(
                        "a disagreement between devices is unresolved, so an "
                        "agent acting here is choosing a side whether it means "
                        "to or not"
                    ),
                    basis=tuple(o.claim_id for o in contradicted),
                )
            )
        return out


SYSTEM_PROMPT = """\
You are given every stored claim about one subject, written over several work \
sessions by several agents on several devices. Decide what holds across them \
that no single claim says.

Return JSON: {"conclusions": [{"statement": ..., "kind": ..., "reason": ...}]}

A statement is a durable assertion in the third person, written so it still \
makes sense a year from now with no surrounding context, and written with the \
person or agent who said it left out. "Datastore choices on Lantern are driven \
by traversal depth." Not "the agent noticed that..." and not "we have decided".

kind is one of:
  episodic   - something established across the sessions taken together.
  procedural - how work on this subject is done. A reusable rule, not an \
instance of following it.
  tacit      - a heuristic nobody stated outright, drawn from the pattern.

reason is why the next agent working on this subject needs to know, in one \
sentence. It is read by that agent, so write it for them.

Things that are only visible across claims, as a guide to what to look for and \
not a list to fill in:

  - a constraint that keeps deciding the outcome, where several decisions were \
made for the same underlying reason;
  - a direction of travel, where the subject has moved consistently one way;
  - an approach that was tried and abandoned, so the next agent does not try it \
again;
  - a dependency between this subject and another that no single claim states.

Hard rules:

Do not restate a claim you were given. If what you would say is already one of \
the inputs, or is one of them reworded, leave it out. You are being asked for \
what is only visible across them.

Do not assert that anything supersedes or contradicts anything. The status of \
each claim is given to you and the relationships between them are decided \
elsewhere; a judgement you make here about which one wins is both wrong and \
unverifiable.

Do not infer anything about the person's character, mood or competence. The \
subject is the work.

Returning {"conclusions": []} is correct and common. Several sessions about one \
subject usually add up to exactly what each of them already said.
"""


class LLMReasoner:
    """Cross-session reasoning through the same OpenAI-compatible provider.

    Composes `LLMExtractor` for the client, the retry behaviour and the key
    handling rather than subclassing it, for the reason `LLMConsolidator` gives:
    a subclass would inherit `extract()`, which asks the activity question and
    is exactly wrong here.

    **Where this runs matters more than for the other two prompts.** Extraction
    sees one incoming record; this sees the stored claims of a whole subject,
    unsealed. That is the `resolver.py:221` exposure with a wider aperture, which
    is why ADR 0025 gates shipping it on step 5 -- the call going out from inside
    the enclave over the existing TLS tunnel. Running it here is correct for
    development and is not the end state.
    """

    def __init__(self, settings: Settings) -> None:
        from .llm import LLMExtractor

        self._inner = LLMExtractor(settings)
        self._model = settings.extraction_model

    @property
    def name(self) -> str:
        return f"llm-reasoner@{self._model}"

    def close(self) -> None:
        self._inner.close()

    def reason(
        self,
        subject: str,
        observations: list[Observation],
        *,
        also_known: list[str] | None = None,
    ) -> list[CrossSessionConclusion]:
        if not observations:
            return []
        payload = {
            "subject": subject,
            "claims": [
                {
                    "statement": o.statement,
                    "status": o.status,
                    # Sessions and devices are named by an opaque short form.
                    # The model needs to know that two claims came from
                    # different places; it has no use for which places, and a
                    # full device id in a prompt is an identifier crossing a
                    # boundary for no reason.
                    "device": _short(o.device_id),
                    "session": _short(o.session_id),
                }
                for o in observations
            ],
        }
        if also_known:
            # Named in the prompt as well as filtered on the way out. Filtering
            # alone would spend the model's attention producing something that
            # is then thrown away, and the interesting case is what it says
            # *given* that these are covered.
            payload["already_concluded"] = list(also_known)
        content = self._inner._post(
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload)},
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0,
            }
        )
        return _parse(content, observations, also_known=also_known)


def _short(value: str | None) -> str | None:
    return value[:8] if value else None


def _parse(
    content: str,
    observations: list[Observation],
    *,
    also_known: list[str] | None = None,
) -> list[CrossSessionConclusion]:
    """What came back, with anything unusable dropped rather than raised.

    One malformed conclusion must not lose the others: this runs over a whole
    subject and a rerun costs the same as the first run, so a partial result is
    worth keeping and an exception is not.
    """
    try:
        parsed = json.loads(_strip_fence(content))
    except json.JSONDecodeError:
        log.warning("reasoning.unparseable len=%d", len(content))
        return []

    seen_inputs = {_normalise(o.statement) for o in observations}
    seen_inputs |= {_normalise(s) for s in (also_known or [])}
    basis = tuple(o.claim_id for o in observations)
    out: list[CrossSessionConclusion] = []
    seen: set[str] = set()
    for raw in parsed.get("conclusions") or []:
        if not isinstance(raw, dict):
            continue
        statement = str(raw.get("statement") or "").strip()
        if not statement:
            continue
        key = _normalise(statement)
        if key in seen_inputs:
            # The prompt forbids restating an input; a model does it anyway. A
            # restatement that got through would be written as a *derived* claim
            # saying what an agent already said, which the resolver would then
            # compare against the original and mark as a duplicate or a
            # contradiction -- noise attributed to the harness.
            log.info("reasoning.dropped_restatement")
            continue
        if key in seen:
            continue
        seen.add(key)
        try:
            kind = MemoryKind(str(raw.get("kind") or "").strip().lower())
        except ValueError:
            # Unknown kind rather than a default: `tacit` raises sensitivity and
            # `procedural` does not, so guessing picks a disclosure level on the
            # model's behalf.
            log.info("reasoning.dropped_unknown_kind kind=%r", raw.get("kind"))
            continue
        reason = str(raw.get("reason") or "").strip()
        if not reason:
            # Same bar `record_decision` sets for an agent: the briefing is built
            # out of the reason, and a derived claim with no stated basis is the
            # least justifiable thing in the record.
            log.info("reasoning.dropped_no_reason")
            continue
        out.append(
            CrossSessionConclusion(
                statement=statement, kind=kind, reason=reason, basis=basis
            )
        )
    return out


_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$")


def _strip_fence(content: str) -> str:
    return _FENCE.sub("", content).strip()


def _normalise(statement: str) -> str:
    return " ".join(statement.lower().split()).rstrip(".!?")


class CompositeReasoner:
    """The rules **and** the model, not the model instead of the rules.

    Written after the live path concluded nothing on a subject whose history had
    three reversals in it -- which the rule-based reasoner finds every time,
    because counting reversals is arithmetic. Choosing one implementation or the
    other made live mode strictly worse than mock at the two patterns that are
    facts about the graph rather than readings of it, which is a silly way to
    lose them.

    So the rules run first and always, and the model is asked what it can add.
    What the rules found is passed to it as already known: the same rule that
    stops it restating an input, extended to stop it restating a conclusion that
    is already being written.
    """

    def __init__(self, settings: Settings) -> None:
        self._rules = RuleBasedReasoner(settings)
        self._llm = LLMReasoner(settings)

    @property
    def name(self) -> str:
        return f"{self._rules.name}+{self._llm.name}"

    def close(self) -> None:
        self._rules.close()
        self._llm.close()

    def reason(
        self,
        subject: str,
        observations: list[Observation],
        *,
        also_known: list[str] | None = None,
    ) -> list[CrossSessionConclusion]:
        structural = self._rules.reason(subject, observations)
        return structural + self._llm.reason(
            subject,
            observations,
            also_known=[*(also_known or []), *(c.statement for c in structural)],
        )


def get_reasoner(settings: Settings):
    """The reasoner this deployment should use.

    Follows `EXTRACTOR`, like `get_consolidator`, and for the same reason -- a
    deployment reasoning with a model while extracting with regexes would
    produce memory whose halves disagree about how much they can be trusted.
    """
    if settings.use_llm_extractor:
        return CompositeReasoner(settings)
    return RuleBasedReasoner(settings)
