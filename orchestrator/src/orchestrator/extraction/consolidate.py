"""Turning a session's working context into memory worth keeping.

A session holds what an agent was working from: the turns so far, what a tool
returned, a scratchpad, the contents of a file it opened. Stored, and
deliberately not searchable. Consolidation is the one thing that moves any of it
into the second state -- and almost all of it should never move.

**A third prompt, not a third model.** The same precedent `extract_page` set:
pointing the activity prompt at a scratchpad produces "the assistant decided
that the migration will use Postgres" -- a claim attributed to nobody, about a
decision nobody made, now in a person's memory as though they had made it. So
this prompt asks a different question. What did this session *conclude* that is
worth keeping after the session is gone, and of what kind.

**Three kinds, and they are not interchangeable.** An episodic claim is what was
decided. A procedural one is how something is done. A tacit one is a heuristic
drawn from experience -- and that last is an inference *about* a person rather
than something they said, which is why labelling one raises its sensitivity and
why the rule-based consolidator below will not produce one at all.

**What this is not allowed to do is summarise.** A session's blocks are a
transcript, and a consolidator that emitted a paragraph per session would turn
the memory into a pile of retrievable documents -- the exact thing the resolved
record exists instead of. So the output is statements: each one a durable
assertion that can be superseded, contradicted and reconciled by machinery that
already exists.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from ..config import Settings
from ..enums import MemoryKind

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You read an AI agent's working notes from one finished work session and decide \
what, if anything, is worth remembering after the session is gone.

Return JSON: {"conclusions": [{"statement": ..., "kind": ..., "reason": ...}]}

A statement is a durable assertion in the third person, written so it still \
makes sense a year from now with no surrounding context. "Project Lantern uses \
Neo4j." Not "we decided to use Neo4j" and not "I chose Neo4j".

kind is one of:
  episodic   - something that was decided or established. A choice, a fact, a \
preference, a convention.
  procedural - how a task is done. A reusable sequence or rule, not an instance \
of doing it.
  tacit      - a heuristic drawn from experience that nobody stated outright.

reason is why this is worth keeping, in one sentence. It is read by the next \
agent to work on this, so write it for them.

Rules you must follow:
- Return an empty list if the session concluded nothing durable. Most sessions \
conclude nothing. An empty list is the correct and common answer.
- Never summarise the session. You are not writing minutes. If a sentence only \
makes sense as a description of what happened, leave it out.
- Never attribute a decision to a person unless the notes say that person made \
it. The agent's own conclusions are the agent's.
- Never invent a tacit claim from a single occurrence. A heuristic needs \
repetition to be one, and a guess about how somebody thinks is the most \
sensitive thing you could write into their memory.
- No commitments. Nothing here owes anybody anything.
"""


@dataclass(frozen=True, slots=True)
class Conclusion:
    """One thing a session concluded that outlives it."""

    statement: str
    kind: MemoryKind
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "kind": self.kind.value,
            "reason": self.reason,
        }


class ConsolidationError(RuntimeError):
    pass


#: Cues the rule-based consolidator recognises, and nothing else. Each one is a
#: thing an agent wrote *deliberately* to mark a conclusion.
_EPISODIC_CUE = re.compile(
    r"^\s*(?:decision|decided|conclusion|concluded)\s*[:\-]\s*(.+)$",
    re.IGNORECASE,
)
_PROCEDURAL_CUE = re.compile(
    r"^\s*(?:procedure|process|workflow|how to|runbook)\s*[:\-]\s*(.+)$",
    re.IGNORECASE,
)
_BECAUSE = re.compile(r"\s+because\s+(.+)$", re.IGNORECASE)


class RuleBasedConsolidator:
    """Deterministic consolidation, for mock mode. Recognises only what was marked.

    It finds a conclusion when a line says so -- ``Decision: ...``,
    ``Procedure: ...`` -- and finds nothing otherwise. That is deliberately
    unintelligent, and the limitation is the feature: a regex cannot tell what a
    session concluded, and one that guessed would write invented claims into a
    real person's memory under an authenticated device id.

    **It never emits a tacit claim.** A tacit claim is an inference about how
    somebody thinks, assembled from watching them. A fixture producing one would
    be the single worst thing in this codebase: unfalsifiable, maximally
    sensitive, and attributed to a real person by a pattern match. The LLM
    consolidator may produce them; this will not, and a test holds that.
    """

    name = "rule-based-consolidator@v1"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def close(self) -> None:
        pass

    def consolidate(self, blocks: list[str]) -> list[Conclusion]:
        out: list[Conclusion] = []
        seen: set[str] = set()
        for block in blocks:
            for line in block.splitlines():
                found = self._line(line)
                if found is None:
                    continue
                if found.statement.lower() in seen:
                    # A scratchpad repeats itself; the record should not. Two
                    # identical conclusions in one session are one conclusion.
                    continue
                seen.add(found.statement.lower())
                out.append(found)
        return out

    def _line(self, line: str) -> Conclusion | None:
        for pattern, kind in (
            (_EPISODIC_CUE, MemoryKind.EPISODIC),
            (_PROCEDURAL_CUE, MemoryKind.PROCEDURAL),
        ):
            match = pattern.match(line)
            if not match:
                continue
            body = match.group(1).strip()
            reason_match = _BECAUSE.search(body)
            if reason_match:
                reason = reason_match.group(1).strip().rstrip(".")
                statement = body[: reason_match.start()].strip()
            else:
                # No stated reason, and none invented. The consolidator says
                # where it came from instead, which is true and useless to
                # nobody -- a fabricated rationale would be worse than a plain
                # one.
                reason = "marked as a conclusion in the agent's own session notes"
                statement = body
            statement = statement.rstrip(".") + "."
            if not statement.strip("."):
                return None
            return Conclusion(statement=statement, kind=kind, reason=reason)
        return None


class LLMConsolidator:
    """Consolidation through the same OpenAI-compatible provider as extraction.

    Wired and unrun against a live API from this repository, like
    `extraction/llm.py`. It reuses the extractor's client and retry behaviour by
    composition rather than inheritance: what differs is one prompt and the shape
    of the answer, and a subclass would inherit `extract()` too -- a method that
    asks the activity question and is exactly wrong for a scratchpad.
    """

    def __init__(self, settings: Settings) -> None:
        from .llm import LLMExtractor

        self._inner = LLMExtractor(settings)
        self._inner.system_prompt = SYSTEM_PROMPT
        self._model = settings.extraction_model

    @property
    def name(self) -> str:
        return f"llm-consolidator@{self._model}"

    def close(self) -> None:
        self._inner.close()

    def consolidate(self, blocks: list[str]) -> list[Conclusion]:
        if not blocks:
            return []
        notes = "\n\n---\n\n".join(blocks)
        content = self._inner._post(
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": notes},
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0,
            }
        )
        return _parse(content)


def _parse(content: str) -> list[Conclusion]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ConsolidationError(f"consolidator returned non-JSON: {exc}") from exc

    out: list[Conclusion] = []
    for raw in payload.get("conclusions", []):
        statement = str(raw.get("statement", "")).strip()
        reason = str(raw.get("reason", "")).strip()
        kind_name = str(raw.get("kind", "")).strip().lower()
        if not statement or not reason:
            # Dropped rather than defaulted. A conclusion with no stated reason
            # is the thing the briefing cannot use, and inventing one here would
            # put words in the model's mouth.
            log.info("consolidate.dropped incomplete conclusion: %r", raw)
            continue
        try:
            kind = MemoryKind(kind_name)
        except ValueError:
            log.info("consolidate.dropped unknown kind %r", kind_name)
            continue
        out.append(Conclusion(statement=statement, kind=kind, reason=reason))
    return out


def get_consolidator(settings: Settings):
    """The consolidator this deployment should use.

    Follows `EXTRACTOR` rather than having its own switch: a deployment running
    rule-based extraction and an LLM consolidator would produce memory whose two
    halves disagree about how much they can be trusted.
    """
    if settings.use_llm_extractor:
        return LLMConsolidator(settings)
    return RuleBasedConsolidator(settings)
