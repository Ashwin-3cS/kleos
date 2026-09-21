"""Claude-backed extractor.

Wired so it works the moment ``ANTHROPIC_API_KEY`` is set and
``ORCHESTRATOR_MODE=live``; mock mode never constructs it, so no key is
required for local development or tests. The prompt deliberately forbids
the model from asserting supersession or contradiction -- it cannot see
stored memory, so that call is the resolver's.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime

from ..config import Settings
from ..enums import EntityKind, FulfillmentStatus
from ..permissions import ObjectAcl, Sensitivity
from ..schema import (
    Candidate,
    Citation,
    Claim,
    ClaimStatus,
    Commitment,
    Entity,
    Event,
    Provenance,
    RawRecord,
    SourceRef,
)
from .ids import stable_id

SYSTEM_PROMPT = """\
You extract structured memory from one raw activity record.

Return JSON only: {"entities": [{"kind": "person|project|artifact|organization|topic", \
"name": str}], "claims": [{"statement": str, "subjects": [str], "confidence": float, \
"commitment": null | {"owed_by": str, "owed_to": str | null, "due_at": "YYYY-MM-DD" | null}}]}.

A claim is a durable decision or assertion, not a restatement of the record. \
Subjects are entity names you also returned. Never assert that a claim supersedes or \
contradicts anything: you cannot see previously stored memory.

Set "commitment" when the claim is someone undertaking to do something. "owed_by" and \
"owed_to" are person entity names you also returned; use null for "owed_to" when the \
commitment is to no one in particular, and null for "due_at" when no deadline is stated. \
Resolve relative deadlines ("by Friday", "next week") against the record's occurred_at \
date. Keep the person out of "statement": write the obligation itself ("project Atlas \
will ship the storage migration by 2025-02-14"), because who owes it is carried by the \
commitment fields and can change while the obligation stays the same. Never report a \
commitment as done -- whether it was kept is not visible in the record that made it.
"""


class LLMExtractor:
    name = "claude-extractor@v1"

    def __init__(self, settings: Settings) -> None:
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is required when ORCHESTRATOR_MODE=live")
        from langchain_anthropic import ChatAnthropic

        self._settings = settings
        self._model = ChatAnthropic(
            model=settings.extraction_model,
            api_key=settings.anthropic_api_key,
            max_tokens=2048,
            temperature=0,
        )

    def extract(self, owner_id: str, record: RawRecord) -> Candidate:
        response = self._model.invoke(
            [
                ("system", SYSTEM_PROMPT),
                (
                    "human",
                    json.dumps(
                        {
                            "title": record.title,
                            "body": record.body,
                            # So the model can resolve "by Friday" without
                            # guessing what day the record is from.
                            "occurred_at": datetime.fromtimestamp(
                                record.occurred_at_ms / 1000, tz=UTC
                            ).strftime("%Y-%m-%d"),
                        }
                    ),
                ),
            ]
        )
        parsed = json.loads(_text_of(response))
        return _to_candidate(owner_id, record, parsed, self.name)


def _text_of(response: object) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return str(content)


def _due_ms(date: str | None) -> int | None:
    if not date:
        return None
    try:
        parsed = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        # A deadline the model got wrong is dropped, not fatal: the
        # commitment itself is still worth recording without one.
        return None
    return int(parsed.timestamp() * 1000)


def _commitment_of(raw: dict | None, by_name: dict) -> tuple[Commitment | None, list]:
    """Maps the model's commitment block onto the facet.

    Returns ``(None, [])`` unless the party who owes it resolves to an entity
    the model also returned -- a commitment with no identifiable owner is not
    answerable by "what does X still owe", so it is better dropped to a plain
    claim than stored pointing at nothing.
    """
    if not raw:
        return None, []
    owed_by = by_name.get(str(raw.get("owed_by", "")).lower())
    if owed_by is None:
        return None, []
    owed_to = by_name.get(str(raw.get("owed_to") or "").lower())
    return (
        Commitment(
            owed_by_entity_id=owed_by.id,
            owed_to_entity_id=owed_to.id if owed_to else None,
            due_at_ms=_due_ms(raw.get("due_at")),
            fulfillment=FulfillmentStatus.OPEN,
            settled_at_ms=None,
        ),
        [owed_by, *([owed_to] if owed_to else [])],
    )


def _to_candidate(owner_id: str, record: RawRecord, parsed: dict, derived_by: str) -> Candidate:
    ingested_at_ms = int(time.time() * 1000)
    source = SourceRef(
        connector=record.connector,
        external_id=record.external_id,
        url=record.url,
        occurred_at_ms=record.occurred_at_ms,
        ingested_at_ms=ingested_at_ms,
    )
    event_id = stable_id("evt", owner_id, record.connector, record.external_id)
    sensitivity = Sensitivity.CONFIDENTIAL if record.sensitive else Sensitivity.PERSONAL

    def provenance(quote: str, confidence: float) -> Provenance:
        return Provenance(
            citations=[Citation(event_id=event_id, source=source, quote=quote)],
            derived_by=derived_by,
            confidence=confidence,
            created_at_ms=ingested_at_ms,
        )

    def acl(kinds: list[EntityKind]) -> ObjectAcl:
        return ObjectAcl(
            owner_id=owner_id,
            sources=[record.connector],
            sensitivity=sensitivity,
            entity_kinds=kinds,
            occurred_at_ms=record.occurred_at_ms,
            denied_agents=[],
        )

    entities: list[Entity] = []
    by_name: dict[str, Entity] = {}
    for raw in parsed.get("entities", []):
        kind = EntityKind(raw["kind"])
        name = raw["name"]
        entity = Entity(
            id=stable_id("ent", owner_id, kind.value, name.lower()),
            owner_id=owner_id,
            kind=kind,
            name=name,
            aliases=raw.get("aliases", []),
            first_seen_at_ms=record.occurred_at_ms,
            last_seen_at_ms=record.occurred_at_ms,
            provenance=provenance(name, 0.9),
            acl=acl([kind]),
        )
        entities.append(entity)
        by_name[name.lower()] = entity

    kinds = sorted({e.kind for e in entities}, key=lambda k: k.value)
    event = Event(
        id=event_id,
        owner_id=owner_id,
        summary=record.title,
        body=None if record.sensitive else record.body,
        entity_ids=[e.id for e in entities],
        source=source,
        encrypted_content=None,
        provenance=provenance(record.title, 1.0),
        acl=acl(kinds),
    )

    claims: list[Claim] = []
    for raw in parsed.get("claims", []):
        subjects = [by_name[s.lower()] for s in raw.get("subjects", []) if s.lower() in by_name]
        commitment, parties = _commitment_of(raw.get("commitment"), by_name)
        claims.append(
            Claim(
                id=stable_id("clm", owner_id, event_id, raw["statement"]),
                owner_id=owner_id,
                statement=raw["statement"],
                subject_entity_ids=[e.id for e in subjects],
                status=ClaimStatus.ACTIVE,
                supersedes=[],
                contradicts=[],
                reconciled_into=None,
                commitment=commitment,
                asserted_at_ms=record.occurred_at_ms,
                provenance=provenance(raw["statement"], float(raw.get("confidence", 0.7))),
                # The parties are part of what the object is about, so a scope
                # that excludes persons must not see the commitment.
                acl=acl(sorted({e.kind for e in [*subjects, *parties]}, key=lambda k: k.value)),
            )
        )

    return Candidate(entities=entities, events=[event], claims=claims)
