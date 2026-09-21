"""Rule-based extractor used in mock mode and in tests.

Deterministic and offline: no API key, no network. It recognises a narrow
fixture grammar ("<Person> decided/agreed/noted that project <Project> will
<...>") which is enough to produce every shape the rest of the pipeline has
to handle -- overlapping entities across records, claims about the same
subject that later conflict, and commitments ("<Person> committed to
<Person> that project <Project> will <...> by <YYYY-MM-DD>").
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime

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

NAME = "mock-extractor@v1"

_PROJECT_RE = re.compile(r"\bproject ([A-Z][A-Za-z0-9_-]*)")
_ARTIFACT_RE = re.compile(r"\buse ([A-Z][A-Za-z0-9_+.-]*)")
_CLAIM_RE = re.compile(
    r"([A-Z][a-z]+) (?:decided|agreed|noted|recorded) that (project [A-Za-z0-9_-]+ will [^.]+)"
)
# "Alice committed to Bob that project Atlas will ship the migration by 2025-02-14."
# The owed-to clause and the deadline are both optional, matching the schema.
_COMMITMENT_RE = re.compile(
    r"([A-Z][a-z]+) committed(?: to ([A-Z][a-z]+))? that "
    r"(project [A-Za-z0-9_-]+ will [^.]+?)"
    r"(?: by (\d{4}-\d{2}-\d{2}))?\."
)


def _due_ms(date: str | None) -> int | None:
    if not date:
        return None
    return int(
        datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=UTC).timestamp() * 1000
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


class MockExtractor:
    name = NAME

    def extract(self, owner_id: str, record: RawRecord) -> Candidate:
        ingested_at_ms = _now_ms()
        source = SourceRef(
            connector=record.connector,
            external_id=record.external_id,
            url=record.url,
            occurred_at_ms=record.occurred_at_ms,
            ingested_at_ms=ingested_at_ms,
        )
        event_id = stable_id("evt", owner_id, record.connector, record.external_id)

        text = f"{record.title}. {record.body}"
        entities: list[Entity] = []
        seen: set[str] = set()

        def add_entity(kind: EntityKind, name: str) -> Entity:
            entity_id = stable_id("ent", owner_id, kind.value, name.lower())
            existing = next((e for e in entities if e.id == entity_id), None)
            if existing is not None:
                return existing
            entity = Entity(
                id=entity_id,
                owner_id=owner_id,
                kind=kind,
                name=name,
                aliases=[],
                first_seen_at_ms=record.occurred_at_ms,
                last_seen_at_ms=record.occurred_at_ms,
                provenance=Provenance(
                    citations=[Citation(event_id=event_id, source=source, quote=name)],
                    derived_by=NAME,
                    confidence=0.9,
                    created_at_ms=ingested_at_ms,
                ),
                acl=_acl(owner_id, record, [kind]),
            )
            entities.append(entity)
            seen.add(entity_id)
            return entity

        for person in record.participants:
            add_entity(EntityKind.PERSON, person)
        for match in _CLAIM_RE.finditer(text):
            add_entity(EntityKind.PERSON, match.group(1))
        for match in _COMMITMENT_RE.finditer(text):
            add_entity(EntityKind.PERSON, match.group(1))
            if match.group(2):
                add_entity(EntityKind.PERSON, match.group(2))
        for match in _PROJECT_RE.finditer(text):
            add_entity(EntityKind.PROJECT, match.group(1))
        for match in _ARTIFACT_RE.finditer(text):
            add_entity(EntityKind.ARTIFACT, match.group(1))

        kinds = sorted({e.kind for e in entities}, key=lambda k: k.value)
        citations = [Citation(event_id=event_id, source=source, quote=record.title)]
        # A record that points at another record -- a reply, a commit that
        # closes an issue, a note referencing a thread elsewhere. Declared as
        # "<connector>:<external_id>" because an event id is derived, not
        # something a source knows. This is what makes CITES cross
        # connectors, and the ingestion graph already turns it into an edge.
        for reference in record.metadata.get("cites", []):
            connector, _, external_id = str(reference).partition(":")
            citations.append(
                Citation(
                    event_id=stable_id("evt", owner_id, connector, external_id),
                    # These timestamps are the *reference's*; the cited event
                    # carries its own, which is what a reader should use.
                    source=SourceRef(
                        connector=connector,
                        external_id=external_id,
                        url=None,
                        occurred_at_ms=record.occurred_at_ms,
                        ingested_at_ms=ingested_at_ms,
                    ),
                    quote=None,
                )
            )

        event = Event(
            id=event_id,
            owner_id=owner_id,
            summary=record.title,
            body=None if record.sensitive else record.body,
            entity_ids=[e.id for e in entities],
            source=source,
            encrypted_content=None,
            provenance=Provenance(
                citations=citations,
                derived_by=NAME,
                confidence=1.0,
                created_at_ms=ingested_at_ms,
            ),
            acl=_acl(owner_id, record, kinds),
        )

        claims: list[Claim] = []
        for match in _CLAIM_RE.finditer(text):
            statement = f"{match.group(2).strip()}."
            subject_ids = [
                e.id for e in entities if e.kind in (EntityKind.PROJECT, EntityKind.ARTIFACT)
            ]
            claims.append(
                Claim(
                    id=stable_id("clm", owner_id, event_id, statement),
                    owner_id=owner_id,
                    statement=statement,
                    subject_entity_ids=subject_ids,
                    status=ClaimStatus.ACTIVE,
                    supersedes=[],
                    contradicts=[],
                    reconciled_into=None,
                    asserted_at_ms=record.occurred_at_ms,
                    provenance=Provenance(
                        citations=[
                            Citation(event_id=event_id, source=source, quote=match.group(0))
                        ],
                        derived_by=NAME,
                        confidence=0.8,
                        created_at_ms=ingested_at_ms,
                    ),
                    acl=_acl(
                        owner_id,
                        record,
                        sorted(
                            {
                                e.kind
                                for e in entities
                                if e.kind in (EntityKind.PROJECT, EntityKind.ARTIFACT)
                            },
                            key=lambda k: k.value,
                        ),
                    ),
                )
            )

        # A commitment is a claim with a facet, produced by the same path as
        # any other claim: who owes it lives in the facet, not in the
        # statement text, so a reassignment is a new claim about the same
        # obligation rather than a new topic.
        for match in _COMMITMENT_RE.finditer(text):
            owed_by, owed_to, obligation, due = match.groups()
            statement = obligation.strip()
            if due:
                statement = f"{statement} by {due}"
            statement = f"{statement}."
            subjects = [
                e for e in entities if e.kind in (EntityKind.PROJECT, EntityKind.ARTIFACT)
            ]
            parties = [add_entity(EntityKind.PERSON, owed_by)]
            if owed_to:
                parties.append(add_entity(EntityKind.PERSON, owed_to))
            claims.append(
                Claim(
                    id=stable_id("clm", owner_id, event_id, statement),
                    owner_id=owner_id,
                    statement=statement,
                    subject_entity_ids=[e.id for e in subjects],
                    status=ClaimStatus.ACTIVE,
                    supersedes=[],
                    contradicts=[],
                    reconciled_into=None,
                    commitment=Commitment(
                        owed_by_entity_id=parties[0].id,
                        owed_to_entity_id=parties[1].id if owed_to else None,
                        due_at_ms=_due_ms(due),
                        # An extractor can see a promise being made; it cannot
                        # see it being kept. Fulfillment only ever moves later.
                        fulfillment=FulfillmentStatus.OPEN,
                        settled_at_ms=None,
                    ),
                    asserted_at_ms=record.occurred_at_ms,
                    provenance=Provenance(
                        citations=[
                            Citation(event_id=event_id, source=source, quote=match.group(0))
                        ],
                        derived_by=NAME,
                        confidence=0.8,
                        created_at_ms=ingested_at_ms,
                    ),
                    # The parties are part of what this object is about, so a
                    # scope that excludes persons must not see it.
                    acl=_acl(
                        owner_id,
                        record,
                        sorted(
                            {e.kind for e in [*subjects, *parties]},
                            key=lambda k: k.value,
                        ),
                    ),
                )
            )

        return Candidate(entities=entities, events=[event], claims=claims)


def _acl(owner_id: str, record: RawRecord, kinds: list[EntityKind]) -> ObjectAcl:
    return ObjectAcl(
        owner_id=owner_id,
        sources=[record.connector],
        sensitivity=Sensitivity.CONFIDENTIAL if record.sensitive else Sensitivity.PERSONAL,
        entity_kinds=kinds,
        occurred_at_ms=record.occurred_at_ms,
        denied_agents=[],
    )
