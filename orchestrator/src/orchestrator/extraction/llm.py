"""LLM-backed extractor, over an OpenAI-compatible chat API.

Groq by default. The dependency is the *API shape*, not the vendor: Groq, OpenAI,
Together and a local vLLM all speak `/chat/completions`, so the provider is
`LLM_BASE_URL` and swapping one for another is a setting rather than a rewrite.
Called through `httpx`, which the service already depends on, rather than adding
a vendor SDK for one POST.

Wired so it works the moment a key is present and `ORCHESTRATOR_MODE=live` (or
`EXTRACTOR=llm`); mock mode never constructs it, so no key is needed for local
development or tests.

## The prompt is the extraction quality lever

Three things in it are not stylistic, and getting them wrong produces a record
that looks right and resolves wrong:

**The statement excludes the actor.** The resolver decides supersession by
comparing statements, so "Rafi committed to Mina that the migration lands Friday"
and "Teo committed to Mina that the migration lands Friday" are different topics
and no supersession is found -- which is exactly the reassignment case the
commitment facet exists for. The obligation goes in the statement; who owes it
goes in the facet, where it can change while the obligation stays the same.

**Subjects are what the claim is about, not who said it.** Subject entities drive
`ABOUT` edges and the `claims_about` lookup the resolver uses to find candidates
to compare against. Pointing them at the speaker means a later decision about the
same project never gets compared to the earlier one.

**The model never asserts supersession or contradiction.** It cannot see stored
memory, so that call is the resolver's. Asked anyway, it will confabulate one.
"""

from __future__ import annotations

import json
import logging
import random
import re
import time
from datetime import UTC, datetime

import httpx

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

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You extract structured memory from one raw activity record.

Return JSON only, in exactly this shape:
{"entities": [{"kind": "person|project|artifact|organization|topic", "name": str}],
 "claims": [{"statement": str, "subjects": [str], "confidence": float,
             "commitment": null | {"owed_by": str, "owed_to": str | null,
                                   "due_at": "YYYY-MM-DD" | null}}]}

ENTITIES are the people, projects, artifacts, organizations and topics the record
refers to. Use the shortest natural name ("Lantern", not "project Lantern").

CLAIMS are durable decisions or assertions, not restatements of the record. A
record that settles nothing yields no claims, and returning none is correct.

The STATEMENT is the assertion itself, with the person who made it left out.
Write "project Lantern will use Postgres for durable storage", never "Mina decided
that project Lantern will use Postgres". Who said it is already recorded; the
statement has to be comparable with a later statement about the same thing, and a
name in front of it makes two versions of one decision look like two topics.

SUBJECTS are the entity names the claim is *about* - the project, artifact,
organization or topic. Not the person who said it, and not the person who owes a
commitment. Use names you also returned in "entities".

COMMITMENT is set when the claim is someone undertaking to do something.
"owed_by" and "owed_to" are person names you also returned; "owed_to" is null when
the commitment is to no one in particular, and "due_at" is null when no deadline
is stated. Resolve relative deadlines ("by Friday", "next week") against the
record's occurred_at date. Keep the person out of "statement" here too: who owes
an obligation can change while the obligation stays the same, which is why it is
carried separately.

Never report a commitment as already done: whether it was kept is not visible in
the record that made it.

Never assert that a claim supersedes or contradicts anything. You cannot see
previously stored memory, so that judgement is not yours to make.
"""


class LLMExtractor:
    """One record in, one `Candidate` out. Stateless by design.

    The extractor sees exactly one record and no stored memory, which is what
    keeps it unable to invent a relationship between records -- that is the
    resolver's job, working from what is actually in the graph.
    """

    def __init__(self, settings: Settings) -> None:
        key = settings.llm_api_key
        if not key:
            raise ValueError(
                "no LLM API key: set GROQ_API_KEY (or LLM_API_KEY), or point "
                "LLM_API_KEY_FILE at a file holding one"
            )
        self._settings = settings
        self._model = settings.extraction_model
        self._url = settings.llm_base_url.rstrip("/") + "/chat/completions"
        # One client for the extractor's life: a backfill makes one call per
        # record, and a fresh connection per call would spend more time in TLS
        # handshakes than in inference.
        self._max_attempts = settings.llm_max_attempts
        self._http = httpx.Client(
            timeout=settings.llm_timeout_secs,
            headers={
                "authorization": f"Bearer {key}",
                "content-type": "application/json",
            },
        )

    @property
    def name(self) -> str:
        # Carried onto every object as `Provenance.derived_by`, so it names the
        # model rather than a generic label: two claims extracted by different
        # models are not equally trustworthy, and a reader is entitled to know
        # which produced what.
        return f"llm-extractor@{self._model}"

    def close(self) -> None:
        self._http.close()

    def extract(self, owner_id: str, record: RawRecord) -> Candidate:
        payload = {
            "model": self._model,
            # Extraction is not a creative task and a backfill must be
            # reproducible: the same record re-ingested should produce the same
            # claim ids, which are content-addressed over the statement text.
            "temperature": 0,
            # Server-side JSON mode, so a stray sentence of prose cannot make a
            # record fail to parse. Not every OpenAI-compatible provider honours
            # it, which is why the parse below is still defensive.
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
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
                },
            ],
        }
        parsed = _parse(self._post(payload), record.external_id)
        return _to_candidate(owner_id, record, parsed, self.name)

    def _post(self, payload: dict) -> str:
        """One call, retried on the failures that are expected rather than wrong.

        Rate limits are the normal case for a backfill, not an exception: a
        provider's per-minute token budget is smaller than one person's export,
        so an extractor that gives up on the first 429 cannot ingest anything
        real. Transient 5xx gets the same treatment.

        A 4xx that is not a rate limit is not retried -- a bad key or a
        decommissioned model does not improve by waiting, and retrying it just
        delays the error that explains it.
        """
        last: str = ""
        for attempt in range(self._max_attempts):
            try:
                response = self._http.post(self._url, json=payload)
            except httpx.HTTPError as exc:
                last = f"request failed: {exc}"
                _sleep(_backoff(attempt))
                continue

            if response.status_code == 429 or response.status_code >= 500:
                last = f"{response.status_code}: {response.text[:300]}"
                wait = _retry_after(response) or _backoff(attempt)
                log.warning(
                    "llm %s, retrying in %.1fs (attempt %d/%d)",
                    response.status_code,
                    wait,
                    attempt + 1,
                    self._max_attempts,
                )
                _sleep(wait)
                continue

            if response.status_code >= 400:
                # The body carries the actual reason -- a decommissioned model,
                # a bad key -- and swallowing it turns a one-line fix into an
                # afternoon.
                raise ExtractionError(
                    f"LLM returned {response.status_code}: {response.text[:400]}"
                )
            return _content_of(response.json())

        raise ExtractionError(
            f"LLM unavailable after {self._max_attempts} attempts; last was {last}"
        )


def _content_of(body: dict) -> str:
    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise ExtractionError(f"unexpected LLM response shape: {body}") from exc


def _retry_after(response: httpx.Response) -> float | None:
    """How long the provider asked us to wait.

    The `Retry-After` header when there is one; otherwise the hint providers put
    in the error prose ("try again in 3.39s"), because Groq sends that and not
    the header, and guessing a backoff when the server has told us the number is
    how a backfill takes four times longer than it needs to.
    """
    header = response.headers.get("retry-after")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    match = re.search(r"try again in ([0-9.]+)s", response.text)
    if match:
        # A little past the stated time: landing exactly on it races the
        # provider's own window boundary and earns a second 429.
        return float(match.group(1)) + 0.5
    return None


def _backoff(attempt: int) -> float:
    """Exponential with jitter, capped. Jittered because a backfill issues these
    in a tight loop, and identical sleeps would resynchronise every retry into
    the same instant."""
    return min(2.0 ** attempt, 30.0) * (0.75 + random.random() * 0.5)


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class ExtractionError(RuntimeError):
    """Raised when a record cannot be extracted.

    A distinct type because ingestion has to tell "this provider is broken" from
    "this record produced nothing": the first should stop a backfill, the second
    is an ordinary outcome for a record that settles nothing.
    """


def _parse(content: str, external_id: str) -> dict:
    """Parses the model's reply, tolerating the two things models do anyway.

    JSON mode is requested, and not every provider honours it, so a fenced block
    or a leading sentence is still possible. Recovering here rather than failing
    is worth it because the alternative is losing a whole record to a stray
    newline -- but a reply that is not JSON at all is an error, not an empty
    candidate, since silently extracting nothing from a real record is how a
    backfill reports success having stored almost none of it.
    """
    text = content.strip()
    if text.startswith("```"):
        text = text.split("```")[1] if "```" in text[3:] else text[3:]
        text = text.removeprefix("json").strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ExtractionError(f"record {external_id}: reply contained no JSON object")
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ExtractionError(f"record {external_id}: reply is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ExtractionError(f"record {external_id}: reply is not a JSON object")
    return parsed


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

    # A record that points at another record -- a reply, a commit that closes an
    # issue, a note referencing a thread elsewhere. Declared as
    # "<connector>:<external_id>" because an event id is derived, not something a
    # source knows.
    #
    # These ride on claims as well as on the event, and that is not cosmetic:
    # `why_did_this_shift` promises "the citations present in the superseder that
    # were absent from the claim it replaced -- the evidence that moved the
    # decision". A note that cites a thread and then records a decision has
    # grounded that decision in the thread. The mock extractor was fixed for this
    # (ADR 0006); this one shipped without it, and the eval scored "what changed
    # and why" at 0% as a result.
    referenced = [
        Citation(
            event_id=stable_id("evt", owner_id, *str(ref).split(":", 1)),
            source=SourceRef(
                connector=str(ref).split(":", 1)[0],
                external_id=str(ref).split(":", 1)[-1],
                url=None,
                occurred_at_ms=record.occurred_at_ms,
                ingested_at_ms=ingested_at_ms,
            ),
            quote=None,
        )
        for ref in record.metadata.get("cites", [])
        if ":" in str(ref)
    ]

    def provenance(quote: str, confidence: float) -> Provenance:
        return Provenance(
            citations=[
                Citation(event_id=event_id, source=source, quote=quote),
                *referenced,
            ],
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
