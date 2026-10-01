"""A labelled corpus for the eval harness.

Entirely synthetic. Fictional people, fictional projects, no real personal data
anywhere in it -- which is a working rule of the plan and also the only way a
corpus can live in a public repo.

It is written to the mock extractor's grammar on purpose
(`<Person> decided that project <X> will ...`, `<Person> committed to <Person>
that ... by <date>`), because the harness measures **retrieval and
resolution**, not extraction coverage. If the extractor silently failed to
produce a claim, every metric below would move and the cause would look like a
ranking problem. Extraction quality is its own measurement, against a live LLM,
and it is the next Phase 0 item.

What the corpus is shaped to contain:

- **A decision that moved twice**, each time with new evidence cited from
  another source: Sqlite -> Postgres -> Neo4j. This is the case the whole
  product is a bet on, and the case a plain vector index cannot represent --
  all three statements are lexically near-identical, and nothing in the text
  says which one is current.
- **A commitment that was reassigned** with an identical statement and
  deadline, so the only difference is the facet. Tests that "what do I owe
  whom" returns one obligation rather than two.
- **A second project with a parallel storage decision**, as a lexical
  distractor: "which database does Harbour use" must not answer with Lantern's.
- **Filler** that mentions the same people without asserting anything, so the
  corpus has a realistic ratio of signal to chatter and recall is not trivially
  1.0.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..config import Settings
from ..connectors.base import ConnectorSpec, pack_paragraphs
from ..schema import RawRecord

#: Three sources, so a multi-source ACL is exercised and a citation can cross
#: connectors the way the context-chain read exists to show.
NOTES = "eval_notes"
CHAT = "eval_chat"
TRACKER = "eval_tracker"

SOURCES = (NOTES, CHAT, TRACKER)

_DAY = 86_400_000
#: 2026-01-05T00:00:00Z. Fixed, not "now", so every run scores the same corpus:
#: a recency term computed against a moving clock would make yesterday's
#: measurement incomparable with today's.
T0 = 1_767_571_200_000


def _at(day: int, hour: int = 9) -> int:
    return T0 + day * _DAY + hour * 3_600_000


@dataclass(frozen=True, slots=True)
class Record:
    connector: str
    external_id: str
    title: str
    body: str
    occurred_at_ms: int
    participants: tuple[str, ...] = ()
    cites: tuple[str, ...] = ()
    sensitive: bool = False
    #: The claim this record asserts, as the extractor will phrase it. Empty for
    #: a record that asserts nothing.
    #:
    #: It exists so the harness can ask whether an answer *presented* a stale
    #: assertion, rather than whether it merely touched a record that once
    #: contained one. The two are different: an event ("Lantern kickoff notes",
    #: day 0) is a timestamped fact that never stops being true, while the claim
    #: it produced ("will use Sqlite") stops being current the moment something
    #: supersedes it. Only the second can be stale.
    assertion: str = ""

    def to_raw(self) -> RawRecord:
        return RawRecord(
            external_id=self.external_id,
            connector=self.connector,
            occurred_at_ms=self.occurred_at_ms,
            title=self.title,
            body=self.body,
            url=f"https://example.invalid/{self.connector}/{self.external_id}",
            sensitive=self.sensitive,
            participants=list(self.participants),
            metadata={"cites": list(self.cites)} if self.cites else {},
        )


# -- the storage decision, which moves twice -----------------------------

LANTERN_SQLITE = Record(
    connector=NOTES,
    external_id="lantern-kickoff",
    title="Lantern kickoff notes",
    body=(
        "First planning session for the prototype.\n\n"
        "Mina decided that project Lantern will use Sqlite for durable storage."
    ),
    occurred_at_ms=_at(0),
    participants=("Mina", "Rafi"),
    assertion="project Lantern will use Sqlite for durable storage",
)

THROUGHPUT_EVIDENCE = Record(
    connector=CHAT,
    external_id="throughput-thread",
    title="Write throughput on the ingest path",
    body=(
        "Load test from this morning.\n\n"
        "Sena noted that project Lantern will exceed Sqlite write throughput "
        "at ten thousand events per minute."
    ),
    occurred_at_ms=_at(9),
    participants=("Sena", "Rafi"),
    assertion="project Lantern will exceed Sqlite write throughput",
)

LANTERN_POSTGRES = Record(
    connector=NOTES,
    external_id="lantern-storage-revisited",
    title="Storage decision revisited after the load test",
    body=(
        "Following the throughput numbers from the ingest thread.\n\n"
        "Mina decided that project Lantern will use Postgres for durable storage."
    ),
    occurred_at_ms=_at(11),
    participants=("Mina", "Sena"),
    cites=(f"{CHAT}:throughput-thread",),
    assertion="project Lantern will use Postgres for durable storage",
)

TRAVERSAL_EVIDENCE = Record(
    connector=CHAT,
    external_id="traversal-thread",
    title="The neighbourhood view needs multi-hop traversal",
    body=(
        "Prototyping the explorer against the relational schema.\n\n"
        "Sena noted that project Lantern will need recursive traversal for the "
        "neighbourhood view."
    ),
    occurred_at_ms=_at(26),
    participants=("Sena", "Mina"),
    assertion="project Lantern will need recursive traversal",
)

LANTERN_NEO4J = Record(
    connector=NOTES,
    external_id="lantern-storage-final",
    title="Storage decision after the traversal prototype",
    body=(
        "The recursive query work made the relational option much worse.\n\n"
        "Mina decided that project Lantern will use Neo4j for durable storage."
    ),
    occurred_at_ms=_at(29),
    participants=("Mina", "Sena"),
    cites=(f"{CHAT}:traversal-thread",),
    assertion="project Lantern will use Neo4j for durable storage",
)

# -- a commitment, then reassigned ---------------------------------------

MIGRATION_RAFI = Record(
    connector=TRACKER,
    external_id="migration-assigned",
    title="Storage migration assigned",
    body=(
        "Rafi committed to Mina that project Lantern will complete the storage "
        "migration by 2026-03-20."
    ),
    occurred_at_ms=_at(31),
    participants=("Rafi", "Mina"),
    assertion="project Lantern will complete the storage migration by 2026-03-20",
)

MIGRATION_TEO = Record(
    connector=TRACKER,
    external_id="migration-reassigned",
    title="Storage migration reassigned",
    body=(
        "Rafi is on the ingest path for the rest of the quarter.\n\n"
        "Teo committed to Mina that project Lantern will complete the storage "
        "migration by 2026-03-20."
    ),
    occurred_at_ms=_at(38),
    participants=("Teo", "Mina", "Rafi"),
    assertion="project Lantern will complete the storage migration by 2026-03-20",
)

# -- the distractor project ----------------------------------------------

HARBOUR_REDIS = Record(
    connector=NOTES,
    external_id="harbour-kickoff",
    title="Harbour kickoff notes",
    body=(
        "Separate workstream, separate stack.\n\n"
        "Teo decided that project Harbour will use Redis for durable storage."
    ),
    occurred_at_ms=_at(4),
    participants=("Teo", "Sena"),
    assertion="project Harbour will use Redis for durable storage",
)

HARBOUR_DOCS = Record(
    connector=TRACKER,
    external_id="harbour-docs",
    title="API documentation owner",
    body=(
        "Sena committed to Teo that project Harbour will publish the API "
        "documentation by 2026-04-10."
    ),
    occurred_at_ms=_at(12),
    participants=("Sena", "Teo"),
    assertion="project Harbour will publish the API documentation by 2026-04-10",
)

HARBOUR_ONBOARDING = Record(
    connector=CHAT,
    external_id="harbour-standup",
    title="Harbour standup",
    body=(
        "Short sync, nothing blocking.\n\n"
        "Teo noted that project Harbour will ship the onboarding flow before "
        "the storage work starts."
    ),
    occurred_at_ms=_at(16),
    participants=("Teo",),
    assertion="project Harbour will ship the onboarding flow",
)

# -- filler: people and projects, no assertions --------------------------

_FILLER = (
    Record(
        connector=CHAT,
        external_id="filler-coffee",
        title="Offsite logistics",
        body="Mina and Rafi sorted out the room booking for the offsite.",
        occurred_at_ms=_at(2),
        participants=("Mina", "Rafi"),
    ),
    Record(
        connector=CHAT,
        external_id="filler-review",
        title="Review queue is long",
        body="Sena mentioned the review queue has eleven open items this week.",
        occurred_at_ms=_at(7),
        participants=("Sena",),
    ),
    Record(
        connector=NOTES,
        external_id="filler-retro",
        title="Retro notes",
        body=(
            "The team talked about the prototype pace. Storage came up but "
            "nothing was settled in this session."
        ),
        occurred_at_ms=_at(14),
        participants=("Mina", "Rafi", "Sena", "Teo"),
    ),
    Record(
        connector=TRACKER,
        external_id="filler-ticket",
        title="Flaky test in the ingest suite",
        body="Rafi picked up the flaky test on the ingest path.",
        occurred_at_ms=_at(19),
        participants=("Rafi",),
    ),
    Record(
        connector=CHAT,
        external_id="filler-storage-chatter",
        title="Database opinions",
        body=(
            "General chatter about databases. Someone linked a Postgres blog "
            "post and someone else linked a Neo4j one. No decision here."
        ),
        occurred_at_ms=_at(22),
        participants=("Rafi", "Teo"),
    ),
    Record(
        connector=NOTES,
        external_id="filler-hiring",
        title="Hiring loop notes",
        body="Mina wrote up the interview loop for the open role.",
        occurred_at_ms=_at(34),
        participants=("Mina",),
    ),
    *(
        # Bulk filler, so that returning `top_k` results is a *choice* rather
        # than returning most of the corpus. With 16 records and top_k=8 both
        # systems scored ~95% recall by handing back half of everything, which
        # measures nothing: recall@k approaches 1 as k approaches N whatever the
        # ranking does. These are deliberately on-topic enough to be plausible
        # competitors (the same people, the same two projects, storage words)
        # without asserting anything, which is the hard case for a lexical
        # matcher and the honest test for ranking.
        Record(
            connector=connector,
            external_id=f"filler-{slug}",
            title=title,
            body=body,
            occurred_at_ms=_at(day, hour),
            participants=people,
        )
        for connector, slug, title, body, day, hour, people in (
            (
                CHAT, "standup-1", "Monday standup",
                "Rafi is on the ingest path, Sena is on the load tests, Mina is "
                "writing up the storage options.", 1, 10, ("Mina", "Rafi", "Sena"),
            ),
            (
                CHAT, "standup-2", "Monday standup",
                "Sena finished the load tests. Storage options still open.",
                8, 10, ("Sena", "Mina"),
            ),
            (
                CHAT, "standup-3", "Monday standup",
                "Rafi asked whether the storage decision was settled. Mina said "
                "not yet.", 15, 10, ("Rafi", "Mina"),
            ),
            (
                CHAT, "standup-4", "Monday standup",
                "Mina is prototyping the neighbourhood view against the current "
                "schema.", 22, 10, ("Mina", "Sena"),
            ),
            (
                CHAT, "standup-5", "Monday standup",
                "Teo is on Harbour onboarding. Sena is on Harbour docs.",
                23, 10, ("Teo", "Sena"),
            ),
            (
                NOTES, "options-memo", "Storage options memo",
                "A list of candidate databases with rough notes on each: Sqlite, "
                "Postgres, Neo4j, Redis. No recommendation in this memo.",
                6, 14, ("Mina",),
            ),
            (
                NOTES, "schema-sketch", "Schema sketch",
                "Rough tables for events and claims. Independent of which "
                "database ends up underneath.", 13, 14, ("Mina", "Rafi"),
            ),
            (
                NOTES, "explorer-sketch", "Explorer page sketch",
                "A drawing of the neighbourhood view with nodes coloured by "
                "label.", 24, 14, ("Sena",),
            ),
            (
                NOTES, "offsite-agenda", "Offsite agenda",
                "Three sessions: roadmap, storage, hiring. Mina to run the "
                "storage one.", 3, 14, ("Mina", "Rafi", "Sena", "Teo"),
            ),
            (
                NOTES, "quarter-goals", "Quarter goals",
                "Ship the Lantern prototype and the Harbour onboarding flow.",
                5, 14, ("Mina", "Teo"),
            ),
            (
                TRACKER, "ticket-ingest-retry", "Retry on ingest failure",
                "Rafi is adding a retry to the ingest path.", 10, 11, ("Rafi",),
            ),
            (
                TRACKER, "ticket-load-harness", "Load test harness",
                "Sena built the harness used for the throughput numbers.",
                7, 11, ("Sena",),
            ),
            (
                TRACKER, "ticket-explorer", "Explorer page",
                "Sena is building the neighbourhood view page.", 25, 11, ("Sena",),
            ),
            (
                TRACKER, "ticket-harbour-auth", "Harbour auth flow",
                "Teo is wiring the Harbour login.", 17, 11, ("Teo",),
            ),
            (
                TRACKER, "ticket-docs-outline", "Docs outline",
                "Sena drafted an outline for the Harbour API documentation.",
                13, 11, ("Sena",),
            ),
            (
                TRACKER, "ticket-migration-plan", "Migration plan",
                "A checklist for moving the prototype data across, whoever ends "
                "up owning it.", 30, 11, ("Rafi", "Mina"),
            ),
            (
                CHAT, "storage-aside", "Aside about indexes",
                "Rafi and Sena talked about vector indexes in general, not about "
                "project Lantern specifically.", 20, 16, ("Rafi", "Sena"),
            ),
            (
                CHAT, "harbour-aside", "Aside about queues",
                "Teo mentioned queue semantics without deciding anything.",
                21, 16, ("Teo", "Rafi"),
            ),
        )
    ),
)

RECORDS: tuple[Record, ...] = (
    LANTERN_SQLITE,
    HARBOUR_REDIS,
    THROUGHPUT_EVIDENCE,
    LANTERN_POSTGRES,
    HARBOUR_DOCS,
    HARBOUR_ONBOARDING,
    TRAVERSAL_EVIDENCE,
    LANTERN_NEO4J,
    MIGRATION_RAFI,
    MIGRATION_TEO,
    *_FILLER,
)


def by_id(key: tuple[str, str]) -> Record:
    """The record named by ``(connector, external_id)``.

    Ground truth is declared in those terms (see ``questions.py``), so this is
    how a question's labels get back to the text they were labelled against.
    """
    for record in RECORDS:
        if (record.connector, record.external_id) == key:
            return record
    raise KeyError(key)


def records() -> tuple[Record, ...]:
    """Chronological, as a connector would yield them."""
    return tuple(sorted(RECORDS, key=lambda r: r.occurred_at_ms))


class EvalConnector:
    """Yields the corpus for one source id.

    One connector instance per source so the corpus spans three sources
    without the registry needing to know anything special about it -- which is
    the property `tests/test_connector_registry.py` exists to hold, reused here.
    """

    def __init__(self, source_id: str) -> None:
        self.name = source_id
        self._source_id = source_id

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        for record in records():
            if record.connector == self._source_id and record.occurred_at_ms >= since_ms:
                yield record.to_raw()


def specs() -> tuple[ConnectorSpec, ...]:
    return tuple(
        ConnectorSpec(
            source_id=source,
            display_name=f"eval corpus ({source})",
            factory=lambda settings, s=source: EvalConnector(s),
            chunker=pack_paragraphs(400),
            mock_factory=lambda settings, s=source: EvalConnector(s),
        )
        for source in SOURCES
    )


def register(registry) -> None:
    for spec in specs():
        registry.register(spec)


def settings_for(base: Settings) -> Settings:
    """Settings that can ingest the corpus regardless of ENABLED_SOURCES."""
    return base.model_copy(update={"enabled_sources": list(SOURCES)})
