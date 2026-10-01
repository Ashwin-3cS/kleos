"""The labelled question set.

Four categories, from the plan: who decided X, what changed and why, what do I
owe whom, what did I know on date D.

**Ground truth is declared against source records, not object ids.** Two
reasons. The ids are derived (`stable_id` over owner, connector and external
id), so writing them here would be writing hashes into a fixture. More
importantly, it is the only *fair* unit of comparison: a plain RAG baseline
returns chunks of raw text and cannot name a claim id, so scoring on claim ids
would hand the resolved path a win by construction rather than on merit. Both
systems are scored on which source records their answer rests on.

Each question also declares `stale`: records whose content was once the answer
and no longer is. This is the measurement that matters most for the product's
central bet. Returning a stale record is not automatically wrong -- "what
changed and why" *should* return all three storage decisions -- so the metric is
not "did a stale record appear" but "did the answer present stale content
without marking it as superseded". A plain vector index cannot mark anything,
because nothing in the text of a superseded decision says it was superseded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import corpus as c

#: Day offsets reused below, so a time-window question and the record it is
#: meant to exclude cannot drift apart.
BEFORE_NEO4J_DECISION = c.LANTERN_NEO4J.occurred_at_ms - 1


@dataclass(frozen=True, slots=True)
class Question:
    id: str
    #: who_decided | what_changed | what_owed | what_i_knew
    category: str
    text: str
    #: ``(connector, external_id)`` of every record the answer should rest on.
    relevant: tuple[tuple[str, str], ...]
    #: Records that were once the answer and are not now. Scored on whether the
    #: answer marks them, not on whether it returns them.
    stale: tuple[tuple[str, str], ...] = ()
    #: Records that must not appear at all -- a wrong answer, not an old one.
    forbidden: tuple[tuple[str, str], ...] = ()
    #: Narrows the grant for this question, e.g. a time window.
    scope_overrides: dict = field(default_factory=dict)
    #: Why this question is in the set, for whoever reads a regression later.
    rationale: str = ""


def _r(record: c.Record) -> tuple[str, str]:
    return (record.connector, record.external_id)


QUESTIONS: tuple[Question, ...] = (
    Question(
        id="lantern-current-storage",
        category="who_decided",
        text="Which database did Mina decide project Lantern will use for durable storage?",
        relevant=(_r(c.LANTERN_NEO4J),),
        stale=(_r(c.LANTERN_SQLITE), _r(c.LANTERN_POSTGRES)),
        forbidden=(_r(c.HARBOUR_REDIS),),
        rationale=(
            "The headline case. Three statements differing by one word, all lexically "
            "equivalent to the question, and only the graph says which is current. A "
            "vector index has to guess; it has nothing to guess with."
        ),
    ),
    Question(
        id="lantern-storage-history",
        category="what_changed",
        text="What changed about project Lantern's storage decision, and why?",
        relevant=(
            _r(c.LANTERN_SQLITE),
            _r(c.LANTERN_POSTGRES),
            _r(c.LANTERN_NEO4J),
            _r(c.THROUGHPUT_EVIDENCE),
            _r(c.TRAVERSAL_EVIDENCE),
        ),
        rationale=(
            "The two evidence records are the point. They never mention a database by "
            "name, so they are lexically distant from the question and from the "
            "decisions they caused -- reachable by citation edges and by nothing else."
        ),
    ),
    Question(
        id="lantern-migration-owed",
        category="what_owed",
        text="Who owes the project Lantern storage migration, and by when?",
        relevant=(_r(c.MIGRATION_TEO),),
        stale=(_r(c.MIGRATION_RAFI),),
        rationale=(
            "The two records have identical statements and identical deadlines; the "
            "only difference is who owes it, which lives in the commitment facet and "
            "not in the text. Nothing lexical can separate them."
        ),
    ),
    Question(
        id="lantern-storage-as-of-day-28",
        category="what_i_knew",
        text="What was project Lantern's durable storage decision?",
        relevant=(_r(c.LANTERN_POSTGRES),),
        stale=(_r(c.LANTERN_SQLITE),),
        forbidden=(_r(c.LANTERN_NEO4J),),
        scope_overrides={"not_after_ms": BEFORE_NEO4J_DECISION},
        rationale=(
            "'What did I know, and when did I know it' -- asked by narrowing the "
            "grant's time window rather than by a different question. The Neo4j "
            "decision is outside the window and must not appear; Postgres, which was "
            "current at that moment, must. This is the one question where the "
            "permission layer and the retrieval layer have to agree."
        ),
    ),
    Question(
        id="harbour-current-storage",
        category="who_decided",
        text="Which database did Teo decide project Harbour will use for durable storage?",
        relevant=(_r(c.HARBOUR_REDIS),),
        forbidden=(
            _r(c.LANTERN_SQLITE),
            _r(c.LANTERN_POSTGRES),
            _r(c.LANTERN_NEO4J),
        ),
        rationale=(
            "The distractor check, and the one question where the resolved path could "
            "plausibly do *worse*: graph proximity pulls in neighbours, and if it "
            "pulls Lantern's storage decisions into a Harbour question then proximity "
            "is hurting. A metric that cannot lose on any question is not measuring."
        ),
    ),
    Question(
        id="harbour-docs-owed",
        category="what_owed",
        text="Who committed to publishing the project Harbour API documentation?",
        relevant=(_r(c.HARBOUR_DOCS),),
        forbidden=(_r(c.MIGRATION_TEO), _r(c.MIGRATION_RAFI)),
        rationale="A commitment with no competing version, as a control for the one above.",
    ),
)


def by_category() -> dict[str, list[Question]]:
    out: dict[str, list[Question]] = {}
    for question in QUESTIONS:
        out.setdefault(question.category, []).append(question)
    return out
