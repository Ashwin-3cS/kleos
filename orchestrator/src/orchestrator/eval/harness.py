"""Runs both paths over the labelled corpus and reports the difference.

This is step 0's exit test (see the root README, "Where this is going"). The
instruction there is explicit: *if resolution does not help, stop and rethink
before building further.* So the
harness is built to be able to say no. Two of the six questions exist
specifically as cases where the resolved path could lose -- a distractor project
whose storage decision graph proximity might drag in, and a commitment with no
competing version where the extra machinery buys nothing.

## What is measured

**recall / precision over source records.** Both systems' answers reduce to the
set of records they rest on, because the baseline cannot name a claim id. See
`questions.py`.

**unmarked-stale rate.** The metric the product's central bet lives or dies on.
A stale record appearing is not automatically wrong -- "what changed and why"
should return all three storage decisions -- so this counts answers that present
superseded content *without saying it is superseded*.

The rule, fixed before the numbers were looked at, is that only an **assertion**
can be stale. A claim asserts ("project Lantern will use Sqlite") and stops
being current when something supersedes it. An event records ("Lantern kickoff
notes", day 0) and never stops being true; the answer line for an event is its
title, which asserts nothing about any database. A first version of this metric
counted any returned object belonging to a stale *record*, which scored the
resolved path at 50% unmarked-stale while it was in fact marking every stale
claim correctly -- the penalty was entirely events. So: for the resolved path,
a returned Claim whose record is stale and whose status is still `active`. For
the baseline, a returned chunk whose text contains the stale assertion -- which
is always unmarked, because nothing in the text of a superseded decision says it
was superseded. That 0% is structural, not a failure of this particular
baseline, and no amount of embedding quality would change it.

**forbidden rate.** Records that are a wrong answer rather than an old one.

**cited rate.** Whether every returned object carries a citation back to a
source event. Also structural for the baseline, and also worth stating: a chunk
of text is its own provenance, which is not the same thing as a chain.

## What is deliberately not claimed

The absolute numbers are close to meaningless right now, because both paths run
on `HashedTokenEmbedder` -- stable, non-semantic, no API key. That is the right
*control* (embedding quality is held identical, so the delta isolates
resolution) and it is a poor absolute measurement. The next step 0 item is a
real embedder, and the first thing to do after wiring it is re-run this and
compare deltas, not scores.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from ..enums import EntityKind, Sensitivity
from ..graphs.history import why_did_this_shift
from ..graphs.ingestion import run_ingestion
from ..graphs.query import run_query
from ..graphs.runtime import Runtime
from ..permissions import Scope
from . import corpus as c
from .baseline import PlainRag
from .questions import QUESTIONS, Question

log = logging.getLogger(__name__)

#: One owner for the whole eval, namespaced so a run cannot collide with a dev
#: owner in the same database.
OWNER = "owner-eval-harness"
#: Small relative to the corpus on purpose. At top_k=8 over 16 records both
#: systems scored ~95% recall by returning half of everything, which measures
#: nothing -- recall@k approaches 1 as k approaches N however bad the ranking is.
#: With ~34 records and k=5, returning the right things is a choice.
TOP_K = 5


@dataclass(slots=True)
class QuestionResult:
    question_id: str
    category: str
    system: str
    recall: float
    precision: float
    returned: int
    #: Stale records returned without being marked superseded.
    unmarked_stale: list[str] = field(default_factory=list)
    forbidden_returned: list[str] = field(default_factory=list)
    cited: bool = False
    answered: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SystemScore:
    system: str
    questions: int = 0
    recall: float = 0.0
    precision: float = 0.0
    unmarked_stale_rate: float = 0.0
    forbidden_rate: float = 0.0
    cited_rate: float = 0.0
    answered_rate: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _scope(**overrides) -> Scope:
    base = dict(
        agent_id="agent-eval",
        owner_id=OWNER,
        sources=list(c.SOURCES),
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    return Scope(**{**base, **overrides})


class _LocalScopeGateway:
    """Resolves a grant token to a scope without a running gateway.

    The eval needs no enclave: the corpus has no sensitive records, so nothing
    crosses the trust boundary. Standing up the Rust stack to measure retrieval
    quality would make the exit test harder to run than it needs to be, and the
    gateway round trip is already proven by `scripts/orchestrator_smoke.sh`.

    The grant token is a JSON scope here, which is exactly what the query graph
    refuses to accept from a caller -- but it refuses a caller-supplied scope,
    not an introspected one, and this stands in for the thing that introspects.
    """

    def __init__(self) -> None:
        self.calls = 0

    def introspect_scope(self, grant_token: str) -> Scope:
        self.calls += 1
        return Scope.model_validate(json.loads(grant_token))

    def adopt_session(self, token: str) -> None:
        pass

    def seal_encrypt(self, plaintext: bytes):
        raise AssertionError("the eval corpus has no sensitive records")

    def close(self) -> None:
        pass


def prepare(runtime: Runtime, *, wipe: bool = True) -> dict[str, int]:
    """Ingests the corpus. Returns what landed, per source."""
    if wipe:
        runtime.store.wipe_owner(OWNER)
    c.register(runtime.registry)
    runtime.gateway = _LocalScopeGateway()

    written: dict[str, int] = {}
    for source in c.SOURCES:
        result = run_ingestion(
            runtime,
            OWNER,
            source=source,
            thread_id=f"eval:{source}",
        )
        if result.errors:
            raise RuntimeError(f"eval corpus failed to ingest from {source}: {result.errors}")
        written[source] = result.entities + result.events + result.claims
    counts = runtime.store.count(OWNER)
    log.info("eval corpus ingested: %s", counts)
    return counts


def _records_of(runtime: Runtime, object_ids: list[str]) -> dict[str, tuple[str, str]]:
    """Maps each returned object id back to the record it came from.

    An object can rest on several records -- that is what `acl.sources` being
    plural means -- but for scoring, the record a claim or event was *extracted
    from* is its first citation's source, which is the one the ground truth
    names.
    """
    out: dict[str, tuple[str, str]] = {}
    for stored in runtime.store.get_many(OWNER, object_ids):
        citations = stored.node.provenance.citations
        if not citations:
            continue
        source = citations[0].source
        out[stored.id] = (source.connector, source.external_id)
    return out


def _asserting(runtime: Runtime, object_ids: list[str]) -> set[str]:
    """Which returned objects make a claim, as opposed to recording a fact.

    Claims assert and can therefore go stale. Entities and events cannot: an
    entity is a referent, and an event is something that happened at a stated
    time, which stays true however the decisions around it move.
    """
    return {
        stored.id
        for stored in runtime.store.get_many(OWNER, object_ids)
        if stored.label == "Claim"
    }


def _stale_marked(runtime: Runtime, object_ids: list[str]) -> set[str]:
    """Which returned objects declare themselves superseded.

    Read from the stored claim rather than parsed out of the answer text: the
    text is a presentation detail and could change, while `status` is the thing
    the record actually asserts.
    """
    marked = set()
    for stored in runtime.store.get_many(OWNER, object_ids):
        status = getattr(stored.node, "status", None)
        if status is not None and status.value != "active":
            marked.add(stored.id)
    return marked


def run_resolved(runtime: Runtime, question: Question) -> QuestionResult:
    scope = _scope(**question.scope_overrides)
    answer = run_query(
        runtime,
        question.text,
        grant_token=scope.model_dump_json(),
        top_k=TOP_K,
        thread_id=f"eval:resolved:{question.id}",
    )
    object_ids = [citation.object_id for citation in answer.citations]
    by_record = _records_of(runtime, object_ids)
    asserting = _asserting(runtime, object_ids)
    marked = _stale_marked(runtime, object_ids)

    returned_records = {by_record[i] for i in object_ids if i in by_record}
    # Only an assertion can be stale, and only an unmarked one counts. See the
    # module docstring: an event records a fact and never stops being true.
    unmarked_stale = {
        by_record[i]
        for i in object_ids
        if i in asserting and by_record.get(i) in question.stale and i not in marked
    }
    return _score(
        question,
        system="resolved",
        returned_records=returned_records,
        returned_count=len(object_ids),
        unmarked_stale=unmarked_stale,
        cited=bool(object_ids)
        and all(citation.source for citation in answer.citations),
        answered=answer.answered,
    )


def run_resolved_with_history(runtime: Runtime, question: Question) -> QuestionResult:
    """The query graph, then the supersession read on its best claim.

    Scored as a third system rather than folded into `run_resolved`, because
    quietly letting the resolved path use a purpose-built read while the
    baseline gets one vector search would be exactly the kind of comparison this
    harness exists not to make. Both numbers are reported: `resolved` is the
    like-for-like retrieval comparison, and this is what the product can
    actually answer with.

    It is also not free, and the report shows that: expanding a chain adds
    objects, so on a question with no history the extra reach costs precision
    for nothing. A system that only ever helped would mean the metric was
    rigged.
    """
    scope = _scope(**question.scope_overrides)
    grant = scope.model_dump_json()
    answer = run_query(
        runtime,
        question.text,
        grant_token=grant,
        top_k=TOP_K,
        thread_id=f"eval:history:{question.id}",
    )
    object_ids = [citation.object_id for citation in answer.citations]
    asserting = _asserting(runtime, object_ids)

    records: set[tuple[str, str]] = set()
    by_record = _records_of(runtime, object_ids)
    records.update(by_record[i] for i in object_ids if i in by_record)

    # Seed the history read with the highest-ranked claim: the query graph
    # returns citations in rank order, so the first claim is the one the
    # retrieval layer thinks the question is about.
    seed = next((i for i in object_ids if i in asserting), None)
    unmarked_stale: set[tuple[str, str]] = set()
    if seed is not None:
        history = why_did_this_shift(runtime, seed, grant)
        chain_ids = [entry["id"] for entry in history.chain if not entry.get("withheld")]
        chain_records = _records_of(runtime, chain_ids)
        records.update(chain_records.values())
        # The evidence that moved each decision -- the whole point of this read,
        # and the part the query graph cannot reach because the evidence records
        # never mention what they caused.
        for step in history.steps:
            for citation in step.get("new_citations", []):
                records.add((citation["connector"], citation["external_id"]))
        # A chain entry states its own status, so nothing in it is unmarked.
        unmarked_stale = {
            chain_records[i]
            for entry in history.chain
            if not entry.get("withheld")
            and (i := entry["id"]) in chain_records
            and chain_records[i] in question.stale
            and entry.get("status") == "active"
        }

    unmarked_stale |= {
        by_record[i]
        for i in object_ids
        if i in asserting and by_record.get(i) in question.stale and i not in _stale_marked(
            runtime, object_ids
        )
    }
    return _score(
        question,
        system="resolved+history",
        returned_records=records,
        returned_count=len(records),
        unmarked_stale=unmarked_stale,
        cited=bool(object_ids),
        answered=answer.answered,
    )


def run_baseline(rag: PlainRag, question: Question) -> QuestionResult:
    result = rag.answer(
        question.text,
        top_k=TOP_K,
        not_after_ms=question.scope_overrides.get("not_after_ms"),
    )
    returned_records = set(result["records"])
    # Scored by the same rule as the resolved path: a stale *assertion* actually
    # present in what the answer shows the reader. The baseline shows chunk text,
    # so the test is whether a chunk contains the assertion -- not merely whether
    # it came from a record that has one. Every such assertion is unmarked,
    # because a chunk of raw text carries no status. Structural, not a failure of
    # this particular baseline.
    unmarked_stale = {
        record
        for record in question.stale
        if (assertion := c.by_id(record).assertion)
        and any(assertion in text for text in result["texts"])
    }
    return _score(
        question,
        system="plain-rag",
        returned_records=returned_records,
        returned_count=len(result["records"]),
        unmarked_stale=unmarked_stale,
        cited=False,
        answered=bool(result["records"]),
    )


def _score(
    question: Question,
    *,
    system: str,
    returned_records: set[tuple[str, str]],
    returned_count: int,
    unmarked_stale: set[tuple[str, str]],
    cited: bool,
    answered: bool,
) -> QuestionResult:
    relevant = set(question.relevant)
    hits = returned_records & relevant
    # Precision is measured over *distinct records* rather than returned items,
    # so a system is not punished for returning two objects from one record --
    # which the resolved path does by design (a claim and the event it came
    # from) and the baseline does by accident (two chunks of one document).
    denominator = len(returned_records) or 1
    return QuestionResult(
        question_id=question.id,
        category=question.category,
        system=system,
        recall=len(hits) / len(relevant) if relevant else 0.0,
        precision=len(hits) / denominator,
        returned=returned_count,
        unmarked_stale=sorted(f"{a}:{b}" for a, b in unmarked_stale),
        forbidden_returned=sorted(
            f"{a}:{b}" for a, b in (returned_records & set(question.forbidden))
        ),
        cited=cited,
        answered=answered,
    )


def _aggregate(system: str, results: list[QuestionResult]) -> SystemScore:
    n = len(results) or 1
    return SystemScore(
        system=system,
        questions=len(results),
        recall=sum(r.recall for r in results) / n,
        precision=sum(r.precision for r in results) / n,
        unmarked_stale_rate=sum(1 for r in results if r.unmarked_stale) / n,
        forbidden_rate=sum(1 for r in results if r.forbidden_returned) / n,
        cited_rate=sum(1 for r in results if r.cited) / n,
        answered_rate=sum(1 for r in results if r.answered) / n,
    )


def evaluate(runtime: Runtime, questions: tuple[Question, ...] = QUESTIONS) -> dict[str, Any]:
    started = time.time()
    counts = prepare(runtime)
    rag = PlainRag(c.records(), runtime.embedder, runtime.registry)

    per_question: list[QuestionResult] = []
    for question in questions:
        per_question.append(run_resolved(runtime, question))
        per_question.append(run_resolved_with_history(runtime, question))
        per_question.append(run_baseline(rag, question))

    def of(system: str) -> list[QuestionResult]:
        return [r for r in per_question if r.system == system]

    return {
        "owner_id": OWNER,
        "corpus": {
            "records": len(c.records()),
            "sources": list(c.SOURCES),
            "baseline_chunks": len(rag),
            "stored": counts,
        },
        "config": {
            "embedder": type(runtime.embedder).__name__,
            "extractor": runtime.extractor.name,
            "top_k": TOP_K,
            "weights": {
                "semantic": runtime.weights.semantic,
                "recency": runtime.weights.recency,
                "proximity": runtime.weights.proximity,
                "half_life_days": runtime.weights.half_life_days,
            },
        },
        "systems": {
            name: _aggregate(name, of(name)).as_dict()
            for name in ("resolved", "resolved+history", "plain-rag")
        },
        "by_question": [r.as_dict() for r in per_question],
        "elapsed_secs": round(time.time() - started, 2),
    }


def format_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    corpus = report["corpus"]
    config = report["config"]
    lines.append("Kleos eval harness -- resolved record vs plain RAG")
    lines.append("=" * 64)
    lines.append(
        f"corpus: {corpus['records']} records over {len(corpus['sources'])} sources "
        f"-> {corpus['stored']}; baseline index: {corpus['baseline_chunks']} chunks"
    )
    lines.append(
        f"config: embedder={config['embedder']} extractor={config['extractor']} "
        f"top_k={config['top_k']} half_life={config['weights']['half_life_days']}d"
    )
    if "Hashed" in config["embedder"]:
        lines.append(
            "  NOTE: hashed-token embeddings. Both systems use them, so the *delta* is "
            "meaningful\n        and the absolute numbers are not. Re-run with a real "
            "embedder before quoting these."
        )
    lines.append("")

    systems = ["resolved", "resolved+history", "plain-rag"]
    header = f"{'metric':<22}" + "".join(f"{name:>18}" for name in systems) + f"{'delta':>10}"
    lines.append(header)
    lines.append("-" * len(header))
    scores = {name: report["systems"][name] for name in systems}
    for key, label, better_high in (
        ("recall", "recall", True),
        ("precision", "precision", True),
        ("answered_rate", "answered", True),
        ("cited_rate", "cited", True),
        ("unmarked_stale_rate", "unmarked stale", False),
        ("forbidden_rate", "forbidden returned", False),
    ):
        # Delta compares the product's best read against the baseline, since
        # that is the question the exit test asks. The like-for-like column is
        # right there beside it for anyone who wants the narrower comparison.
        delta = scores["resolved+history"][key] - scores["plain-rag"][key]
        arrow = "" if abs(delta) < 1e-9 else (" +" if (delta > 0) == better_high else " -")
        row = f"{label:<22}" + "".join(f"{scores[n][key]:>17.0%} " for n in systems)
        lines.append(f"{row}{delta:>+8.0%}{arrow}")

    lines.append("")
    lines.append("per question -- recall, and whether stale/forbidden content came back")
    lines.append("-" * len(header))
    by_question: dict[str, dict[str, Any]] = {}
    for row in report["by_question"]:
        by_question.setdefault(row["question_id"], {})[row["system"]] = row
    for question_id, got in by_question.items():
        cells = []
        for name in systems:
            r = got[name]
            flags = ("S" if r["unmarked_stale"] else ".") + (
                "F" if r["forbidden_returned"] else "."
            )
            cells.append(f"{r['recall']:>5.0%} {flags}")
        lines.append(f"  {question_id:<34}" + "   ".join(cells))
    lines.append("  (S = stale assertion unmarked, F = forbidden record returned)")

    lines.append("")
    verdict = _verdict(scores["resolved+history"], scores["plain-rag"], scores["resolved"])
    lines.append(verdict)
    lines.append(f"({report['elapsed_secs']}s)")
    return "\n".join(lines)


def _verdict(best: dict, baseline: dict, query_only: dict) -> str:
    """States the step 0 exit condition in one line, including a failure.

    The plan says to stop and rethink if resolution does not help. A harness
    that cannot print that sentence is not an exit test, so the failure branch
    is written first and the passing branch has to get past it.

    "Helps" is judged on recall and unmarked staleness together, not either
    alone. Recall by itself misses the product's actual claim -- anything can be
    retrieved, the question is whether what comes back is right about what is
    still true. Unmarked staleness by itself would score a system that
    retrieves nothing at a perfect zero.
    """
    recall_delta = best["recall"] - baseline["recall"]
    stale_delta = baseline["unmarked_stale_rate"] - best["unmarked_stale_rate"]
    forbidden_delta = baseline["forbidden_rate"] - best["forbidden_rate"]

    if recall_delta <= 0 and stale_delta <= 0:
        return (
            "VERDICT: resolution does not help on this corpus -- it retrieves no more, "
            "and is no more\n         correct about what is current. Per the step 0 "
            "exit condition, stop and rethink\n         before building further."
        )

    parts = [f"recall {recall_delta:+.0%}", f"unmarked-stale {-stale_delta:+.0%}"]
    if abs(forbidden_delta) > 1e-9:
        parts.append(f"forbidden {-forbidden_delta:+.0%}")
    verdict = "VERDICT: resolution helps (" + ", ".join(parts) + ")."
    if query_only["recall"] < baseline["recall"]:
        verdict += (
            "\n         But the query graph alone retrieves "
            f"{baseline['recall'] - query_only['recall']:.0%} less than the baseline: the gain "
            "comes from\n         the supersession read and from marking what is "
            "superseded, not from ranking."
        )
    return verdict
