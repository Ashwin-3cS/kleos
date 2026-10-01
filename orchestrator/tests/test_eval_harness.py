"""Tests for the eval harness itself.

A harness is a measuring instrument, and an instrument that cannot be wrong is
not measuring. These tests hold the properties that make its verdict mean
something -- above all that it is *able to fail*, since the step 0 exit
condition is "stop and rethink if resolution does not help" and a harness that
always prints success could never say that.
"""

from __future__ import annotations

import pytest

from orchestrator.eval import corpus as c
from orchestrator.eval.baseline import PlainRag
from orchestrator.eval.harness import (
    OWNER,
    SystemScore,
    _verdict,
    evaluate,
    prepare,
)
from orchestrator.eval.questions import QUESTIONS
from orchestrator.graphs.runtime import Runtime


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(c.settings_for(settings))
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.close()


# -- the corpus and its labels ------------------------------------------


def test_every_label_names_a_real_record() -> None:
    """Ground truth is declared as (connector, external_id) pairs, which are
    strings and therefore mistypeable. A label naming nothing would silently
    depress recall and look like a ranking problem."""
    for question in QUESTIONS:
        for group in (question.relevant, question.stale, question.forbidden):
            for key in group:
                assert c.by_id(key), f"{question.id} names a missing record: {key}"


def test_stale_and_forbidden_do_not_overlap_relevant() -> None:
    """A record cannot be both the answer and a wrong answer. If it were, the
    metrics would contradict each other and whichever ran last would win."""
    for question in QUESTIONS:
        relevant = set(question.relevant)
        assert not (relevant & set(question.forbidden)), question.id
        assert not (set(question.stale) & set(question.forbidden)), question.id


def test_every_stale_record_declares_an_assertion() -> None:
    """Staleness is scored against the text an answer shows the reader, so a
    stale record with no assertion to look for would silently score 0."""
    for question in QUESTIONS:
        for key in question.stale:
            assert c.by_id(key).assertion, f"{question.id}: {key} has no assertion"


def test_the_corpus_is_large_enough_for_top_k_to_be_a_choice() -> None:
    """At top_k=8 over 16 records both systems scored ~95% recall by returning
    half the corpus. recall@k approaches 1 as k approaches N however bad the
    ranking is, so the corpus has to be several times k for the number to mean
    anything."""
    from orchestrator.eval.harness import TOP_K

    assert len(c.records()) >= 5 * TOP_K


def test_timestamps_are_fixed_not_relative_to_now() -> None:
    """A corpus dated relative to the clock would make today's measurement
    incomparable with yesterday's, because the recency term would move."""
    first = c.records()
    second = c.records()
    assert [r.occurred_at_ms for r in first] == [r.occurred_at_ms for r in second]
    # All anchored to the fixed T0 rather than to the wall clock.
    assert all(r.occurred_at_ms >= c.T0 for r in first)
    assert max(r.occurred_at_ms for r in first) - c.T0 < 60 * 86_400_000


def test_every_question_explains_why_it_is_in_the_set() -> None:
    for question in QUESTIONS:
        assert question.rationale, question.id


# -- the baseline is a fair opponent ------------------------------------


def test_the_baseline_indexes_the_whole_corpus(runtime: Runtime) -> None:
    rag = PlainRag(c.records(), runtime.embedder, runtime.registry)
    assert len(rag) >= len(c.records())


def test_the_baseline_uses_the_same_embedder(runtime: Runtime) -> None:
    """The comparison isolates resolution only if everything else is held
    equal. A baseline on a worse embedder would be a straw man."""
    rag = PlainRag(c.records(), runtime.embedder, runtime.registry)
    hits = rag.retrieve("project Lantern durable storage", top_k=3)
    assert hits
    assert all(-1.0001 <= hit.score <= 1.0001 for hit in hits)


def test_the_baseline_honours_a_time_window(runtime: Runtime) -> None:
    """Otherwise it would lose the "what did I know on date D" question to a
    missing feature rather than to a missing capability, and the resolved path
    would be credited for something a real RAG system does too."""
    rag = PlainRag(c.records(), runtime.embedder, runtime.registry)
    cutoff = c.LANTERN_NEO4J.occurred_at_ms - 1
    answer = rag.answer("durable storage", top_k=20, not_after_ms=cutoff)
    assert (c.NOTES, c.LANTERN_NEO4J.external_id) not in answer["records"]


def test_the_baseline_is_deterministic(runtime: Runtime) -> None:
    rag = PlainRag(c.records(), runtime.embedder, runtime.registry)
    first = rag.answer("who owes the migration", top_k=5)
    second = rag.answer("who owes the migration", top_k=5)
    assert first["records"] == second["records"]


# -- the verdict can fail -----------------------------------------------


def test_the_verdict_says_stop_when_resolution_does_not_help() -> None:
    """The property that makes this an exit test rather than a dashboard."""
    equal = SystemScore(system="x", recall=0.9, unmarked_stale_rate=0.5).as_dict()
    verdict = _verdict(equal, equal, equal)
    assert "does not help" in verdict
    assert "stop and rethink" in verdict


def test_the_verdict_fails_on_better_recall_alone_if_staleness_is_no_better() -> None:
    """Recall alone is not the claim. Retrieving more while being equally wrong
    about what is current is not what the product promises."""
    better_recall = SystemScore(
        system="resolved", recall=1.0, unmarked_stale_rate=0.5
    ).as_dict()
    baseline = SystemScore(system="rag", recall=0.9, unmarked_stale_rate=0.5).as_dict()
    assert "helps" in _verdict(better_recall, baseline, better_recall)

    worse_recall = SystemScore(
        system="resolved", recall=0.8, unmarked_stale_rate=0.5
    ).as_dict()
    assert "does not help" in _verdict(worse_recall, baseline, worse_recall)


def test_the_verdict_reports_when_ranking_is_not_the_source_of_the_gain() -> None:
    """The gain currently comes from the supersession read and from marking
    superseded claims, not from the query graph's ranking -- and the report has
    to say so rather than letting a reader assume retrieval improved."""
    best = SystemScore(system="best", recall=1.0, unmarked_stale_rate=0.0).as_dict()
    baseline = SystemScore(system="rag", recall=0.93, unmarked_stale_rate=0.5).as_dict()
    query_only = SystemScore(system="q", recall=0.87, unmarked_stale_rate=0.0).as_dict()
    verdict = _verdict(best, baseline, query_only)
    assert "helps" in verdict
    assert "query graph alone" in verdict


# -- the end-to-end run -------------------------------------------------


def test_the_corpus_ingests_cleanly(runtime: Runtime) -> None:
    counts = prepare(runtime)
    assert counts["Event"] == len(c.records())
    # Ten asserting records, ten claims: if the extractor's grammar stops
    # matching the corpus, every metric moves and the cause looks like ranking.
    assert counts["Claim"] == sum(1 for r in c.records() if r.assertion)


def test_the_full_run_produces_a_report(runtime: Runtime) -> None:
    report = evaluate(runtime)
    assert set(report["systems"]) == {"resolved", "resolved+history", "plain-rag"}
    assert len(report["by_question"]) == 3 * len(QUESTIONS)
    for score in report["systems"].values():
        assert score["questions"] == len(QUESTIONS)
        for key in ("recall", "precision", "unmarked_stale_rate"):
            assert 0.0 <= score[key] <= 1.0


def test_resolution_currently_beats_the_baseline(runtime: Runtime) -> None:
    """Step 0's exit test, asserted so a regression is a failing test rather
    than a number nobody re-ran.

    Deliberately asserts the *direction* and not the figures: the numbers depend
    on the embedder and are expected to move the moment a real one is wired in.
    What must not move is which system is more correct about what is current.
    """
    report = evaluate(runtime)
    best = report["systems"]["resolved+history"]
    baseline = report["systems"]["plain-rag"]

    assert best["unmarked_stale_rate"] < baseline["unmarked_stale_rate"], (
        "the resolved record must be more correct than raw retrieval about which "
        "claims are still current -- this is the product's central bet"
    )
    assert best["recall"] >= baseline["recall"]
    assert best["cited_rate"] > baseline["cited_rate"]


def test_the_baseline_cannot_mark_staleness_at_all(runtime: Runtime) -> None:
    """Reported as structural rather than earned: nothing in the text of a
    superseded decision says it was superseded, so no embedder would fix it."""
    report = evaluate(runtime)
    assert report["systems"]["plain-rag"]["cited_rate"] == 0.0
    assert report["systems"]["plain-rag"]["unmarked_stale_rate"] > 0.0


def test_the_eval_does_not_need_a_gateway_or_an_enclave(runtime: Runtime) -> None:
    """The corpus has no sensitive records, so nothing crosses the trust
    boundary and the exit test stays runnable with two containers."""
    report = evaluate(runtime)
    assert report["corpus"]["records"] == len(c.records())
    assert runtime.gateway.calls > 0, "scopes must still be introspected, not assumed"


def test_the_report_warns_when_embeddings_are_not_semantic(runtime: Runtime) -> None:
    from orchestrator.eval.harness import format_report

    text = format_report(evaluate(runtime))
    assert "hashed-token" in text
    assert "absolute numbers are not" in text
