"""Hybrid ranking, and the recency term that was wrong.

``RECENCY_HALF_LIFE_MS`` was 30 days, applied as ``exp(-age / half_life)``.
That is a 1/e point, not a half-life, so the constant promised one thing and
delivered something 44% shorter -- and at 30 days a year-old decision scored
1.6e-6, which is a filter rather than a tie-break. For a record whose
signature read is "why did this change", that is backwards. See ADR 0003.
"""

from __future__ import annotations

import math

import pytest

from orchestrator.config import Settings
from orchestrator.retrieval.ranking import (
    DEFAULT_RECENCY_HALF_LIFE_DAYS,
    RankingWeights,
    proximity_score,
    recency_score,
)

_DAY_MS = 86_400_000


def test_the_half_life_is_a_half_life() -> None:
    half_life_ms = 30 * _DAY_MS
    assert recency_score(0, half_life_ms, half_life_ms) == pytest.approx(0.5)
    assert recency_score(0, 2 * half_life_ms, half_life_ms) == pytest.approx(0.25)
    assert recency_score(0, 3 * half_life_ms, half_life_ms) == pytest.approx(0.125)


def test_the_old_curve_was_not_a_half_life() -> None:
    """Documents the defect rather than trusting memory of it: the previous
    formula returned 1/e at the value it called a half-life."""
    half_life_ms = 30 * _DAY_MS
    old = math.exp(-1.0)
    assert old == pytest.approx(0.3679, abs=1e-4)
    assert recency_score(0, half_life_ms, half_life_ms) > old


def test_something_that_just_happened_scores_one() -> None:
    assert recency_score(1_000, 1_000, _DAY_MS) == pytest.approx(1.0)


def test_a_future_timestamp_does_not_exceed_one() -> None:
    """Clock skew between a source and this machine is routine; a recency
    score above 1 would let a skewed event outrank everything."""
    assert recency_score(2_000, 1_000, _DAY_MS) == pytest.approx(1.0)


def test_an_old_decision_is_no_longer_filtered_out() -> None:
    """The reason the default moved to 180 days. A year-old decision that
    nothing has superseded is still the answer, and it has to be able to
    outrank a lexically-similar irrelevant note."""
    year_ms = 365 * _DAY_MS
    old_default = math.exp(-year_ms / (30 * _DAY_MS))
    new_default = recency_score(0, year_ms, DEFAULT_RECENCY_HALF_LIFE_DAYS * _DAY_MS)
    assert old_default < 1e-5
    assert new_default > 0.2


def test_proximity_rewards_closer_nodes() -> None:
    assert proximity_score(1) > proximity_score(2) > proximity_score(5)
    assert proximity_score(None) == 0.0


def test_weights_are_normalised_so_scores_stay_comparable() -> None:
    """A score has to mean the same thing after someone retunes the weights,
    or no measured number from the eval harness survives a config change."""
    doubled = RankingWeights(semantic=1.2, recency=0.3, proximity=0.5)
    default = RankingWeights()
    assert doubled.total == pytest.approx(2 * default.total)

    from orchestrator.retrieval.ranking import rank
    from orchestrator.storage.neo4j_store import StoredNode

    class _Node:
        def __init__(self, node_id: str) -> None:
            self.id = node_id

    stored = StoredNode(id="n1", label="Event", node=None, text="t", occurred_at_ms=0)
    candidates = [(stored, 1.0)]
    now = 0
    a = rank(candidates, {"n1": 1}, now, default)[0].score
    b = rank(candidates, {"n1": 1}, now, doubled)[0].score
    assert a == pytest.approx(b), "the same ratios must give the same score"
    assert 0.0 <= a <= 1.0


def test_a_perfect_candidate_scores_one_and_a_hopeless_one_zero() -> None:
    from orchestrator.retrieval.ranking import rank
    from orchestrator.storage.neo4j_store import StoredNode

    # Far enough back that the recency term is negligible: ~27 half-lives at
    # the default. "Old" has to be measured in half-lives, not in milliseconds.
    now = 5_000 * _DAY_MS
    best = StoredNode(id="best", label="Event", node=None, text="t", occurred_at_ms=now)
    worst = StoredNode(id="worst", label="Event", node=None, text="t", occurred_at_ms=0)

    ranked = rank([(best, 1.0), (worst, 0.0)], {"best": 1}, now)
    assert ranked[0].node.id == "best"
    assert ranked[0].score == pytest.approx(1.0)
    assert ranked[1].score < 0.01


def test_ties_are_broken_deterministically() -> None:
    """The eval harness compares ordered result lists, so a tie must not
    resolve differently between runs."""
    from orchestrator.retrieval.ranking import rank
    from orchestrator.storage.neo4j_store import StoredNode

    nodes = [
        StoredNode(id=f"n{i}", label="Event", node=None, text="t", occurred_at_ms=0)
        for i in range(5)
    ]
    candidates = [(n, 0.5) for n in nodes]
    first = [r.node.id for r in rank(candidates, {}, 0)]
    second = [r.node.id for r in rank(list(reversed(candidates)), {}, 0)]
    assert first == second == sorted(first)


def test_invalid_weights_are_rejected_at_construction() -> None:
    with pytest.raises(ValueError):
        RankingWeights(half_life_days=0)
    with pytest.raises(ValueError):
        RankingWeights(semantic=-1)
    with pytest.raises(ValueError):
        RankingWeights(semantic=0, recency=0, proximity=0)


def test_weights_come_from_settings() -> None:
    settings = Settings(
        semantic_weight=0.5,
        recency_weight=0.25,
        proximity_weight=0.25,
        recency_half_life_days=90,
    )
    weights = RankingWeights.from_settings(settings)
    assert weights.semantic == 0.5
    assert weights.half_life_days == 90
    assert weights.half_life_ms == 90 * _DAY_MS
