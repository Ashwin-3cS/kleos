"""Hybrid ranking: semantic similarity + recency + graph proximity.

Pure embedding similarity systematically under-ranks the thing that makes a
graph-shaped memory worth having: an event two hops from an entity the query
already matched is usually more relevant than a lexically similar event
about something else entirely. Graph proximity is that correction, and
recency keeps a resolved timeline from answering with its own history.

The weights and the recency half-life are configuration, not constants. See
ADR 0003: the previous values were a guess with no way to evaluate them, and
the recency term in particular was actively wrong for this product.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..storage.neo4j_store import StoredNode

_DAY_MS = 86_400_000

#: Ratios, normalised at use. These match the original hand-picked values so
#: that only the recency *curve* changes by default -- that change is
#: deliberate and argued in ADR 0003.
DEFAULT_SEMANTIC_WEIGHT = 0.6
DEFAULT_RECENCY_WEIGHT = 0.15
DEFAULT_PROXIMITY_WEIGHT = 0.25

#: Why 180 days and not 30. A resolved record's whole point is that an old
#: decision still stands until something supersedes it, so age is not
#: evidence of irrelevance here the way it is in a feed. Under the previous
#: 30-day constant a year-old decision scored 1.6e-6 on recency: that is not
#: a tie-break, it is a filter, and it filtered out exactly the material the
#: "why did this change?" read exists to surface. This is a starting point
#: for the eval harness to move, not a claim to have found the right number.
DEFAULT_RECENCY_HALF_LIFE_DAYS = 180.0


@dataclass(frozen=True, slots=True)
class RankingWeights:
    """Normalised scoring weights plus the recency curve.

    Normalisation is what makes scores comparable across configurations: a
    score is always in [0, 1] whatever ratios were supplied, so a number the
    eval harness reports still means the same thing after someone retunes the
    weights.
    """

    semantic: float = DEFAULT_SEMANTIC_WEIGHT
    recency: float = DEFAULT_RECENCY_WEIGHT
    proximity: float = DEFAULT_PROXIMITY_WEIGHT
    half_life_days: float = DEFAULT_RECENCY_HALF_LIFE_DAYS

    def __post_init__(self) -> None:
        if self.half_life_days <= 0:
            raise ValueError("half_life_days must be positive")
        if min(self.semantic, self.recency, self.proximity) < 0:
            raise ValueError("ranking weights must be non-negative")
        if self.semantic + self.recency + self.proximity <= 0:
            raise ValueError("at least one ranking weight must be non-zero")

    @classmethod
    def from_settings(cls, settings) -> RankingWeights:
        return cls(
            semantic=settings.semantic_weight,
            recency=settings.recency_weight,
            proximity=settings.proximity_weight,
            half_life_days=settings.recency_half_life_days,
        )

    @property
    def total(self) -> float:
        return self.semantic + self.recency + self.proximity

    @property
    def half_life_ms(self) -> float:
        return self.half_life_days * _DAY_MS


DEFAULT_WEIGHTS = RankingWeights()


@dataclass(slots=True)
class RankedNode:
    node: StoredNode
    score: float
    semantic: float
    recency: float
    proximity: float


def recency_score(occurred_at_ms: int, now_ms: int, half_life_ms: float) -> float:
    """Exponential decay with a genuine half-life.

    The previous implementation was ``exp(-age / 30 days)``, which decays to
    1/e at 30 days rather than to 1/2 -- so the constant was named a
    half-life and delivered something 44% shorter than one. Multiplying by
    ``ln 2`` is the whole fix: at ``half_life_ms`` this returns exactly 0.5.
    """
    age_ms = max(now_ms - occurred_at_ms, 0)
    return math.exp(-math.log(2.0) * age_ms / half_life_ms)


def proximity_score(hops: int | None) -> float:
    if hops is None:
        return 0.0
    return 1.0 / float(hops)


def rank(
    candidates: list[tuple[StoredNode, float]],
    hops_by_id: dict[str, int],
    now_ms: int,
    weights: RankingWeights = DEFAULT_WEIGHTS,
) -> list[RankedNode]:
    total = weights.total
    half_life_ms = weights.half_life_ms
    ranked = []
    for node, semantic in candidates:
        rec = recency_score(node.occurred_at_ms, now_ms, half_life_ms)
        prox = proximity_score(hops_by_id.get(node.id))
        ranked.append(
            RankedNode(
                node=node,
                score=(
                    weights.semantic * semantic
                    + weights.recency * rec
                    + weights.proximity * prox
                )
                / total,
                semantic=semantic,
                recency=rec,
                proximity=prox,
            )
        )
    # Ties broken by id so a ranking is reproducible across runs: the eval
    # harness compares ordered result lists, and must not see churn that is
    # really dict iteration order.
    ranked.sort(key=lambda r: (-r.score, r.node.id))
    return ranked
