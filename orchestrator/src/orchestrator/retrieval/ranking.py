"""Hybrid ranking: semantic similarity + recency + graph proximity.

Pure embedding similarity systematically under-ranks the thing that makes a
graph-shaped memory worth having: an event two hops from an entity the query
already matched is usually more relevant than a lexically similar event
about something else entirely. Graph proximity is that correction, and
recency keeps a resolved timeline from answering with its own history.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..storage.neo4j_store import StoredNode

SEMANTIC_WEIGHT = 0.6
RECENCY_WEIGHT = 0.15
PROXIMITY_WEIGHT = 0.25

RECENCY_HALF_LIFE_MS = 30 * 86_400_000


@dataclass(slots=True)
class RankedNode:
    node: StoredNode
    score: float
    semantic: float
    recency: float
    proximity: float


def recency_score(occurred_at_ms: int, now_ms: int) -> float:
    age_ms = max(now_ms - occurred_at_ms, 0)
    return math.exp(-age_ms / RECENCY_HALF_LIFE_MS)


def proximity_score(hops: int | None) -> float:
    if hops is None:
        return 0.0
    return 1.0 / float(hops)


def rank(
    candidates: list[tuple[StoredNode, float]],
    hops_by_id: dict[str, int],
    now_ms: int,
) -> list[RankedNode]:
    ranked = []
    for node, semantic in candidates:
        rec = recency_score(node.occurred_at_ms, now_ms)
        prox = proximity_score(hops_by_id.get(node.id))
        ranked.append(
            RankedNode(
                node=node,
                score=(
                    SEMANTIC_WEIGHT * semantic
                    + RECENCY_WEIGHT * rec
                    + PROXIMITY_WEIGHT * prox
                ),
                semantic=semantic,
                recency=rec,
                proximity=prox,
            )
        )
    ranked.sort(key=lambda r: r.score, reverse=True)
    return ranked
