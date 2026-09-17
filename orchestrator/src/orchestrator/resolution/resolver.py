"""Resolves extracted candidates against what is already stored.

This is the step that turns "a pile of retrievable documents" into a
record: every candidate claim is compared against the claims already stored
about the same subjects, and classified as new, an update, or a
contradiction. Nothing is ever overwritten -- an older claim is marked
``superseded`` and the link between them is kept, so the timeline can still
answer what was believed before and when it changed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..enums import ClaimStatus
from ..schema import Candidate, Claim
from ..storage.neo4j_store import Neo4jStore

_STOPWORDS = {
    "a", "after", "all", "an", "and", "at", "be", "for", "from", "in", "of",
    "on", "pending", "primary", "review", "the", "that", "to", "will", "with",
}
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _topic(statement: str) -> frozenset[str]:
    """The part of a statement that identifies *what it is about*.

    Two claims share a topic when they name the same subject and predicate;
    they conflict when their topics match but their full token sets differ.
    """
    tokens = [t for t in _TOKEN_RE.findall(statement.lower()) if t not in _STOPWORDS]
    return frozenset(tokens[:3])


def _tokens(statement: str) -> frozenset[str]:
    return frozenset(t for t in _TOKEN_RE.findall(statement.lower()) if t not in _STOPWORDS)


@dataclass(slots=True)
class Resolution:
    """What the resolver decided for one batch of candidates."""

    new_claims: list[Claim] = field(default_factory=list)
    #: (superseding claim id, superseded claim id)
    supersessions: list[tuple[str, str]] = field(default_factory=list)
    #: (claim id, conflicting claim id) -- unresolved, both stay active-ish
    contradictions: list[tuple[str, str]] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)


class Resolver:
    def __init__(self, store: Neo4jStore) -> None:
        self._store = store

    def resolve_batch(self, owner_id: str, candidates: list[Candidate]) -> list[Resolution]:
        """Resolves a whole ingestion batch.

        Claims from earlier records in the same batch are not in the store
        yet but must still be resolvable against, or a backfill would never
        notice a decision being superseded within its own window.
        """
        pending: list[Claim] = []
        return [self.resolve(owner_id, c, pending) for c in candidates]

    def resolve(
        self,
        owner_id: str,
        candidate: Candidate,
        pending: list[Claim] | None = None,
    ) -> Resolution:
        resolution = Resolution()

        prior: list[Claim] = pending if pending is not None else []
        for claim in candidate.claims:
            if self._store.get(claim.id) is not None:
                resolution.duplicates.append(claim.id)
                continue

            stored = [
                s.node
                for s in self._store.claims_about(owner_id, claim.subject_entity_ids)
                if isinstance(s.node, Claim)
            ]
            # Candidates within this same batch are not in the store yet but
            # must still resolve against each other.
            existing = stored + prior

            topic = _topic(claim.statement)
            tokens = _tokens(claim.statement)
            for other in existing:
                if other.id == claim.id:
                    continue
                if _topic(other.statement) != topic:
                    continue
                if _tokens(other.statement) == tokens:
                    continue
                if other.status is not ClaimStatus.ACTIVE:
                    continue

                if claim.asserted_at_ms > other.asserted_at_ms:
                    claim.supersedes.append(other.id)
                    other.status = ClaimStatus.SUPERSEDED
                    resolution.supersessions.append((claim.id, other.id))
                elif claim.asserted_at_ms == other.asserted_at_ms:
                    claim.contradicts.append(other.id)
                    claim.status = ClaimStatus.CONTRADICTED
                    resolution.contradictions.append((claim.id, other.id))
                else:
                    # Arrived late but happened earlier: the stored claim
                    # stands, this one is born superseded rather than dropped.
                    claim.status = ClaimStatus.SUPERSEDED
                    resolution.supersessions.append((other.id, claim.id))

            prior.append(claim)
            resolution.new_claims.append(claim)

        return resolution
