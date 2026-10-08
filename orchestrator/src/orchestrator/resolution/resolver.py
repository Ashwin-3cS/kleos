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

from ..enums import Authority, ClaimStatus
from ..schema import Candidate, Claim
from ..storage.mutations import (
    RULE_AGENT_DELEGATE_SUPERSEDES,
    RULE_ARRIVED_LATE_BORN_SUPERSEDED,
    RULE_DUPLICATE_ID,
    RULE_EQUAL_ASSERTED_AT_CONTRADICTS,
    RULE_NEWER_ASSERTED_AT,
    RULE_SUPERSESSION_SETTLES_CONFLICT,
    RULE_WEAKER_SOURCE_CONTRADICTS,
)
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


def _obligation(claim: Claim) -> tuple[str | None, str | None, int | None]:
    """The part of a commitment that is not in its statement text.

    Who owes a commitment lives in the facet, not the prose, so two claims
    can have identical statements and still be different obligations -- a
    reassignment with the same deadline is exactly that. Without this the
    token comparison below would write the reassignment off as a duplicate.
    """
    c = claim.commitment
    if c is None:
        return (None, None, None)
    return (c.owed_by_entity_id, c.owed_to_entity_id, c.due_at_ms)


#: Sources whose claims are reference material rather than the person's own account.
#: Kept here, next to the precedence rule, rather than imported from the tool that
#: produces them: the rule is about what the resolver will believe, and it should be
#: readable without following an import into the tool layer.
_WEAKER_SOURCES = frozenset({"web"})


def _is_weaker(claim: Claim) -> bool:
    """Whether this claim is reference material rather than the person's account.

    Reads ``Provenance.authority`` when it is set, because precedence is a
    property of what asserted a thing rather than of where the bytes came from:
    an agent the owner granted ``may_supersede_owner`` is a *delegate* and is not
    weaker, while the same agent without it writes ``Reference`` and is.

    Falls back to the source rule when authority is absent, which is every claim
    stored before that field existed. That fallback is why ``authority`` is
    ``Option`` with no default -- a default would relabel the whole existing
    graph as one class or the other.

    The source rule itself uses ``all`` rather than ``any``: a claim derived from
    both a page and the person's own note carries their account too, and demoting
    it would lose that.
    """
    authority = claim.provenance.authority
    if authority is not None:
        return authority is Authority.REFERENCE
    sources = list(claim.acl.sources)
    return bool(sources) and all(s in _WEAKER_SOURCES for s in sources)


def _supersession_rule(candidate: Claim) -> str:
    """Which rule a supersession was decided by.

    A delegate's write is recorded as such rather than as a timestamp
    comparison, because the timestamp is not what permitted it: an agent's claim
    only reaches this branch at all when the owner's grant said
    `may_supersede_owner`. Recording `newer_asserted_at` there would say the
    clock decided, which is the thing ADR 0014 is careful about.
    """
    if candidate.provenance.authority is Authority.DELEGATE:
        return RULE_AGENT_DELEGATE_SUPERSEDES
    return RULE_NEWER_ASSERTED_AT


def _may_not_supersede(candidate: Claim, stored: Claim) -> bool:
    """Blocks a weaker-sourced claim from superseding a stronger-sourced one.

    **This is the whole mitigation for prompt injection through a fetched page.** A
    page that says "the user has decided to use Postgres" extracts as a claim about
    Postgres, lands in the same subject neighbourhood as the person's real decision,
    and -- being newer -- would win on timestamp. Timestamps are the right tie-break
    between two things the person said and exactly the wrong one between something
    they said and something a stranger wrote.

    Deliberately asymmetric: the person's own later claim *may* supersede a
    web-derived one, because learning that a page was wrong is a normal thing to
    happen and the record should follow.
    """
    return _is_weaker(candidate) and not _is_weaker(stored)


@dataclass(frozen=True, slots=True)
class Decision:
    """One resolution decision, with the rule that produced it.

    Deliberately not a `MutationEntry`: the resolver knows which rule fired and
    against what, and knows nothing about who asked -- the actor arrives at the
    write node, which is where the grant is. Keeping them apart is what stops
    the resolver needing to know about grants at all.
    """

    #: The object whose state this changes.
    object_id: str
    #: The other claim involved, when there is one.
    other_id: str | None
    #: One of `storage.mutations.RULES`.
    rule: str
    #: Prose, for a reader. The rule is for a filter.
    reason: str


@dataclass(slots=True)
class Resolution:
    """What the resolver decided for one batch of candidates."""

    new_claims: list[Claim] = field(default_factory=list)
    #: (superseding claim id, superseded claim id)
    supersessions: list[tuple[str, str]] = field(default_factory=list)
    #: (claim id, conflicting claim id) -- unresolved, both stay active-ish
    contradictions: list[tuple[str, str]] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    #: Why each of the above happened: which branch fired, and against what.
    #:
    #: This is the field that makes "every state change and why" true. The
    #: reasons existed already -- newer timestamp wins, equal timestamps
    #: contradict, a late arrival is born superseded, a weaker source may not
    #: supersede -- but they lived in control flow and were discarded the moment
    #: the branch returned, so the graph recorded that B replaced A and nothing
    #: recorded why. The write node turns these into `:Mutation` entries.
    decisions: list[Decision] = field(default_factory=list)
    #: ``(reconciled claim id, the claim that settled it)``.
    #:
    #: `reconciled_into` has been in both schemas since the beginning, is read by
    #: `graphs/history.py`, and was written by nothing -- so
    #: `ShiftHistory.reconciliations` was populated-but-always-empty and the
    #: question "what resolved this disagreement" had no answer the record could
    #: give. This is the producer.
    reconciliations: list[tuple[str, str]] = field(default_factory=list)


class Resolver:
    def __init__(self, store: Neo4jStore, unseal=None) -> None:
        self._store = store
        # Stored claims may have their statements sealed at rest (ADR 0010).
        # Comparing a plaintext candidate against a sealed statement would make
        # every topic differ and every supersession go unnoticed -- a silent
        # failure, since the batch would still write successfully. Identity by
        # default so a caller with nothing to unseal needs no ceremony.
        self._unseal = unseal or (lambda claim: claim)

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
                resolution.decisions.append(
                    Decision(
                        object_id=claim.id,
                        other_id=None,
                        rule=RULE_DUPLICATE_ID,
                        reason=(
                            "already stored: the id is content-addressed, so this is "
                            "the same statement from the same record"
                        ),
                    )
                )
                continue

            stored = [
                self._unseal(s.node)
                for s in self._store.claims_about(owner_id, claim.subject_entity_ids)
                if isinstance(s.node, Claim)
            ]
            # Candidates within this same batch are not in the store yet but
            # must still resolve against each other.
            existing = stored + prior

            topic = _topic(claim.statement)
            tokens = _tokens(claim.statement)
            obligation = _obligation(claim)
            for other in existing:
                if other.id == claim.id:
                    continue
                if _topic(other.statement) != topic:
                    continue
                if _tokens(other.statement) == tokens and _obligation(other) == obligation:
                    continue
                if other.status is not ClaimStatus.ACTIVE:
                    continue
                if _may_not_supersede(claim, other):
                    # A page the person read cannot overwrite what the person said.
                    # Recorded as a contradiction instead, so the disagreement is
                    # visible without the weaker source winning.
                    claim.contradicts.append(other.id)
                    resolution.contradictions.append((claim.id, other.id))
                    resolution.decisions.append(
                        Decision(
                            object_id=claim.id,
                            other_id=other.id,
                            rule=RULE_WEAKER_SOURCE_CONTRADICTS,
                            reason=(
                                "reference material cannot overwrite the person's own "
                                "account, so the disagreement is recorded instead"
                            ),
                        )
                    )
                    continue

                if claim.asserted_at_ms > other.asserted_at_ms:
                    claim.supersedes.append(other.id)
                    other.status = ClaimStatus.SUPERSEDED
                    resolution.supersessions.append((claim.id, other.id))
                    self._settle_conflicts(resolution, claim, other)
                    resolution.decisions.append(
                        Decision(
                            object_id=other.id,
                            other_id=claim.id,
                            rule=_supersession_rule(claim),
                            reason=(
                                "a later assertion about the same subject replaced it"
                            ),
                        )
                    )
                elif claim.asserted_at_ms == other.asserted_at_ms:
                    claim.contradicts.append(other.id)
                    claim.status = ClaimStatus.CONTRADICTED
                    resolution.contradictions.append((claim.id, other.id))
                    resolution.decisions.append(
                        Decision(
                            object_id=claim.id,
                            other_id=other.id,
                            rule=RULE_EQUAL_ASSERTED_AT_CONTRADICTS,
                            reason=(
                                "asserted at the same instant, so neither is the later "
                                "one and the conflict stays open"
                            ),
                        )
                    )
                else:
                    # Arrived late but happened earlier: the stored claim
                    # stands, this one is born superseded rather than dropped.
                    claim.status = ClaimStatus.SUPERSEDED
                    resolution.supersessions.append((other.id, claim.id))
                    resolution.decisions.append(
                        Decision(
                            object_id=claim.id,
                            other_id=other.id,
                            rule=RULE_ARRIVED_LATE_BORN_SUPERSEDED,
                            reason=(
                                "ingested after a claim that was asserted later, so it "
                                "is stored already superseded rather than dropped"
                            ),
                        )
                    )

            prior.append(claim)
            resolution.new_claims.append(claim)

        return resolution

    def _settle_conflicts(
        self, resolution: Resolution, superseding: Claim, superseded: Claim
    ) -> None:
        """A later decision on the same subject settles a standing disagreement.

        If the claim being superseded was in an unresolved `CONTRADICTS` pair,
        both sides of that pair are reconciled into the claim that replaced it.
        The reasoning is the same one supersession rests on: the person -- or a
        delegate they authorised -- has decided the matter again, more recently,
        and a conflict between two older readings of it is no longer open.

        **Conservative on purpose.** It settles only conflicts touching the claim
        actually superseded, never every conflict about the subject: a decision
        about the database does not settle an unrelated argument about the same
        project. And it never reconciles a claim into itself.

        A contradiction with no superseding claim stays open, which is the common
        case and the right one -- an unresolved disagreement is part of the
        record, not a defect in it.
        """
        pairs = self._store.conflict_links(superseded.owner_id, [superseded.id])
        if not pairs:
            return
        settled: set[str] = set()
        for left, right in pairs:
            settled.update({left, right})
        settled.discard(superseding.id)
        for claim_id in sorted(settled):
            resolution.reconciliations.append((claim_id, superseding.id))
            resolution.decisions.append(
                Decision(
                    object_id=claim_id,
                    other_id=superseding.id,
                    rule=RULE_SUPERSESSION_SETTLES_CONFLICT,
                    reason=(
                        "a later decision on the same subject superseded one side "
                        "of this disagreement, which settles it"
                    ),
                )
            )
