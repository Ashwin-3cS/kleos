"""Making the graph cohere: deciding when two entity names are one entity.

Entity ids are content-addressed over the name --
``stable_id("ent", owner_id, kind, name.lower())`` -- so ``RAG`` and ``retrieval
augmented generation`` are two permanently separate nodes. Every claim about one
is invisible from the other: the resolver looks for claims to compare against via
``claims_about(owner_id, subject_entity_ids)``, so a decision recorded under the
acronym is never weighed against a decision recorded under the expansion. The
duplicate is not a cosmetic problem, it is a hole in the record.

## Why this is lexical and not learned

The obvious design is embedding similarity above a threshold. It does not work,
and the measurement is worth keeping because it is counter-intuitive. Cosines
under ``bge-small``:

===========================================  =====  ==============================  =====
should merge                                        should **not** merge
-------------------------------------------  -----  ------------------------------  -----
``RAG`` ~ ``retrieval augmented generation`` 0.531  ``Postgres`` vs ``Redis``       0.652
``K8s`` ~ ``Kubernetes``                     0.674  ``Mina`` vs ``Rafi``            0.542
``Mina`` ~ ``Mina Patel``                    0.794  ``Lantern`` vs ``Harbour``      0.528
``Kleos`` ~ ``project Kleos``                0.897  ``RAG`` vs ``sourdough bread``  0.519
``Postgres`` ~ ``PostgreSQL``                0.934
===========================================  =====  ==============================  =====

The classes overlap: the lowest true positive (0.531) sits *below* the highest
true negative (0.652). No threshold separates them. Any cutoff low enough to
merge an acronym with its expansion also merges two unrelated databases into one
entity, which is far worse than leaving a duplicate.

The plan this came from kept embeddings as a *veto* -- never causing a merge,
only blocking one. That does not survive either: a veto floor has to sit below
0.531 to avoid killing the acronym case and above 0.542 to reject anything at
all, and no such number exists. So embeddings play no part here. The honest
reading of the measurement is that a sentence embedder has little to say about
two- and three-word proper nouns, which is not what it was trained on.

What is left is better anyway: every pair embeddings score highly (0.794-0.934)
is one a cheap deterministic rule also catches, the one case needing real help is
exactly where they fail, and a rule can be read, tested and explained to the
person whose record it changed.

## The asymmetry that matters

**Ambiguity resolves to leaving a duplicate.** A duplicate is visible and
recoverable: a later merge fixes it. A wrong merge is neither -- two people's
histories are now one person's, nothing records that they were ever separate, and
there is no per-object deletion in this system to undo it with. So every rule
here is deliberately narrow, and when two targets match about equally well the
answer is to merge with neither.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from ..enums import EntityKind
from ..schema import Candidate, Entity
from ..storage.neo4j_store import Neo4jStore

log = logging.getLogger(__name__)

_WORD_RE = re.compile(r"[a-z0-9]+")

#: Below this many characters a name is too generic for the containment and fold
#: rules to mean anything: "AI" is contained in a hundred unrelated names, and
#: folding "os" into "osx" would be a coin flip. Exact-normalised and acronym
#: matching are still allowed below it, because both compare the *whole* string.
_MIN_PARTIAL_LEN = 4


def normalise(name: str) -> list[str]:
    """A name as comparable tokens: lowercase, punctuation dropped.

    ``Node.js`` and ``nodejs`` both become ``["node", "js"]`` and ``["nodejs"]``
    respectively -- which is why the compact form below exists too.
    """
    return _WORD_RE.findall(name.lower())


def _compact(tokens: list[str]) -> str:
    """Tokens with the separators thrown away, for comparisons that should not
    care where the word breaks fell. ``R.A.G.``, ``R A G`` and ``RAG`` all give
    ``rag``, so an acronym written three ways is one acronym."""
    return "".join(tokens)


def _is_sublist(small: list[str], large: list[str]) -> bool:
    """Whether ``small`` appears in ``large`` as a *contiguous* run.

    Contiguous rather than as a subset: ``["mina"]`` is in ``["mina", "patel"]``,
    but ``["lantern", "review"]`` should not match ``["lantern", "design",
    "review"]`` -- a design review of Lantern is not the Lantern review.
    """
    if not small or len(small) > len(large):
        return False
    return any(
        large[i : i + len(small)] == small for i in range(len(large) - len(small) + 1)
    )


#: Kinds whose names are common noun phrases rather than proper nouns, where
#: containment means *narrower than* and not *the same as*. "storage" and "durable
#: storage" are a topic and a sub-topic; folding them asserts they are one thing and
#: builds a high-degree hub that every project's claims hang off.
#:
#: Measured, not assumed. With topics included, the eval's Harbour question started
#: returning the Lantern storage decision -- cross-project contamination through
#: exactly that shared node -- while recall and precision stayed flat. It is the
#: failure mode a single metric misses: the graph looked more connected and the
#: answers got wronger.
#:
#: Only containment is restricted. An acronym or a shared spelling asserts identity,
#: which is as true of a topic as of a person: "RAG" and "retrieval augmented
#: generation" are one topic and must still merge.
CONTAINMENT_FORBIDDEN_KINDS = frozenset({EntityKind.TOPIC})

#: Each rule's score. Compared against each other to pick the best match for a
#: name and to detect a tie, so only the ordering is meaningful -- the numbers
#: are not confidences and nothing thresholds on them.
SCORES = {"same_normalised": 4, "acronym": 3, "suffix_fold": 2, "containment": 1}


def match(left: str, right: str) -> str | None:
    """The strongest rule under which these two names are the same thing, or None.

    Symmetric in its arguments: which of the two is stored and which is new is a
    question about precedence, decided by the caller, not about whether they
    match.
    """
    a, b = normalise(left), normalise(right)
    if not a or not b:
        # A name that is pure punctuation has nothing to compare. Merging two of
        # them because they are equally empty would be the worst available answer.
        return None

    if a == b:
        return "same_normalised"

    ca, cb = _compact(a), _compact(b)
    if ca == cb:
        # "Node.js" vs "nodejs": the same string, written with a dot.
        return "same_normalised"

    # -- acronym: initials of the longer name spell the shorter one ------
    for short, long in ((ca, b), (cb, a)):
        if len(short) < 2 or len(short) > 6 or len(long) < 2:
            continue
        if short == "".join(token[0] for token in long):
            return "acronym"

    # -- suffix fold: one name is the other plus a short tail -----------
    short, long = sorted((ca, cb), key=len)
    if (
        len(short) >= _MIN_PARTIAL_LEN + 1
        and long.startswith(short)
        and len(long) - len(short) <= 3
    ):
        # "postgres" -> "postgresql" folds; "redis" -> "redisearch" does not,
        # because a five-character tail is a different word and not an
        # inflection. Deliberately tight: this rule has no way to tell a suffix
        # from the start of another name.
        return "suffix_fold"

    # -- containment: one name's words appear inside the other ----------
    # The weakest rule, and the only one restricted by kind at the call site --
    # see CONTAINMENT_FORBIDDEN_KINDS.
    small, large = sorted((a, b), key=len)
    if len(_compact(small)) >= _MIN_PARTIAL_LEN and _is_sublist(small, large):
        return "containment"

    return None


@dataclass(frozen=True, slots=True)
class Merge:
    """One decision: ``from_id`` ceases to exist and becomes an alias of ``into_id``."""

    from_id: str
    into_id: str
    #: The name that is being given up, kept as an alias on the survivor so the
    #: person can still find the entity by what they originally called it.
    alias: str
    #: Which rule fired. Recorded because the first question about a surprising
    #: merge is which rule allowed it, and that should not need a bisect.
    rule: str

    def as_dict(self) -> dict[str, str]:
        return {
            "from_id": self.from_id,
            "into_id": self.into_id,
            "alias": self.alias,
            "rule": self.rule,
        }


@dataclass(slots=True)
class Canonicalisation:
    """What canonicalisation did to one batch."""

    merges: list[Merge] = field(default_factory=list)
    #: Candidates refused for ambiguity: (entity id, the ids it matched equally).
    #: Kept because "two things matched and so nothing happened" is the outcome
    #: most likely to be mistaken for the rule not working.
    ambiguous: list[tuple[str, list[str]]] = field(default_factory=list)

    @property
    def mapping(self) -> dict[str, str]:
        return {m.from_id: m.into_id for m in self.merges}


def _rewrite(ids: list[str], mapping: dict[str, str]) -> list[str]:
    """References through the mapping, deduplicated, order preserved.

    Deduplicating matters: an event mentioning both ``RAG`` and ``retrieval
    augmented generation`` would otherwise carry the survivor's id twice and
    produce two identical MENTIONS edges.
    """
    out: list[str] = []
    for ident in ids:
        mapped = mapping.get(ident, ident)
        if mapped not in out:
            out.append(mapped)
    return out


class Canonicaliser:
    """Folds a batch's entities into the ones already stored, and into each other.

    Runs as its own node **before** ``resolve``, which is not an arbitrary
    ordering. The resolver finds claims to compare a candidate against by looking
    up ``claims_about(owner_id, subject_entity_ids)``. If a new claim's subject is
    still the fresh ``RAG`` node while the stored claim's subject is the old
    expansion, that lookup returns nothing and **no supersession is ever
    detected**. Canonicalising afterwards would leave the graph tidy and the
    record wrong, which is the worse of the two failures.
    """

    def __init__(self, store: Neo4jStore, unseal=None, *, limit: int = 2_000) -> None:
        self._store = store
        self._limit = limit
        # Entity names are sealed at rest when content encryption is on (ADR
        # 0010), and ciphertext does not match lexically. Unsealing here keeps
        # the rules looking at names; if it is unavailable the rules simply find
        # nothing, which costs a duplicate rather than causing a wrong merge.
        self._unseal = unseal or (lambda node: node)

    def canonicalise(self, owner_id: str, candidates: list[Candidate]) -> Canonicalisation:
        """Rewrites ``candidates`` in place and reports what it decided."""
        result = Canonicalisation()

        stored: dict[str, Entity] = {}
        for row in self._store.recent_entities(owner_id, self._limit):
            node = self._unseal(row.node)
            if isinstance(node, Entity):
                stored[node.id] = node

        # The pool a new name is matched against: stored entities first, so an
        # id already in the graph always wins and nothing stored ever has to be
        # rewritten. Entities new in this batch join it as they are accepted, so
        # a batch containing both "RAG" and its expansion resolves to one entity
        # even though neither was stored.
        pool: dict[str, Entity] = dict(stored)
        #: Survivors this batch touched, which are the only entities to write.
        touched: dict[str, Entity] = {}

        incoming = [e for candidate in candidates for e in candidate.entities]
        # Longest name first, so when two *new* names merge the more specific one
        # survives: "retrieval augmented generation" keeps "RAG" as an alias
        # rather than the reverse. Id as the tie-break keeps it deterministic.
        # (A stored name always survives regardless of length -- rewriting stored
        # references would need a migration this has no way to perform.)
        incoming.sort(key=lambda e: (-len(e.name), e.id))

        for entity in incoming:
            if entity.id in pool:
                # Not a merge: the same name mentioned again. Carry the stored
                # aliases forward, because `upsert` replaces the payload
                # wholesale and a re-mention would otherwise wipe out aliases an
                # earlier merge added -- silently re-opening the duplicate this
                # whole module exists to close.
                existing = pool[entity.id]
                entity.aliases = _merge_aliases(entity, existing.aliases)
                entity.first_seen_at_ms = min(
                    entity.first_seen_at_ms, existing.first_seen_at_ms
                )
                pool[entity.id] = entity
                touched[entity.id] = entity
                continue

            target, rule, tied = self._best(entity, pool)
            if tied:
                result.ambiguous.append((entity.id, tied))
                log.info(
                    "canonicalise ambiguous name=%r matched=%d targets", entity.name, len(tied)
                )
            if target is None:
                pool[entity.id] = entity
                touched[entity.id] = entity
                continue

            survivor = pool[target]
            survivor.aliases = _merge_aliases(survivor, [entity.name, *entity.aliases])
            survivor.last_seen_at_ms = max(survivor.last_seen_at_ms, entity.last_seen_at_ms)
            survivor.first_seen_at_ms = min(
                survivor.first_seen_at_ms, entity.first_seen_at_ms
            )
            touched[target] = survivor
            result.merges.append(
                Merge(from_id=entity.id, into_id=target, alias=entity.name, rule=rule or "")
            )

        self._apply(candidates, result.mapping, touched)
        log.info(
            "canonicalise merged=%d ambiguous=%d entities=%d",
            len(result.merges),
            len(result.ambiguous),
            len(touched),
        )
        return result

    def _best(
        self, entity: Entity, pool: dict[str, Entity]
    ) -> tuple[str | None, str | None, list[str]]:
        """The one pool entry this name should merge into, if exactly one stands out.

        Returns ``(target, rule, tied)``. A non-empty ``tied`` means two or more
        entries matched equally well and nothing is merged -- see the asymmetry
        in the module docstring.
        """
        best: list[tuple[str, str]] = []
        best_score = 0
        for other_id, other in pool.items():
            # A Person never merges with a Project, whatever the names say.
            # Without this, a project named after its owner collapses the two.
            if other.kind is not entity.kind:
                continue
            rule = match(entity.name, other.name)
            if rule is None:
                continue
            if rule == "containment" and entity.kind in CONTAINMENT_FORBIDDEN_KINDS:
                continue
            score = SCORES[rule]
            if score > best_score:
                best_score, best = score, [(other_id, rule)]
            elif score == best_score:
                best.append((other_id, rule))

        if not best:
            return (None, None, [])
        if len(best) > 1:
            return (None, None, sorted(ident for ident, _ in best))
        return (best[0][0], best[0][1], [])

    @staticmethod
    def _apply(
        candidates: list[Candidate],
        mapping: dict[str, str],
        touched: dict[str, Entity],
    ) -> None:
        """Rewrites every reference to a merged id, and replaces the entity set.

        **This is where a bug would hide.** A merge that updates the entity and
        misses a commitment's ``owed_by`` leaves an obligation pointing at an id
        no node has, so "what does Mina owe me" silently returns nothing. Every
        field holding an entity id is listed here; the parity test over the Rust
        schema is what catches a new one being added.
        """
        for candidate in candidates:
            for event in candidate.events:
                event.entity_ids = _rewrite(event.entity_ids, mapping)
            for claim in candidate.claims:
                claim.subject_entity_ids = _rewrite(claim.subject_entity_ids, mapping)
                commitment = claim.commitment
                if commitment is None:
                    continue
                commitment.owed_by_entity_id = mapping.get(
                    commitment.owed_by_entity_id, commitment.owed_by_entity_id
                )
                if commitment.owed_to_entity_id is not None:
                    commitment.owed_to_entity_id = mapping.get(
                        commitment.owed_to_entity_id, commitment.owed_to_entity_id
                    )

        # The survivors go on the first candidate and the rest are emptied: an
        # entity merged across two records in one batch belongs to neither, and
        # writing it once is the point. `write` upserts by id, so which candidate
        # carries it has no effect beyond this.
        if candidates:
            candidates[0].entities = list(touched.values())
            for candidate in candidates[1:]:
                candidate.entities = []


def _merge_aliases(entity: Entity, incoming: list[str]) -> list[str]:
    """Aliases unioned, case-insensitively, with the canonical name excluded.

    Order is kept stable so a re-ingest of the same batch writes an identical
    payload rather than a reshuffled one.
    """
    seen = {entity.name.lower()}
    out: list[str] = []
    for alias in [*entity.aliases, *incoming]:
        key = alias.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(alias)
    return out


__all__ = [
    "CONTAINMENT_FORBIDDEN_KINDS",
    "Canonicalisation",
    "Canonicaliser",

    "Merge",
    "match",
    "normalise",
]
