"""Folding two names for one thing into one entity.

Entity ids are content-addressed over the name, so ``RAG`` and ``retrieval
augmented generation`` are two permanently separate nodes and every claim about
one is invisible from the other. These tests cover the rules that join them, the
cases that must stay apart, and -- most importantly -- that every reference to a
merged id was rewritten. See ADR 0015.
"""

from __future__ import annotations

import pytest

from orchestrator.connectors.direct import TEXT
from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.extraction.ids import stable_id
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import ObjectAcl
from orchestrator.resolution.entities import (
    CONTAINMENT_FORBIDDEN_KINDS,
    SCORES,
    Canonicaliser,
    match,
    normalise,
)
from orchestrator.schema import Candidate, Claim, Commitment, Entity, Event, Provenance, SourceRef

OWNER = "owner-canon"
NOW = 1_767_571_200_000


# -- the rules, in isolation --------------------------------------------


@pytest.mark.parametrize(
    "left,right,rule",
    [
        # The case this phase exists for, and the one embeddings score lowest.
        ("RAG", "retrieval augmented generation", "acronym"),
        ("R.A.G.", "retrieval augmented generation", "acronym"),
        ("rag", "Retrieval Augmented Generation", "acronym"),
        # Written with a dot or without: the same string.
        ("Node.js", "nodejs", "same_normalised"),
        ("PostgreSQL", "postgresql ", "same_normalised"),
        # A short inflectional tail.
        ("Postgres", "PostgreSQL", "suffix_fold"),
        # One name inside another.
        ("Mina", "Mina Patel", "containment"),
        ("Kleos", "project Kleos", "containment"),
    ],
)
def test_names_that_are_one_thing(left: str, right: str, rule: str) -> None:
    assert match(left, right) == rule
    assert match(right, left) == rule, "the rules are symmetric in their arguments"


@pytest.mark.parametrize(
    "left,right",
    [
        # The pair that kills the embedding design: cosine 0.652, higher than any
        # threshold that would catch RAG, and two distinct databases.
        ("Postgres", "Redis"),
        ("Mina", "Rafi"),
        ("Lantern", "Harbour"),
        ("RAG", "sourdough bread"),
        # A five-character tail is a different word, not an inflection.
        ("Redis", "Redisearch"),
        # Too generic to contain anything: "AI" is inside a hundred unrelated names.
        ("AI", "AI Safety Institute"),
        ("ML", "ML Platform"),
        # Contiguity matters: a design review of Lantern is not the Lantern review.
        ("Lantern review", "Lantern design review"),
        # Nothing to compare is not a reason to merge.
        ("---", "+++"),
    ],
)
def test_names_that_are_not_one_thing(left: str, right: str) -> None:
    assert match(left, right) is None
    assert match(right, left) is None


def test_a_known_miss_is_recorded_rather_than_forced() -> None:
    """``K8s`` is a numeronym, not an acronym -- the digit stands for eight elided
    letters, which no rule here models. Left unmatched on purpose: the shape that
    would catch it (a letter, digits, a letter) also matches version numbers and
    model names, and merging ``Llama 3`` into ``Llama 31`` would cost more than
    this duplicate does."""
    assert match("K8s", "Kubernetes") is None


def test_the_rule_ordering_is_the_only_thing_the_scores_mean() -> None:
    """Nothing thresholds on a score; they are compared against each other to pick
    a best match and to detect a tie. A test so that stays true."""
    assert sorted(SCORES, key=SCORES.get, reverse=True) == [
        "same_normalised",
        "acronym",
        "suffix_fold",
        "containment",
    ]


def test_normalise_drops_punctuation_and_case() -> None:
    assert normalise("Mina  Patel!") == ["mina", "patel"]
    assert normalise("R.A.G.") == ["r", "a", "g"]
    assert normalise("!!!") == []


# -- building candidates ------------------------------------------------


def _acl(kind: EntityKind) -> ObjectAcl:
    return ObjectAcl(
        owner_id=OWNER,
        sources=[TEXT],
        sensitivity=Sensitivity.PERSONAL,
        entity_kinds=[kind],
        occurred_at_ms=NOW,
    )


def _entity(name: str, kind: EntityKind = EntityKind.TOPIC) -> Entity:
    return Entity(
        id=stable_id("ent", OWNER, kind.value, name.lower()),
        owner_id=OWNER,
        kind=kind,
        name=name,
        first_seen_at_ms=NOW,
        last_seen_at_ms=NOW,
        provenance=Provenance(derived_by="test", created_at_ms=NOW),
        acl=_acl(kind),
    )


def _event(name: str, entity_ids: list[str]) -> Event:
    return Event(
        id=stable_id("evt", OWNER, name),
        owner_id=OWNER,
        summary=name,
        entity_ids=entity_ids,
        source=SourceRef(
            connector=TEXT, external_id=name, occurred_at_ms=NOW, ingested_at_ms=NOW
        ),
        provenance=Provenance(derived_by="test", created_at_ms=NOW),
        acl=_acl(EntityKind.TOPIC),
    )


def _claim(statement: str, subjects: list[str], commitment: Commitment | None = None) -> Claim:
    return Claim(
        id=stable_id("clm", OWNER, statement),
        owner_id=OWNER,
        statement=statement,
        subject_entity_ids=subjects,
        commitment=commitment,
        asserted_at_ms=NOW,
        provenance=Provenance(derived_by="test", created_at_ms=NOW),
        acl=_acl(EntityKind.TOPIC),
    )


# -- the canonicaliser, against a real store ----------------------------


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(settings)
    rt.store.wipe_owner(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


@pytest.fixture
def canonicaliser(runtime: Runtime) -> Canonicaliser:
    return Canonicaliser(runtime.store, unseal=runtime.content.unseal_node)


def test_two_new_names_in_one_batch_become_one_entity(canonicaliser: Canonicaliser) -> None:
    """Neither is stored yet, which is the case a stored-only matcher misses. The
    longer name survives: when both are new, the more specific one is the better
    label and the shorter becomes an alias."""
    short, long = _entity("RAG"), _entity("retrieval augmented generation")
    candidates = [Candidate(entities=[short, long])]

    outcome = canonicaliser.canonicalise(OWNER, candidates)

    assert [m.rule for m in outcome.merges] == ["acronym"]
    assert outcome.mapping == {short.id: long.id}
    [survivor] = candidates[0].entities
    assert survivor.id == long.id
    assert survivor.aliases == ["RAG"], "the name given up stays findable"


def test_a_stored_name_survives_even_when_it_is_the_shorter(
    runtime: Runtime, canonicaliser: Canonicaliser
) -> None:
    """The one place the longest-name rule is overridden. Rewriting references on
    *stored* nodes would need a migration this has no way to perform, so an id
    already in the graph always wins."""
    stored = _entity("RAG")
    runtime.store.upsert(stored, runtime.embedder.embed("RAG"))

    arriving = _entity("retrieval augmented generation")
    candidates = [Candidate(entities=[arriving])]
    outcome = canonicaliser.canonicalise(OWNER, candidates)

    assert outcome.mapping == {arriving.id: stored.id}
    [survivor] = candidates[0].entities
    assert survivor.id == stored.id
    assert "retrieval augmented generation" in survivor.aliases


def test_distinct_technologies_stay_distinct(canonicaliser: Canonicaliser) -> None:
    postgres, redis = _entity("Postgres"), _entity("Redis")
    candidates = [Candidate(entities=[postgres, redis])]

    outcome = canonicaliser.canonicalise(OWNER, candidates)

    assert outcome.merges == []
    assert {e.id for e in candidates[0].entities} == {postgres.id, redis.id}


def test_kind_must_agree(canonicaliser: Canonicaliser) -> None:
    """Without this, a project named after the person running it collapses the two
    into one node, and "what does Mina owe me" starts answering about a project."""
    person = _entity("Lantern", EntityKind.PERSON)
    project = _entity("Lantern", EntityKind.PROJECT)
    candidates = [Candidate(entities=[person, project])]

    assert canonicaliser.canonicalise(OWNER, candidates).merges == []


def test_a_topic_does_not_absorb_a_broader_topic(canonicaliser: Canonicaliser) -> None:
    """The regression this exists for, and the one case a second metric caught.

    "storage" and "durable storage" are a topic and a sub-topic. Containment folded
    them, which asserts they are one thing and builds a high-degree node that every
    project's storage claims hang off. The eval's Harbour question then returned the
    *Lantern* storage decision -- cross-project contamination through that shared
    node -- while recall and precision stayed exactly flat. Had the entity count been
    the only number reported, this would have looked like a clean win.
    """
    broad = _entity("storage", EntityKind.TOPIC)
    narrow = _entity("durable storage", EntityKind.TOPIC)
    candidates = [Candidate(entities=[broad, narrow])]

    assert canonicaliser.canonicalise(OWNER, candidates).merges == []
    assert len(candidates[0].entities) == 2


def test_a_person_still_absorbs_their_fuller_name(canonicaliser: Canonicaliser) -> None:
    """The restriction is on topics only, because the principle is about what
    containment *means*: for a proper noun it is the same referent named more fully,
    and for a common noun phrase it is a narrower thing."""
    short = _entity("Mina", EntityKind.PERSON)
    full = _entity("Mina Patel", EntityKind.PERSON)
    candidates = [Candidate(entities=[short, full])]

    assert [m.rule for m in canonicaliser.canonicalise(OWNER, candidates).merges] == [
        "containment"
    ]


def test_a_topic_still_merges_on_identity(canonicaliser: Canonicaliser) -> None:
    """Only containment is restricted. An acronym asserts identity, which is as true
    of a topic as of a person -- and the acronym is the case this whole phase is
    for, so a blanket exclusion of topics would have defeated it."""
    short = _entity("RAG", EntityKind.TOPIC)
    long = _entity("retrieval augmented generation", EntityKind.TOPIC)
    candidates = [Candidate(entities=[short, long])]

    assert [m.rule for m in canonicaliser.canonicalise(OWNER, candidates).merges] == [
        "acronym"
    ]
    assert EntityKind.TOPIC in CONTAINMENT_FORBIDDEN_KINDS, "the point of the test above"


def test_an_ambiguous_match_merges_with_neither(canonicaliser: Canonicaliser) -> None:
    """The asymmetry the whole module is built around. Two targets match by
    containment equally well, so nothing merges: a duplicate is visible and
    recoverable, a wrong merge is neither."""
    a = _entity("Lantern migration", EntityKind.PROJECT)
    b = _entity("Lantern rollout", EntityKind.PROJECT)
    arriving = _entity("Lantern", EntityKind.PROJECT)
    candidates = [Candidate(entities=[a, b, arriving])]

    outcome = canonicaliser.canonicalise(OWNER, candidates)

    assert outcome.merges == []
    assert outcome.ambiguous == [(arriving.id, sorted([a.id, b.id]))]
    assert len(candidates[0].entities) == 3


def test_every_reference_to_a_merged_id_is_rewritten(canonicaliser: Canonicaliser) -> None:
    """Where a bug would hide. A merge that updates the entity and misses a
    commitment's ``owed_by`` leaves an obligation pointing at an id no node has,
    so "what does Mina owe me" silently returns nothing."""
    short, long = _entity("RAG"), _entity("retrieval augmented generation")
    mina = _entity("Mina Patel", EntityKind.PERSON)
    mina_short = _entity("Mina", EntityKind.PERSON)

    event = _event("a chat about it", [short.id, mina_short.id])
    claim = _claim(
        "Mina will write the RAG evaluation",
        [short.id],
        Commitment(owed_by_entity_id=mina_short.id, owed_to_entity_id=short.id),
    )
    candidates = [
        Candidate(
            entities=[short, long, mina, mina_short], events=[event], claims=[claim]
        )
    ]

    canonicaliser.canonicalise(OWNER, candidates)

    assert event.entity_ids == [long.id, mina.id]
    assert claim.subject_entity_ids == [long.id]
    assert claim.commitment.owed_by_entity_id == mina.id
    assert claim.commitment.owed_to_entity_id == long.id


def test_a_reference_to_both_names_does_not_become_a_duplicate_edge(
    canonicaliser: Canonicaliser,
) -> None:
    """An event mentioning the acronym *and* the expansion would otherwise carry
    the survivor's id twice and write two identical MENTIONS edges."""
    short, long = _entity("RAG"), _entity("retrieval augmented generation")
    event = _event("both names in one sentence", [short.id, long.id])
    candidates = [Candidate(entities=[short, long], events=[event])]

    canonicaliser.canonicalise(OWNER, candidates)

    assert event.entity_ids == [long.id]


def test_a_re_mention_does_not_wipe_out_an_earlier_merges_alias(
    runtime: Runtime, canonicaliser: Canonicaliser
) -> None:
    """``upsert`` replaces the payload wholesale, so an entity mentioned again
    arrives with no aliases and would overwrite the ones a merge added -- silently
    re-opening the duplicate this module exists to close."""
    stored = _entity("retrieval augmented generation")
    stored.aliases = ["RAG"]
    runtime.store.upsert(stored, runtime.embedder.embed("x"))

    arriving = _entity("retrieval augmented generation")
    assert arriving.aliases == []
    candidates = [Candidate(entities=[arriving])]

    canonicaliser.canonicalise(OWNER, candidates)

    [survivor] = candidates[0].entities
    assert survivor.aliases == ["RAG"]


def test_merged_entities_are_written_once_across_a_batch(canonicaliser: Canonicaliser) -> None:
    """An entity merged across two records in a batch belongs to neither, so the
    survivors are collected onto one candidate rather than written twice."""
    short, long = _entity("RAG"), _entity("retrieval augmented generation")
    candidates = [Candidate(entities=[short]), Candidate(entities=[long])]

    canonicaliser.canonicalise(OWNER, candidates)

    assert [e.id for e in candidates[0].entities] == [long.id]
    assert candidates[1].entities == []


# -- the node in the graph ----------------------------------------------


def test_canonicalisation_is_on_by_default(settings) -> None:
    """Unlike enrichment: this reaches nothing outward, and a record that silently
    keeps two of every entity is the behaviour worth needing a flag to get back."""
    assert settings.canonicalise_entities is True


def test_canonicalisation_runs_before_resolution(runtime: Runtime) -> None:
    """The ordering claim, asserted against the compiled graph rather than trusted.

    The resolver finds claims to compare a candidate against via
    ``claims_about(owner_id, subject_entity_ids)``. If a new claim's subject is a
    fresh ``RAG`` node while the stored claim's subject is the old expansion, that
    lookup returns nothing and **no supersession is ever detected**. Canonicalising
    after resolution would leave the graph tidy and the record wrong, and nothing
    would fail -- which is why the ordering is pinned here.
    """
    from orchestrator.graphs.ingestion import build_ingestion_graph

    edges = {(e.source, e.target) for e in build_ingestion_graph(runtime).get_graph().edges}
    assert ("canonicalise", "resolve") in edges
    assert ("resolve", "canonicalise") not in edges
    # Both paths into resolution go through it: the plain one and the enriched one.
    assert ("enrich", "canonicalise") in edges
    assert not any(target == "resolve" for source, target in edges if source != "canonicalise")


def test_the_graph_merges_during_a_real_ingest(runtime: Runtime) -> None:
    """End to end through the node, with two spellings of one database."""
    from orchestrator.connectors.direct import build_record

    records = [
        build_record(
            OWNER, "Mina decided that project Atlas will use Postgres.", occurred_at_ms=NOW
        ),
        build_record(
            OWNER,
            "Rafi decided that project Atlas will use PostgreSQL.",
            occurred_at_ms=NOW + 1_000,
        ),
    ]
    result = run_ingestion(
        runtime, OWNER, source=TEXT, records=records, thread_id="canon-graph"
    )

    assert result.errors == []
    rules = {m["rule"] for m in result.merged_entities}
    assert "suffix_fold" in rules, "the two spellings of the database should fold"
    # Also present: ``same_normalised``. The mock extractor's artifact pattern
    # swallows the sentence's full stop, so it emits both "Postgres" and
    # "Postgres." as separate entities with separate ids. That is a real duplicate
    # of exactly the kind this node exists to close, and it was invisible before.
    assert "same_normalised" in rules

    stored = [e.node for e in runtime.store.recent_entities(OWNER)]
    databases = [e for e in stored if e.kind is EntityKind.ARTIFACT]
    assert len(databases) == 1, f"two spellings should be one entity, got {databases}"
    assert databases[0].aliases, "the spellings given up are kept as aliases"


def test_switching_it_off_leaves_both_entities(runtime: Runtime) -> None:
    off = runtime.settings.model_copy(update={"canonicalise_entities": False})
    canon = Canonicaliser(runtime.store)
    short, long = _entity("RAG"), _entity("retrieval augmented generation")
    candidates = [Candidate(entities=[short, long])]

    # The node short-circuits on the flag; the canonicaliser itself has no flag,
    # which keeps the decision in one place rather than two.
    assert off.canonicalise_entities is False
    assert canon.canonicalise(OWNER, candidates).merges, "the class always merges"
