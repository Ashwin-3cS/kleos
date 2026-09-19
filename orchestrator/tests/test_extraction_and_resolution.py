from __future__ import annotations

from orchestrator.connectors.mock import MockConnector
from orchestrator.enums import ClaimStatus, EntityKind
from orchestrator.extraction.mock import MockExtractor
from orchestrator.resolution.resolver import Resolver
from orchestrator.retrieval.embeddings import HashedTokenEmbedder

OWNER = "owner-test"


def test_mock_extractor_is_deterministic():
    record = next(iter(MockConnector().fetch(OWNER, 0)))
    a = MockExtractor().extract(OWNER, record)
    b = MockExtractor().extract(OWNER, record)
    assert [e.id for e in a.entities] == [e.id for e in b.entities]
    assert [c.id for c in a.claims] == [c.id for c in b.claims]


def test_mock_extractor_finds_project_and_claim():
    record = next(iter(MockConnector().fetch(OWNER, 0)))
    candidate = MockExtractor().extract(OWNER, record)
    kinds = {e.kind for e in candidate.entities}
    assert EntityKind.PROJECT in kinds
    assert EntityKind.PERSON in kinds
    assert any("Atlas" in c.statement for c in candidate.claims)


def test_sensitive_record_body_is_withheld_from_the_event():
    sensitive = [r for r in MockConnector().fetch(OWNER, 0) if r.sensitive]
    assert sensitive, "fixture set must contain a sensitive record"
    candidate = MockExtractor().extract(OWNER, sensitive[0])
    assert candidate.events[0].body is None


def test_resolver_supersedes_the_earlier_claim(store):
    store.wipe_owner(OWNER)
    resolver = Resolver(store)
    extractor = MockExtractor()
    embedder = HashedTokenEmbedder(256)

    records = list(MockConnector().fetch(OWNER, 0))
    supersessions = []
    for record in records[:2]:
        candidate = extractor.extract(OWNER, record)
        resolution = resolver.resolve(OWNER, candidate)
        supersessions += resolution.supersessions
        for node in [*candidate.entities, *candidate.events, *resolution.new_claims]:
            text = getattr(node, "statement", None) or getattr(node, "summary", None) or node.name
            store.upsert(node, embedder.embed(text))
        for claim in resolution.new_claims:
            for entity_id in claim.subject_entity_ids:
                store.link(claim.id, "ABOUT", entity_id)
            for superseded in claim.supersedes:
                store.set_claim_status(superseded, ClaimStatus.SUPERSEDED.value)

    assert supersessions, "the Neo4j decision should supersede the Postgres one"
    store.wipe_owner(OWNER)


def test_hashed_embeddings_are_unit_length_and_stable():
    embedder = HashedTokenEmbedder(64)
    a = embedder.embed("project Atlas will use Neo4j")
    b = embedder.embed("project Atlas will use Neo4j")
    assert a == b
    assert abs(sum(x * x for x in a) - 1.0) < 1e-9
