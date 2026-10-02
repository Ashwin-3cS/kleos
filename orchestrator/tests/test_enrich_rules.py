"""The three rules that bound what a fetched page may do.

Following a link means putting content a stranger wrote into a person's memory. The
rules are what keep that from being a way to rewrite the record, and each one exists
because of a specific way it could go wrong. See ADR 0014.
"""

from __future__ import annotations

import pytest

from orchestrator.connectors.direct import TEXT, build_record
from orchestrator.connectors.web import WEB
from orchestrator.enums import ClaimStatus, EntityKind, Sensitivity
from orchestrator.graphs.enrich import urls_in, urls_in_records
from orchestrator.permissions import ObjectAcl, Scope, evaluate
from orchestrator.resolution.resolver import Resolver, _is_weaker, _may_not_supersede
from orchestrator.schema import Candidate, Claim, Provenance
from orchestrator.tools.extract_page import WEB_SOURCE

NOW = 1_767_571_200_000


def _claim(statement: str, sources: list[str], asserted_at_ms: int, owner: str = "o") -> Claim:
    return Claim(
        id=f"clm-{abs(hash((statement, tuple(sources), asserted_at_ms)))}",
        owner_id=owner,
        statement=statement,
        subject_entity_ids=["ent-lantern"],
        asserted_at_ms=asserted_at_ms,
        provenance=Provenance(derived_by="test", created_at_ms=asserted_at_ms),
        acl=ObjectAcl(
            owner_id=owner,
            sources=sources,
            sensitivity=Sensitivity.PERSONAL,
            entity_kinds=[EntityKind.PROJECT],
            occurred_at_ms=asserted_at_ms,
        ),
    )


# -- rule 1: a page cannot overwrite what the person said ---------------


def test_a_web_claim_may_not_supersede_a_user_claim() -> None:
    """The whole mitigation for prompt injection through a fetched page.

    A page saying "the user has decided to use Postgres" extracts as a claim about
    Postgres, lands in the same subject neighbourhood as the person's real decision,
    and -- being newer -- would win on timestamp. Timestamps are the right tie-break
    between two things the person said and exactly the wrong one between something
    they said and something a stranger wrote.
    """
    mine = _claim("project Lantern will use Neo4j", [TEXT], NOW)
    theirs = _claim("project Lantern will use Postgres", [WEB], NOW + 1_000)
    assert _may_not_supersede(theirs, mine)


def test_a_user_claim_may_supersede_a_web_claim() -> None:
    """Deliberately asymmetric. Learning that a page was wrong is a normal thing to
    happen, and the record should follow."""
    theirs = _claim("project Lantern will use Postgres", [WEB], NOW)
    mine = _claim("project Lantern will use Neo4j", [TEXT], NOW + 1_000)
    assert not _may_not_supersede(mine, theirs)


def test_two_web_claims_resolve_normally_against_each_other() -> None:
    older = _claim("RAG uses a retriever", [WEB], NOW)
    newer = _claim("RAG uses a hybrid retriever", [WEB], NOW + 1_000)
    assert not _may_not_supersede(newer, older)


def test_a_claim_drawn_from_both_a_page_and_a_note_is_not_weaker() -> None:
    """``all`` rather than ``any``: a claim that also rests on the person's own
    account carries their account, and demoting it would lose that."""
    mixed = _claim("project Lantern will use Neo4j", [TEXT, WEB], NOW)
    assert not _is_weaker(mixed)
    assert _is_weaker(_claim("x", [WEB], NOW))


def test_a_claim_with_no_source_is_not_treated_as_weaker() -> None:
    """It is already denied by ``permits`` -- an empty source list grants nothing --
    so inferring weakness here would be a second, different rule about the same
    broken object."""
    assert not _is_weaker(_claim("x", [], NOW))


def test_the_resolver_records_a_contradiction_instead_of_superseding(store) -> None:
    """Blocked, but not silently dropped: the disagreement between a page and the
    person is worth keeping, with neither overwriting the other."""
    resolver = Resolver(store)
    mine = _claim("project Lantern will use Neo4j", [TEXT], NOW, owner="owner-rule1")
    theirs = _claim("project Lantern will use Postgres", [WEB], NOW + 1_000, owner="owner-rule1")

    [_, second] = resolver.resolve_batch(
        "owner-rule1",
        [Candidate(claims=[mine]), Candidate(claims=[theirs])],
    )
    assert second.contradictions, "the disagreement should be recorded"
    assert not second.supersessions, "a page must not supersede the person"
    assert mine.status is ClaimStatus.ACTIVE, "the person's claim stands"


# -- rule 2: fetched material is its own source, at public sensitivity ---


def test_the_web_source_id_is_the_same_everywhere() -> None:
    """Two modules name it; a mismatch would silently create a second source that no
    grant covers and no scope excludes."""
    assert WEB == WEB_SOURCE == "web"


def test_a_grant_over_my_own_notes_does_not_reach_the_open_web() -> None:
    """If a page's claims carried the referring utterance's source, "read my notes"
    would silently include everything any page those notes linked to asserted -- and
    ``permits`` would be right to allow it, because the object would be claiming to be
    a note."""
    page_claim = _claim("RAG combines a retriever with a generator", [WEB], NOW)
    notes_only = Scope(
        agent_id="a",
        owner_id="o",
        sources=[TEXT],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.RESTRICTED,
    )
    decision = evaluate(notes_only, page_claim.acl, NOW + 1)
    assert not decision.allowed
    assert decision.reason.value == "source_not_in_scope"


def test_a_public_scope_can_read_reference_material_and_nothing_personal() -> None:
    """What public sensitivity buys: an agent that may read what you read without
    reading anything about you."""
    page = _claim("RAG combines a retriever with a generator", [WEB], NOW)
    page.acl.sensitivity = Sensitivity.PUBLIC
    mine = _claim("project Lantern will use Neo4j", [TEXT], NOW)

    reference_only = Scope(
        agent_id="a",
        owner_id="o",
        sources=[WEB, TEXT],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.PUBLIC,
    )
    assert evaluate(reference_only, page.acl, NOW + 1).allowed
    assert not evaluate(reference_only, mine.acl, NOW + 1).allowed


# -- the URL scanner ----------------------------------------------------


def test_urls_are_found_in_order_and_deduplicated() -> None:
    found = urls_in(
        "see https://a.example/one and https://b.example/two and https://a.example/one again"
    )
    assert found == ["https://a.example/one", "https://b.example/two"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("read https://example.com/page.", "https://example.com/page"),
        ("(https://example.com/page)", "https://example.com/page"),
        ("link: https://example.com/page,", "https://example.com/page"),
        ("<https://example.com/page>", "https://example.com/page"),
    ],
)
def test_sentence_punctuation_is_not_part_of_the_url(text: str, expected: str) -> None:
    assert urls_in(text) == [expected]


def test_a_relative_or_bare_host_is_not_a_url() -> None:
    assert urls_in("see /docs/page and example.com and www.example.com") == []


def test_the_title_is_never_scanned_for_urls() -> None:
    """The regression this exists for. A title is a derived label -- the first ninety
    characters of the body -- so a URL found there may be a *fragment* that the
    truncation cut in half. The first live run scanned it, found
    `.../wiki/Retrieval` where the body said `.../wiki/Retrieval-augmented_generation`,
    and fetched both. The fragment was a real page, so nothing failed and the record
    quietly gained claims about the wrong subject.
    """
    long_url = "https://en.wikipedia.org/wiki/Retrieval-augmented_generation"
    record = build_record("o", f"I learnt about retrieval augmented generation from {long_url}")
    raw = record.model_dump(mode="json")

    assert urls_in_records([raw]) == {record.external_id: [long_url]}
    assert long_url not in record.title


def test_a_records_own_url_is_not_followed() -> None:
    """That is where the record came from, not something it refers to, and fetching
    it would re-read what we already have."""
    raw = build_record("o", "no links in this one").model_dump(mode="json")
    raw["url"] = "https://example.com/source"
    assert urls_in_records([raw]) == {}


def test_a_record_with_no_urls_yields_nothing() -> None:
    raw = build_record("o", "a thought with no links").model_dump(mode="json")
    assert urls_in_records([raw]) == {}
