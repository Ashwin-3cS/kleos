"""The resolved record's text is not readable from the database.

Until ADR 0010 the honest confidentiality model was: sealed bodies and OAuth
tokens are ciphertext, and the derived memory -- who you talked to, what you
decided, what changed -- sits in Neo4j in the clear. That inverted the
sensitivity, because for most purposes the resolved record is the more revealing
artifact.

These tests hold the two properties that close it. Nothing a person said is
readable from the store, and a read unseals only what it is about to disclose --
so a denial costs no decryption and a grant that reads nothing causes no
plaintext to exist in this process at all.
"""

from __future__ import annotations

import pytest

from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.gateway_client import SealedContent
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.query import run_query
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import ObjectAcl, Scope
from orchestrator.schema import Claim, EncryptedContentRef, Entity, Event, Provenance
from orchestrator.storage.content import ContentCrypto, is_sealed, sealed_field_report

OWNER = "owner-at-rest"
TOKEN = "grant-for-at-rest"
BLIND_TOKEN = "grant-that-reads-nothing"

#: Phrases the mock fixtures put into the record. If any of these can be read out
#: of Neo4j, the feature does not work.
FIXTURE_PHRASES = ("Atlas", "migration", "decided", "committed")


class _CountingSealGateway:
    """A gateway whose seal/unseal is reversible and counted.

    Counting is the point: the claim is not only that content is encrypted but
    that a read decrypts *only what it discloses*. A test cannot see that without
    knowing how many crossings happened.
    """

    def __init__(self, scopes: dict[str, Scope]) -> None:
        self._scopes = scopes
        self.seals = 0
        self.unseals = 0

    # -- the crossing ----------------------------------------------------

    def seal_encrypt(self, plaintext: bytes) -> SealedContent:
        self.seals += 1
        return SealedContent(
            ciphertext=bytes(b ^ 0x5A for b in plaintext),
            ref=EncryptedContentRef(
                key_id="test-key", scheme="XOR_TEST", blob_id=None, byte_len=len(plaintext)
            ),
            attestation="TEST_ATTESTATION",
        )

    def seal_decrypt(self, ciphertext: bytes, key_id: str) -> bytes:
        assert key_id == "test-key", "the key id must travel with the sealed field"
        self.unseals += 1
        return bytes(b ^ 0x5A for b in ciphertext)

    # -- the rest of the client surface ----------------------------------

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scopes[grant_token]

    def adopt_session(self, token: str) -> None:
        pass

    def close(self) -> None:
        pass


def _scope(agent_id: str, **overrides) -> Scope:
    base = dict(
        agent_id=agent_id,
        owner_id=OWNER,
        sources=["mock"],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    return Scope(**{**base, **overrides})


@pytest.fixture
def runtime(settings, store):
    sealed_settings = settings.model_copy(update={"encrypt_content_at_rest": True})
    rt = Runtime.build(sealed_settings)
    gateway = _CountingSealGateway(
        {
            TOKEN: _scope("agent-at-rest"),
            BLIND_TOKEN: _scope("agent-blind", sources=["github"]),
        }
    )
    rt.gateway = gateway
    rt.content = ContentCrypto(gateway)
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.close()


def _raw_rows(runtime: Runtime) -> list[dict]:
    """Everything the database actually holds for this owner."""
    return runtime.store._run(
        "MATCH (n:Memory {owner_id: $owner_id}) "
        "RETURN n.payload AS payload, n.text AS text, labels(n) AS labels",
        owner_id=OWNER,
    )


def test_no_fixture_phrase_survives_in_the_database(runtime: Runtime) -> None:
    """The headline property, checked the blunt way: search the bytes that
    actually landed for the words that went in."""
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-ingest")

    rows = _raw_rows(runtime)
    assert rows, "ingestion wrote nothing"
    blob = " ".join(f"{r['payload']} {r['text']}" for r in rows)
    for phrase in FIXTURE_PHRASES:
        assert phrase not in blob, f"{phrase!r} is readable straight out of Neo4j"


def test_the_indexed_text_property_is_sealed_too(runtime: Runtime) -> None:
    """``n.text`` exists for the full-text index and is a second copy of the
    content. Sealing the payload and leaving this in the clear would have been a
    thorough-looking change that protected nothing."""
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-text")
    for row in _raw_rows(runtime):
        assert is_sealed(row["text"]), "n.text must be sealed, not only the payload"


def test_structure_stays_in_the_clear(runtime: Runtime) -> None:
    """Deliberate, and what keeps three of the four reads working without any
    decryption: ids, timestamps, labels, ACL fields and claim status are not
    content and are not sealed."""
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-structure")
    rows = runtime.store._run(
        "MATCH (n:Claim {owner_id: $owner_id}) "
        "RETURN n.id AS id, n.occurred_at_ms AS ts, n.claim_status AS status, "
        "n.acl_sensitivity AS sensitivity",
        owner_id=OWNER,
    )
    assert rows
    for row in rows:
        assert row["id"] and not is_sealed(row["id"])
        assert isinstance(row["ts"], int)
        assert row["status"] in {"active", "superseded", "contradicted", "reconciled"}
        assert row["sensitivity"] in {"public", "personal", "confidential", "restricted"}


def test_every_content_field_is_sealed_and_nothing_else_is(runtime: Runtime) -> None:
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-fields")
    ids = [r["id"] for r in runtime.store._run(
        "MATCH (n:Memory {owner_id: $owner_id}) RETURN n.id AS id", owner_id=OWNER
    )]
    stored = runtime.store.get_many(OWNER, ids)
    assert stored

    seen = set()
    for item in stored:
        report = sealed_field_report(item.node)
        for field, sealed in report.items():
            assert sealed, f"{type(item.node).__name__}.{field} reached the store unsealed"
            seen.add(f"{type(item.node).__name__}.{field}")
    # All three node types contribute, so a type silently skipped would show up.
    assert {"Event.summary", "Claim.statement", "Entity.name"} <= seen


def test_a_query_reads_back_the_plaintext(runtime: Runtime) -> None:
    """Sealing is only worth anything if the record still answers."""
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-query")
    answer = run_query(runtime, "what did we decide about the migration?", TOKEN)

    assert answer.answered
    assert not is_sealed(answer.text)
    assert any(phrase in answer.text for phrase in FIXTURE_PHRASES), (
        "the answer should contain readable content, not ciphertext"
    )


def test_a_declined_read_decrypts_nothing(runtime: Runtime) -> None:
    """The property the counting gateway exists for. A grant that reads nothing
    must cause no unsealing -- otherwise plaintext for objects the agent may not
    see would exist in this process, one bug away from being returned."""
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-denied")

    runtime.gateway.unseals = 0
    answer = run_query(runtime, "what did we decide?", BLIND_TOKEN)

    assert not answer.answered
    assert answer.considered > 0, "objects were retrieved and checked"
    assert runtime.gateway.unseals == 0, (
        f"{runtime.gateway.unseals} objects were decrypted for a read that disclosed none"
    )


def test_the_decrypt_budget_is_the_disclosure_budget(runtime: Runtime) -> None:
    """Unsealing is bounded by what the answer contains, not by what retrieval
    touched."""
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-budget")

    runtime.gateway.unseals = 0
    answer = run_query(runtime, "what did we decide about the migration?", TOKEN, top_k=5)

    disclosed = len(answer.citations)
    assert disclosed > 0
    # One crossing per content field of each disclosed object, so the bound is a
    # small multiple of the disclosed count -- never a multiple of `considered`.
    assert runtime.gateway.unseals <= disclosed * 4, (
        f"{runtime.gateway.unseals} unseals for {disclosed} disclosed objects"
    )


def test_supersession_still_resolves_against_sealed_claims(runtime: Runtime) -> None:
    """The subtle failure this guards. The resolver compares a candidate's
    statement against stored ones; stored statements are sealed, so without
    unsealing them every topic would differ, no supersession would be detected,
    and the batch would still report success."""
    result = run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-resolve")
    assert result.supersessions, (
        "the mock fixtures contain a superseding decision; finding none means the "
        "resolver compared plaintext against ciphertext"
    )


def test_embeddings_are_computed_from_plaintext(runtime: Runtime) -> None:
    """An embedding of ciphertext is noise, and retrieval would go quietly
    useless while every structural test kept passing. Checked by comparing the
    stored vector against one embedded from the known plaintext."""
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-embed")

    rows = runtime.store._run(
        "MATCH (n:Claim {owner_id: $owner_id}) RETURN n.id AS id, n.embedding AS embedding "
        "ORDER BY n.id LIMIT 1",
        owner_id=OWNER,
    )
    assert rows
    stored = runtime.store.get_many(OWNER, [rows[0]["id"]])[0]
    plaintext = runtime.content.unseal_node(stored.node).statement

    expected = runtime.embedder.embed(plaintext)
    assert rows[0]["embedding"] == pytest.approx(expected, abs=1e-6)


def test_sealing_is_idempotent() -> None:
    """A retry after a partial failure must not double-seal and produce something
    only two unseal passes could read."""
    gateway = _CountingSealGateway({})
    crypto = ContentCrypto(gateway)
    claim = Claim(
        id="clm-x",
        owner_id=OWNER,
        statement="project Atlas will use Postgres.",
        asserted_at_ms=1,
        provenance=Provenance(derived_by="t", created_at_ms=1),
        acl=ObjectAcl(
            owner_id=OWNER,
            sources=["mock"],
            sensitivity=Sensitivity.PERSONAL,
            entity_kinds=[EntityKind.PROJECT],
            occurred_at_ms=1,
        ),
    )
    crypto.seal_node(claim)
    once = claim.statement
    crypto.seal_node(claim)
    assert claim.statement == once, "a second seal pass must be a no-op"
    assert crypto.unseal_node(claim).statement == "project Atlas will use Postgres."


def test_a_sealed_field_is_recognisable_as_encrypted() -> None:
    """If one of these ever reaches a log or a UI it should read as obviously
    encrypted rather than as corrupt text."""
    gateway = _CountingSealGateway({})
    entity = Entity(
        id="ent-x",
        owner_id=OWNER,
        kind=EntityKind.PERSON,
        name="Alice",
        aliases=["A."],
        first_seen_at_ms=1,
        last_seen_at_ms=1,
        provenance=Provenance(derived_by="t", created_at_ms=1),
        acl=ObjectAcl(
            owner_id=OWNER,
            sources=["mock"],
            sensitivity=Sensitivity.PERSONAL,
            entity_kinds=[EntityKind.PERSON],
            occurred_at_ms=1,
        ),
    )
    ContentCrypto(gateway).seal_node(entity)
    assert entity.name.startswith("KSEAL1:")
    assert all(a.startswith("KSEAL1:") for a in entity.aliases)
    assert "Alice" not in entity.name


def test_turning_it_off_stores_plaintext(settings, store) -> None:
    """The flag is real, and the default is off while the smoke script and the
    eval run without a gateway. There is no middle state: a run either seals or
    it does not, and a failed crossing is an error rather than a downgrade."""
    rt = Runtime.build(settings.model_copy(update={"encrypt_content_at_rest": False}))
    try:
        assert type(rt.content).__name__ == "NullContentCrypto"
    finally:
        rt.close()


def test_every_node_type_declares_its_content_fields() -> None:
    """A node type with no entry in the registry is stored in the clear, which is
    exactly the kind of omission that would never announce itself."""
    from orchestrator.storage.content import CONTENT_FIELDS

    for model in (Event, Claim, Entity):
        assert model in CONTENT_FIELDS, f"{model.__name__} has no content fields declared"
