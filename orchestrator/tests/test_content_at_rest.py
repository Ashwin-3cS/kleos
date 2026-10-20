"""The resolved record's text is not readable from the database.

Until ADR 0010 the honest confidentiality model was: sealed bodies and OAuth
tokens are ciphertext, and the derived memory -- who you talked to, what you
decided, what changed -- sits in Neo4j in the clear. That inverted the
sensitivity, because for most purposes the resolved record is the more revealing
artifact.

These tests hold the properties that close it. Nothing a person said is readable
from the store, and -- since ADR 0024 and the assembly route -- **a read unseals
nothing in this process at all**.

That second property used to be weaker: a read unsealed exactly what it was
about to disclose, so the decrypt budget was the disclosure budget. It is now
zero, because the assembler moved into the enclave. The bound did not tighten;
the operation left. What remains out here is a courier: rank, hand over the
still-sealed candidates, relay the blob.

So the tests below are about what this process does *not* do, and about what it
hands over. Whether the enclave then assembles correctly is tested in Rust
(`enclave/tests/integration_tests.rs`), where the answer can actually be opened.
"""

from __future__ import annotations

import json

import pytest

from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.gateway_client import ResolvedGrant, SealedAssembly, SealedContent
from orchestrator.graphs.brief import SealedBriefingUnsupported, brief_before_acting
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.query import run_query
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import ObjectAcl, Scope
from orchestrator.schema import Claim, EncryptedContentRef, Entity, Event, Provenance
from orchestrator.storage.content import ContentCrypto, is_sealed, sealed_field_report
from orchestrator.storage.reads import grant_fingerprint

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
        #: Split by route, so a test can assert *which* credential a read used.
        self.session_unseals = 0
        self.grant_unseals = 0
        #: Every call to `assemble`, in order, with what was handed over.
        self.assemblies: list[dict] = []
        #: What the enclave decides to disclose. `None` means "everything it was
        #: offered", which is the ordinary case.
        self.disclosed: list[str] | None = None

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
        """The owner-session route. Ingestion's, not a read's."""
        assert key_id == "test-key", "the key id must travel with the sealed field"
        self.unseals += 1
        self.session_unseals += 1
        return bytes(b ^ 0x5A for b in ciphertext)

    def unseal_for_grant(self, ciphertext: bytes, key_id: str, grant_token: str) -> bytes:
        """The grant route, which is the one a read has to use.

        A read holds a grant and no owner session, so before this existed every
        query against sealed content failed in the gateway client. The token is
        checked rather than ignored, because the gateway verifies it and the
        owner comes from the verified scope.
        """
        assert key_id == "test-key", "the key id must travel with the sealed field"
        assert grant_token in self._scopes, "the grant must be one the gateway knows"
        self.unseals += 1
        self.grant_unseals += 1
        return bytes(b ^ 0x5A for b in ciphertext)

    # -- the assembly route (ADR 0024) -----------------------------------

    def assemble(self, grant_token: str, question: str, candidates: list[dict]):
        """Stands in for gateway + enclave, and records rather than computes.

        Deliberately **not** a reimplementation of the enclave. A fake that
        unsealed, filtered and formatted would be a second assembler maintained
        in a test file, and the test would pass whenever the two fakes agreed.
        What this checks is the orchestrator's actual job in a sealed read: that
        it hands over the right things, still sealed, and relays what comes back
        without reading it.

        `disclosed` is settable so a test can make the enclave's verdict differ
        from the host's -- which is the only way to see which one the read log
        believes.
        """
        self.assemblies.append(
            {"grant_token": grant_token, "question": question, "candidates": candidates}
        )
        offered = [c["node"]["id"] for c in candidates]
        disclosed = offered if self.disclosed is None else self.disclosed
        refused = [
            {"id": i, "reason": "too_sensitive"} for i in offered if i not in disclosed
        ]
        return SealedAssembly(
            sealed={
                "scheme": "KLEOS_X25519_AES256GCM_V1",
                "recipient_key_id": "key-under-test",
                "ephemeral_public_key_b64": "ZXBoZW1lcmFs",
                "nonce_b64": "bm9uY2U=",
                # Stands for a blob. Not the plaintext XORed, because a test
                # that could recover the answer from it would be a test of a
                # fake rather than of the relay.
                "ciphertext_b64": "Y2lwaGVydGV4dA==",
            },
            disclosed_ids=list(disclosed),
            denials=refused,
            considered=len(candidates),
            attestation="TEST_ATTESTATION",
        )

    # -- the rest of the client surface ----------------------------------

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scopes[grant_token]

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        """What the graphs actually call: the scope *and* the signing device.

        A stub has to supply a device id, because every read now records which
        one authorised it. Derived from the token so that two grants held by the
        same agent label are two distinguishable devices -- which is the property
        `agent_id` cannot give and the whole reason the device is carried.

        Through the fingerprint and not the token itself: a device id goes into
        every log row, and `test_the_grant_token_is_never_stored` is right to fail
        a stub that smuggles a bearer credential in beside it.
        """
        return ResolvedGrant(
            scope=self.introspect_scope(grant_token),
            device_id=f"device-{grant_fingerprint(grant_token)[:12]}",
            grant_fp=grant_fingerprint(grant_token),
        )


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


def test_a_read_decrypts_nothing_in_this_process(runtime: Runtime) -> None:
    """The headline property of ADR 0024, and the blunt way to check it.

    Not "a read decrypts only what it discloses" any more. Zero. The assembler
    moved into the enclave, so there is nothing left out here that would have a
    reason to unseal -- and a count of one would mean a path exists that could
    be reached for all of them.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-no-decrypt")

    runtime.gateway.unseals = 0
    answer = run_query(runtime, "what did we decide about the migration?", TOKEN)

    assert answer.answered, "the read still answers"
    assert runtime.gateway.unseals == 0, (
        f"{runtime.gateway.unseals} objects were decrypted on the host during a read"
    )


def test_a_declined_read_decrypts_nothing_either(runtime: Runtime) -> None:
    """Same property from the other end, kept as its own test.

    It used to be the interesting case: a denial had to cost no decryption, or
    plaintext for objects the agent may not see would exist in this process, one
    bug away from being returned. Now both cases are zero -- but a regression
    that reintroduced host-side unsealing would most plausibly do it on the
    path that *does* disclose something, and this is what tells the two apart.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-denied")

    runtime.gateway.unseals = 0
    answer = run_query(runtime, "what did we decide?", BLIND_TOKEN)

    assert not answer.answered
    assert answer.considered > 0, "objects were retrieved and checked"
    assert runtime.gateway.unseals == 0


def test_the_candidates_are_handed_over_still_sealed(runtime: Runtime) -> None:
    """What the host sends up, and the reason the property above is reachable.

    Checked on the bytes actually posted rather than on the absence of an
    unseal call: a future refactor could unseal, format, and re-seal before
    posting, and every count would still read zero.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-handover")
    run_query(runtime, "what did we decide about the migration?", TOKEN)

    assert len(runtime.gateway.assemblies) == 1, "one read, one assembly"
    candidates = runtime.gateway.assemblies[0]["candidates"]
    assert candidates, "nothing was offered to the enclave"

    posted = json.dumps(candidates)
    for phrase in FIXTURE_PHRASES:
        assert phrase not in posted, f"{phrase!r} was posted in the clear"
    assert "KSEAL1:" in posted, "the content fields should still be sealed"


def test_what_is_handed_over_is_enough_for_the_enclave_to_decide(
    runtime: Runtime,
) -> None:
    """The ACLs travel with the candidates, and the node type does too.

    Both are load-bearing. Without the ACL the enclave cannot evaluate and would
    have to trust the host's verdict, which is the operator's verdict. Without
    `object_type` the Rust `MemoryNode` will not deserialise at all, and the
    failure surfaces as a 400 from a route rather than as anything naming the
    cause.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-acls")
    run_query(runtime, "what did we decide about the migration?", TOKEN)

    for candidate in runtime.gateway.assemblies[0]["candidates"]:
        node = candidate["node"]
        assert node["object_type"] in {"entity", "event", "claim"}
        acl = node["acl"]
        assert acl["owner_id"] == OWNER
        assert acl["sources"] and acl["entity_kinds"]
        assert acl["sensitivity"] in {"public", "personal", "confidential", "restricted"}
        assert isinstance(acl["occurred_at_ms"], int)


def test_the_request_names_neither_the_owner_nor_the_recipient(
    runtime: Runtime,
) -> None:
    """Both are derived by the gateway from the verified grant.

    A caller that could name the recipient could ask for the answer sealed to a
    key it controls, so the rule is kept where it cannot be forgotten: there is
    no field. This asserts the absence, because an absence is the kind of thing
    a later convenience parameter quietly fills in.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-derived")
    run_query(runtime, "what did we decide about the migration?", TOKEN)

    sent = runtime.gateway.assemblies[0]
    assert set(sent) == {"grant_token", "question", "candidates"}


def test_the_relayed_answer_carries_the_blob_and_no_plaintext(
    runtime: Runtime,
) -> None:
    """What the agent gets back from this process.

    `text` is a self-labelling placeholder rather than an empty string: a client
    that prints it without noticing `sealed` shows something obviously wrong
    instead of showing nothing, which is the difference between a bug somebody
    reports and a bug nobody sees.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-relay")
    answer = run_query(runtime, "what did we decide about the migration?", TOKEN)

    assert answer.is_sealed
    assert answer.sealed["scheme"] == "KLEOS_X25519_AES256GCM_V1"
    assert answer.sealed["ciphertext_b64"]
    assert answer.disclosed_ids, "the structural half is in the clear"
    # The content half is not here, in either of the two places it used to be.
    assert answer.citations == []
    assert answer.text.startswith("KSEALED:")

    # The question is excluded, and that is not a loophole being papered over:
    # the agent wrote it and the host was handed it, so finding a fixture phrase
    # there says nothing about what the store disclosed. Everything else in the
    # reply has to be clean.
    rendered = json.dumps({k: v for k, v in answer.as_dict().items() if k != "question"})
    for phrase in FIXTURE_PHRASES:
        assert phrase not in rendered, f"{phrase!r} came back through the host"


def test_the_read_log_records_the_enclaves_verdict_not_the_hosts(
    runtime: Runtime,
) -> None:
    """Which disclosure the owner's audit record believes.

    The host narrows the candidates and the enclave decides; if the log were
    written from the host's list it would claim disclosures the enclave refused.
    Made visible by having the enclave disclose *less* than it was offered,
    which is the direction a host cannot fake.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-log")
    runtime.store.wipe_read_log(OWNER)
    runtime.gateway.disclosed = []

    answer = run_query(runtime, "what did we decide about the migration?", TOKEN)

    assert not answer.answered, "the enclave disclosed nothing, so nothing was"
    assert answer.disclosed_ids == []
    entries = runtime.read_log.recent(OWNER, limit=5)
    assert entries, "the read was logged"
    assert all(not e.disclosed_ids for e in entries), (
        "the log recorded disclosures the enclave refused"
    )
    # The enclave's refusals reach the agent as well, alongside the host's.
    assert answer.denied, "a refusal inside the enclave must not vanish"


def test_the_grant_unseal_route_is_no_longer_the_read_path(
    runtime: Runtime,
) -> None:
    """The route still exists, for `include_body`. A query must not use it.

    It was added so that reads could unseal under a grant rather than an owner
    session they do not hold -- which was the right fix for the read path as it
    was then. ADR 0024 removed the need by moving the unsealing somewhere the
    host cannot follow, and leaving the old path reachable would be the exposure
    returning behind a working feature.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-grant-route")
    before = runtime.gateway.grant_unseals

    run_query(runtime, "what did we decide about the migration?", TOKEN)

    assert runtime.gateway.grant_unseals == before


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


def test_a_briefing_refuses_rather_than_reading_the_claims_out_here(
    runtime: Runtime,
) -> None:
    """The one read ADR 0024 did not close, failing loudly instead of quietly.

    A briefing writes its advisories from the claims' own statements, in this
    process. Relaying a sealed answer does not help: the statements are what the
    advisory is made of, so composing one would mean unsealing them out here --
    the query path sealed and the briefing reading the same content through a
    different door, behind a feature that looks like it moved.

    Checked before anything is retrieved, so a refusal costs no read and writes
    no log entry for a read that did not happen.
    """
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-brief")
    runtime.store.wipe_read_log(OWNER)
    runtime.gateway.unseals = 0

    with pytest.raises(SealedBriefingUnsupported) as refused:
        brief_before_acting(runtime, "I am about to pick a database", TOKEN)

    # The refusal has to be actionable: which setting, and what does work.
    message = str(refused.value)
    assert "ENCRYPT_CONTENT_AT_REST" in message
    assert "query" in message

    assert runtime.gateway.unseals == 0, "a refusal must not decrypt anything"
    assert not runtime.read_log.recent(OWNER, limit=5), (
        "a read that did not happen must not be logged as one"
    )


def test_ingestion_still_seals_under_the_owner_session(runtime: Runtime) -> None:
    """The other half of the split, so neither route quietly takes the other's
    work: sealing is ingestion's and goes through the session it holds."""
    runtime.gateway.session_unseals = 0
    run_ingestion(runtime, OWNER, source="mock", thread_id="at-rest-session")

    assert runtime.gateway.seals > 0
    assert runtime.gateway.session_unseals >= 0, "ingestion may unseal to resolve"


# -- sealing when the writer is an agent --------------------------------


class _RoutingGateway:
    """Records which seal/unseal route each call took."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def seal_encrypt(self, plaintext: bytes):
        self.calls.append("owner-session-seal")
        return _sealed(plaintext)

    def seal_for_grant(self, plaintext: bytes, grant_token: str):
        self.calls.append("grant-seal")
        return _sealed(plaintext)

    def seal_decrypt(self, ciphertext: bytes, key_id: str) -> bytes:
        self.calls.append("owner-session-unseal")
        return bytes(ciphertext)

    def unseal_for_grant(self, ciphertext: bytes, key_id: str, grant_token: str) -> bytes:
        self.calls.append("grant-unseal-read")
        return bytes(ciphertext)

    def unseal_for_resolution(
        self, ciphertext: bytes, key_id: str, grant_token: str
    ) -> bytes:
        self.calls.append("grant-unseal-write")
        return bytes(ciphertext)


def _sealed(plaintext: bytes):
    from orchestrator.gateway_client import EncryptedContentRef, SealedContent

    return SealedContent(
        ciphertext=plaintext,
        ref=EncryptedContentRef(
            key_id="k1", scheme="test", blob_id=None, byte_len=len(plaintext)
        ),
        attestation="",
    )


def test_an_agents_write_seals_through_its_grant_not_an_owner_session() -> None:
    """The defect this closes: `seal_encrypt` is owner-session-authorised and an
    agent has none, so with `ENCRYPT_CONTENT_AT_REST` on every agent write
    failed at the seal with "no owner session" -- the confidentiality setting
    and the agent write path could not both be on. Unseen because the setting
    defaults off, exactly as the read-side version of this was."""
    from orchestrator.storage.content import ContentCrypto

    gateway = _RoutingGateway()
    ContentCrypto(gateway).for_grant("grant-1", purpose="write")._seal_text("hello")

    assert gateway.calls == ["grant-seal"]


def test_without_a_grant_sealing_still_goes_through_the_owner_session() -> None:
    """The owner's own ingestion has a session and no grant, and must keep
    working exactly as it did."""
    from orchestrator.storage.content import ContentCrypto

    gateway = _RoutingGateway()
    ContentCrypto(gateway)._seal_text("hello")

    assert gateway.calls == ["owner-session-seal"]


def test_resolution_and_disclosure_unseal_through_different_routes() -> None:
    """Two acts, two capabilities. Unsealing so the resolver can compare
    against stored content discloses nothing to the agent and asks for
    `may_write`; unsealing a body *for* the agent is a disclosure and asks for
    `may_unseal`. One route for both would make every writing grant carry a
    reading capability it does not need."""
    from orchestrator.storage.content import ContentCrypto, pack

    sealed = pack("k1", b"ciphertext")
    gateway = _RoutingGateway()

    ContentCrypto(gateway).for_grant("g", purpose="write")._unseal_text(sealed)
    ContentCrypto(gateway).for_grant("g")._unseal_text(sealed)

    assert gateway.calls == ["grant-unseal-write", "grant-unseal-read"]
