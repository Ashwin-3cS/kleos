"""Reading a sealed body back: the first time anything in this service has.

The path existed in two halves. `LocalQuiltStore.get` was implemented,
owner-partitioned and guarded against path traversal; the gateway proxied the
enclave's decrypt. Nothing joined them -- no code converted a stored
`EncryptedContentRef` into a `BlobRef` -- so `get` had zero call sites and a
sealed body was durable and unreadable. The documentation said the gateway did
not expose decrypt, which was false, and the true statement was nowhere.

The property that needs the most holding is the distinction between two
failures, because collapsing them hides a confidentiality bug behind an empty
record:

- **not_stored** -- the bytes are genuinely absent.
- **backend_not_wired** -- the bytes exist and *this* deployment cannot reach
  them. A body sealed to local disk and read later with Walrus configured. ADR
  0002 and 0008 refuse a silent fall back to local disk on purpose, so this has
  to surface as its own answer.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.gateway_client import ResolvedGrant, SealedContent
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import ObjectAcl, Scope
from orchestrator.schema import EncryptedContentRef, Event, Provenance, SourceRef
from orchestrator.storage.blobs import (
    BlobRef,
    LocalQuiltStore,
    WalrusQuiltStore,
    ref_from_encrypted_content,
)
from orchestrator.storage.bodies import (
    BACKEND_NOT_WIRED,
    NO_REF,
    NOT_PERMITTED,
    NOT_STORED,
    load_body,
)
from orchestrator.storage.reads import grant_fingerprint

OWNER = "owner-bodies"
TOKEN = "grant-for-bodies"
BODY = "the transcript nobody outside the enclave was supposed to read"
NOW = 1_700_000_000_000


class _Gateway:
    """Seals and unseals with a reversible XOR, counting the routes separately.

    Which *route* a read used is the thing worth asserting: an agent holds a
    grant and no owner session, so a read going through the session route is a
    read that cannot work in production.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self.grant_unseals = 0
        self.session_unseals = 0

    def seal_encrypt(self, plaintext: bytes) -> SealedContent:
        return SealedContent(
            ciphertext=bytes(b ^ 0x5A for b in plaintext),
            ref=EncryptedContentRef(
                key_id="test-key", scheme="XOR_TEST", blob_id=None, byte_len=len(plaintext)
            ),
            attestation="TEST",
        )

    def unseal_for_grant(self, ciphertext: bytes, key_id: str, grant_token: str) -> bytes:
        assert key_id == "test-key"
        assert grant_token == TOKEN
        self.grant_unseals += 1
        return bytes(b ^ 0x5A for b in ciphertext)

    def seal_decrypt(self, ciphertext: bytes, key_id: str) -> bytes:
        self.session_unseals += 1
        return bytes(b ^ 0x5A for b in ciphertext)

    def introspect_scope(self, grant_token: str) -> Scope:
        return self._scope

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        return ResolvedGrant(
            scope=self._scope,
            device_id="device-1",
            grant_fp=grant_fingerprint(grant_token),
        )

    def close(self) -> None:
        pass


def _scope(**overrides) -> Scope:
    base = dict(
        agent_id="agent-bodies",
        owner_id=OWNER,
        sources=["mock"],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
        may_unseal=True,
    )
    return Scope(**{**base, **overrides})


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    rt.gateway = _Gateway(_scope())
    rt.store.wipe_owner(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def _event(ref: EncryptedContentRef | None, *, body: str | None = None) -> Event:
    return Event(
        id="evt_sealed_body",
        owner_id=OWNER,
        summary="a sealed record",
        body=body,
        entity_ids=[],
        source=SourceRef(
            connector="mock",
            external_id="rec-1",
            url=None,
            occurred_at_ms=NOW,
            ingested_at_ms=NOW,
        ),
        encrypted_content=ref,
        provenance=Provenance(derived_by="test", created_at_ms=NOW),
        acl=ObjectAcl(
            owner_id=OWNER,
            sources=["mock"],
            sensitivity=Sensitivity.CONFIDENTIAL,
            entity_kinds=[EntityKind.PROJECT],
            occurred_at_ms=NOW,
        ),
    )


def _seal_and_store(runtime: Runtime, text: str) -> EncryptedContentRef:
    """What ingestion does: seal in the enclave, then store the ciphertext."""
    sealed = runtime.gateway.seal_encrypt(text.encode())
    ref = runtime.blobs.put(OWNER, sealed.ciphertext)
    return EncryptedContentRef(
        key_id=sealed.ref.key_id,
        scheme=sealed.ref.scheme,
        blob_id=ref.blob_id,
        patch_id=ref.patch_id,
        byte_len=ref.byte_len,
    )


# -- the middle that was missing ----------------------------------------


def test_the_converter_addresses_the_stored_patch() -> None:
    ref = EncryptedContentRef(
        key_id="k", scheme="s", blob_id="quilt-1", patch_id="patch-1", byte_len=12
    )
    assert ref_from_encrypted_content(ref, "local-quilt") == BlobRef(
        blob_id="quilt-1", patch_id="patch-1", byte_len=12, backend="local-quilt"
    )


def test_a_ref_from_before_blobs_existed_has_nothing_to_read() -> None:
    """`blob_id` was always `None` until ADR 0002, so sealing a record destroyed
    it behind a ref that advertised a `key_id` and a `byte_len`."""
    ref = EncryptedContentRef(key_id="k", scheme="s", blob_id=None, byte_len=12)
    with pytest.raises(ValueError, match="no blob id"):
        ref_from_encrypted_content(ref, "local-quilt")


def test_a_sealed_body_comes_back(runtime: Runtime) -> None:
    """End to end, and the first time in this repository that a sealed body has
    been read back out."""
    ref = _seal_and_store(runtime, BODY)

    loaded = load_body(
        runtime, OWNER, _event(ref), scope=_scope(), grant_token=TOKEN, now_ms=NOW + 1
    )

    assert loaded.text == BODY
    assert loaded.unavailable is None


def test_the_read_unseals_under_the_grant_not_a_session(runtime: Runtime) -> None:
    """An agent holds a grant and no owner session, so a read going through the
    session route is one that cannot work in production."""
    ref = _seal_and_store(runtime, BODY)

    load_body(
        runtime, OWNER, _event(ref), scope=_scope(), grant_token=TOKEN, now_ms=NOW + 1
    )

    assert runtime.gateway.grant_unseals == 1
    assert runtime.gateway.session_unseals == 0


def test_an_unsealed_body_needs_no_round_trip(runtime: Runtime) -> None:
    loaded = load_body(
        runtime,
        OWNER,
        _event(None, body="never sealed"),
        scope=_scope(),
        grant_token=TOKEN,
        now_ms=NOW + 1,
    )
    assert loaded.text == "never sealed"
    assert runtime.gateway.grant_unseals == 0


# -- the permission gate ------------------------------------------------


def test_without_may_unseal_the_statement_returns_and_the_body_does_not(
    runtime: Runtime,
) -> None:
    """Seeing a resolved claim and reading the raw transcript it came from are
    different disclosures, and the body is the one the enclave exists for."""
    ref = _seal_and_store(runtime, BODY)

    loaded = load_body(
        runtime,
        OWNER,
        _event(ref),
        scope=_scope(may_unseal=False),
        grant_token=TOKEN,
        now_ms=NOW + 1,
    )

    assert loaded.text is None
    assert loaded.unavailable == NOT_PERMITTED
    assert loaded.reason == "unseal_not_permitted"
    assert runtime.gateway.grant_unseals == 0, "nothing should have been decrypted"


def test_may_unseal_does_not_bypass_the_read_check(runtime: Runtime) -> None:
    """An object the grant cannot see stays unseen, and says so with the read
    check's own reason rather than an unseal reason."""
    ref = _seal_and_store(runtime, BODY)

    loaded = load_body(
        runtime,
        OWNER,
        _event(ref),
        scope=_scope(sources=["github"]),
        grant_token=TOKEN,
        now_ms=NOW + 1,
    )

    assert loaded.unavailable == NOT_PERMITTED
    assert loaded.reason == "source_not_in_scope"
    assert runtime.gateway.grant_unseals == 0


def test_a_scope_without_its_token_cannot_unseal(runtime: Runtime) -> None:
    """The gateway authorises the decrypt against the grant itself, so a caller
    holding only a scope has no credential to present."""
    ref = _seal_and_store(runtime, BODY)
    with pytest.raises(ValueError, match="cannot unseal"):
        load_body(runtime, OWNER, _event(ref), scope=_scope(), now_ms=NOW + 1)


# -- the two failures that must stay apart ------------------------------


def test_a_missing_blob_is_not_stored_rather_than_an_error(runtime: Runtime) -> None:
    """A missing blob is an ordinary fact about an old ingest and must not fail a
    read that was otherwise permitted."""
    ref = EncryptedContentRef(
        key_id="test-key",
        scheme="XOR_TEST",
        blob_id="quilt-that-was-never-written",
        patch_id="a" * 64,
        byte_len=10,
    )
    loaded = load_body(
        runtime, OWNER, _event(ref), scope=_scope(), grant_token=TOKEN, now_ms=NOW + 1
    )
    assert loaded.unavailable == NOT_STORED
    assert loaded.text is None


def test_no_ref_at_all_says_so(runtime: Runtime) -> None:
    loaded = load_body(
        runtime, OWNER, _event(None), scope=_scope(), grant_token=TOKEN, now_ms=NOW + 1
    )
    assert loaded.unavailable == NO_REF


def test_walrus_raises_rather_than_reporting_no_body(runtime: Runtime) -> None:
    """The distinction that matters most. A deployment pointed at Walrus cannot
    read a body sealed to local disk -- and reporting that as "no body" would
    make a confidentiality design look like an empty record.

    The stub raising rather than returning `None` is what makes the two
    distinguishable, so that is asserted directly too.
    """
    walrus = WalrusQuiltStore(publisher_url="https://walrus.invalid", aggregator_url=None)
    with pytest.raises(NotImplementedError):
        walrus.get(OWNER, BlobRef("q", "p", 1, walrus.backend))

    runtime.blobs = walrus
    ref = EncryptedContentRef(
        key_id="test-key", scheme="XOR_TEST", blob_id="q", patch_id="p", byte_len=1
    )
    loaded = load_body(
        runtime, OWNER, _event(ref), scope=_scope(), grant_token=TOKEN, now_ms=NOW + 1
    )

    assert loaded.unavailable == BACKEND_NOT_WIRED
    assert loaded.unavailable != NOT_STORED
    assert loaded.reason, "the reason has to say which backend is not wired"


def test_a_body_never_crosses_owners(runtime: Runtime, settings: Settings) -> None:
    """The blob store governs *bytes* while the permission layer governs
    *objects*, and collapsing them would mean one bug reaches both."""
    ref = _seal_and_store(runtime, BODY)
    other = LocalQuiltStore(settings.blob_store_dir)

    assert other.get("someone-else", ref_from_encrypted_content(ref, other.backend)) is None
