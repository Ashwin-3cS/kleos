"""What ingestion stores, and what it says it stored.

Two properties, both previously wrong:

**A sealed body is persisted.** The ciphertext goes to the blob store and the
stored ``EncryptedContentRef`` names it, so a sensitive record survives
ingestion. Before ADR 0002 the ref was written with ``blob_id = None`` and the
bytes were dropped when the graph run ended -- sealing a record destroyed it.

**The report counts writes, not candidates.** A run that skips an event
because its body could not be sealed must not report that event as stored.
The one number an ingestion report exists to give is how much landed.
"""

from __future__ import annotations

import pytest

from orchestrator.gateway_client import GatewayError, SealedContent
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.schema import EncryptedContentRef, Event

OWNER = "owner-accounting"
_MARKER = b"FAKE_SEAL_V1:"


class _FakeSealGateway:
    """Stands in for the gateway's enclave round trip.

    The real path is covered by ``scripts/orchestrator_smoke.sh`` with the Rust
    stack running. What is under test here is what the *orchestrator* does with
    what comes back, which needs no enclave -- and faking it is what lets the
    success path be tested at all, since this suite has no gateway.
    """

    def __init__(self) -> None:
        #: ciphertext -> the plaintext it was made from
        self.sealed: dict[bytes, bytes] = {}

    def adopt_session(self, token: str) -> None:
        pass

    def seal_encrypt(self, plaintext: bytes) -> SealedContent:
        ciphertext = _MARKER + plaintext[::-1]
        self.sealed[ciphertext] = plaintext
        return SealedContent(
            ciphertext=ciphertext,
            ref=EncryptedContentRef(
                key_id="fake-key",
                scheme="FAKE_SEAL_V1",
                blob_id=None,
                byte_len=len(ciphertext),
            ),
            attestation="FAKE_ATTESTATION",
        )

    def close(self) -> None:
        pass


class _BrokenSealGateway(_FakeSealGateway):
    def seal_encrypt(self, plaintext: bytes) -> SealedContent:
        raise GatewayError("gateway 503: enclave unreachable")


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(settings)
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.close()


def _stored_events(runtime: Runtime) -> list[Event]:
    rows = runtime.store._run(
        "MATCH (n:Event {owner_id: $owner_id}) RETURN n.id AS id", owner_id=OWNER
    )
    nodes = runtime.store.get_many(OWNER, [row["id"] for row in rows])
    return [n.node for n in nodes if isinstance(n.node, Event)]


def _sealed_events(runtime: Runtime) -> list[Event]:
    return [e for e in _stored_events(runtime) if e.encrypted_content is not None]


def test_a_sealed_body_is_persisted_and_recoverable(runtime: Runtime) -> None:
    gateway = _FakeSealGateway()
    runtime.gateway = gateway

    result = run_ingestion(runtime, OWNER, source="mock", thread_id="blob-success")

    assert result.sealed >= 1, "the mock fixtures include a sensitive record"
    assert result.skipped == 0
    assert not result.errors

    sealed = _sealed_events(runtime)
    assert sealed, "a sensitive record should have produced a sealed event"

    for event in sealed:
        ref = event.encrypted_content
        assert event.body is None, "a sealed body must not also be stored in the clear"
        assert ref.blob_id, "the ref must name the blob holding its bytes"

        stored_bytes = runtime.blobs.get(OWNER, ref.blob_id)
        assert stored_bytes is not None, "the bytes the ref points at must exist"
        assert stored_bytes in gateway.sealed, "must be exactly what the enclave returned"
        assert ref.byte_len == len(stored_bytes)


def test_the_persisted_bytes_are_ciphertext_not_plaintext(runtime: Runtime) -> None:
    """The point of the whole round trip. A blob holding readable source text
    would make the seal path theatre."""
    gateway = _FakeSealGateway()
    runtime.gateway = gateway
    run_ingestion(runtime, OWNER, source="mock", thread_id="blob-opaque")

    for event in _sealed_events(runtime):
        stored_bytes = runtime.blobs.get(OWNER, event.encrypted_content.blob_id)
        plaintext = gateway.sealed[stored_bytes]
        assert stored_bytes.startswith(_MARKER)
        assert plaintext not in stored_bytes
        assert plaintext.decode() not in (event.summary or "")


def test_a_blob_is_not_readable_by_another_owner(runtime: Runtime) -> None:
    runtime.gateway = _FakeSealGateway()
    run_ingestion(runtime, OWNER, source="mock", thread_id="blob-owner")

    for event in _sealed_events(runtime):
        blob_id = event.encrypted_content.blob_id
        assert runtime.blobs.get(OWNER, blob_id) is not None
        assert runtime.blobs.get("owner-someone-else", blob_id) is None


def test_an_unsealed_sensitive_event_is_skipped_and_reported_as_skipped(
    runtime: Runtime,
) -> None:
    """The regression this test exists for: the report counted candidates, so a
    run that stored six events reported seven."""
    runtime.gateway = _BrokenSealGateway()

    result = run_ingestion(runtime, OWNER, source="mock", thread_id="seal-failure")

    assert result.skipped >= 1
    assert any("not sealed" in e for e in result.errors)
    _assert_counts_match_store(runtime, result)


def test_a_blob_store_failure_skips_rather_than_storing_a_dangling_ref(
    runtime: Runtime, monkeypatch
) -> None:
    """Same rule as a failed seal, one step later. A ref whose bytes were never
    written is worse than a missing event: it reads as recoverable."""
    runtime.gateway = _FakeSealGateway()

    def boom(owner_id: str, ciphertext: bytes) -> str:
        raise OSError("no space left on device")

    monkeypatch.setattr(runtime.blobs, "put", boom)

    result = run_ingestion(runtime, OWNER, source="mock", thread_id="blob-store-failure")

    assert result.skipped >= 1
    assert any("not persisted" in e for e in result.errors)
    assert _sealed_events(runtime) == [], "no event may point at bytes that were never stored"
    _assert_counts_match_store(runtime, result)


def test_counts_match_the_store_on_a_clean_run(runtime: Runtime) -> None:
    runtime.gateway = _FakeSealGateway()
    result = run_ingestion(runtime, OWNER, source="mock", thread_id="counts-clean")
    assert result.skipped == 0
    _assert_counts_match_store(runtime, result)


def _assert_counts_match_store(runtime: Runtime, result) -> None:
    stored = runtime.store.count(OWNER)
    assert (result.entities, result.events, result.claims) == (
        stored.get("Entity", 0),
        stored.get("Event", 0),
        stored.get("Claim", 0),
    ), "the reported counts must equal what is actually in the store"
