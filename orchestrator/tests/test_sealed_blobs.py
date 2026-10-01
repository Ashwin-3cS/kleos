"""Sealing a record must not destroy it.

Before ADR 0002, ingesting a sensitive record sealed the body in the enclave,
wrote an ``EncryptedContentRef`` with ``blob_id = None``, cleared
``event.body``, and dropped the ciphertext when the graph run ended. The event
survived; its content did not, and nothing in the stored object said so.

These tests hold the property that fixes it: after ingestion, a sensitive
event's ref names a blob, and that blob contains exactly the bytes the enclave
returned.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.storage.blobs import LocalBlobStore, WalrusBlobStore, blob_id_for, get_blob_store


@pytest.fixture
def blobs(tmp_path) -> LocalBlobStore:
    return LocalBlobStore(tmp_path / "blobs")


def test_put_returns_a_content_address(blobs: LocalBlobStore) -> None:
    ciphertext = b"MOCK_SEAL_V1:not-really-encrypted"
    assert blobs.put("owner-1", ciphertext) == blob_id_for(ciphertext)


def test_round_trips_the_exact_bytes(blobs: LocalBlobStore) -> None:
    ciphertext = bytes(range(256)) * 8
    blob_id = blobs.put("owner-1", ciphertext)
    assert blobs.get("owner-1", blob_id) == ciphertext


def test_put_is_idempotent(blobs: LocalBlobStore) -> None:
    """Re-ingesting unchanged material must not accumulate blobs.

    Content addressing is what gives this for free, and it is the reason the
    id is derived rather than random: a backfill that overlaps a previous one
    would otherwise grow the store without bound.
    """
    ciphertext = b"same bytes"
    first = blobs.put("owner-1", ciphertext)
    second = blobs.put("owner-1", ciphertext)
    assert first == second
    root = blobs.get("owner-1", first)
    assert root == ciphertext


def test_a_blob_id_does_not_cross_owners(blobs: LocalBlobStore) -> None:
    """The id is public and derived from content, so two owners who store the
    same bytes get the same id. That must not make either readable to the
    other: bytes are partitioned by owner, independently of the ACL layer that
    governs objects."""
    ciphertext = b"identical content, two owners"
    blob_id = blobs.put("owner-1", ciphertext)
    assert blobs.put("owner-2", ciphertext) == blob_id

    assert blobs.get("owner-1", blob_id) == ciphertext
    assert blobs.get("owner-3", blob_id) is None


def test_a_blob_id_cannot_escape_its_directory(blobs: LocalBlobStore) -> None:
    blobs.put("owner-1", b"x")
    for bad in ["../x", "a/b", "/etc/passwd", ""]:
        with pytest.raises(ValueError):
            blobs.get("owner-1", bad)


def test_a_missing_blob_is_none_not_an_error(blobs: LocalBlobStore) -> None:
    assert blobs.get("owner-1", blob_id_for(b"never stored")) is None


def test_no_partial_blob_is_left_at_a_valid_id(tmp_path, monkeypatch) -> None:
    """A crash mid-write must not leave a short file sitting at an id that
    claims to address content it does not hold -- that would be a silent
    corruption discovered only when someone tried to decrypt it."""
    blobs = LocalBlobStore(tmp_path / "blobs")

    import os as os_module

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os_module, "replace", boom)
    with pytest.raises(OSError):
        blobs.put("owner-1", b"content that never lands")

    assert blobs.get("owner-1", blob_id_for(b"content that never lands")) is None
    # And no temporary file is left behind either.
    directory = blobs._dir_for("owner-1")
    assert list(directory.iterdir()) == []


def test_walrus_raises_rather_than_falling_back() -> None:
    """A deployment that thinks it writes to Walrus and actually writes to
    local disk has a confidentiality bug. Failing loudly is the point."""
    store = WalrusBlobStore("https://publisher.example", "https://aggregator.example")
    with pytest.raises(NotImplementedError, match="Walrus"):
        store.put("owner-1", b"x")
    with pytest.raises(NotImplementedError, match="Walrus"):
        store.get("owner-1", "abc")


def test_configuration_picks_walrus_when_it_is_set(tmp_path) -> None:
    local = Settings(blob_store_dir=str(tmp_path))
    assert get_blob_store(local).backend == "local"

    walrus = Settings(
        blob_store_dir=str(tmp_path), walrus_publisher_url="https://publisher.example"
    )
    assert get_blob_store(walrus).backend == "walrus"
