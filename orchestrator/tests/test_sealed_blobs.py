"""Sealing a record must not destroy it, and batching must not widen it.

Before ADR 0002, ingesting a sensitive record sealed the body in the enclave,
wrote an ``EncryptedContentRef`` with ``blob_id = None``, cleared ``event.body``,
and dropped the ciphertext when the graph run ended. The event survived; its
content did not, and nothing in the stored object said so.

ADR 0008 then made the store batch-first, because a sealed body is a few
kilobytes and per-blob encoding overhead dominates at that size. These tests hold
both properties: the bytes come back, and batching them together does not make
one owner's body reachable through another's ids.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.storage.blobs import (
    MAX_PATCHES_PER_QUILT,
    BlobRef,
    LocalQuiltStore,
    WalrusQuiltStore,
    get_blob_store,
    patch_id_for,
)


@pytest.fixture
def blobs(tmp_path) -> LocalQuiltStore:
    return LocalQuiltStore(tmp_path / "blobs")


def test_a_patch_id_is_the_content_address(blobs: LocalQuiltStore) -> None:
    ciphertext = b"MOCK_SEAL_V1:not-really-encrypted"
    ref = blobs.put("owner-1", ciphertext)
    assert ref.patch_id == patch_id_for(ciphertext)
    assert ref.byte_len == len(ciphertext)
    assert ref.backend == "local-quilt"


def test_round_trips_the_exact_bytes(blobs: LocalQuiltStore) -> None:
    ciphertext = bytes(range(256)) * 8
    ref = blobs.put("owner-1", ciphertext)
    assert blobs.get("owner-1", ref) == ciphertext


def test_a_batch_shares_one_quilt(blobs: LocalQuiltStore) -> None:
    """The reason the interface is batch-first. One container for the run, not
    one per body."""
    bodies = [f"MOCK_SEAL_V1:body-{i}".encode() for i in range(12)]
    refs = blobs.put_batch("owner-1", bodies)

    assert len(refs) == len(bodies)
    assert len({ref.blob_id for ref in refs}) == 1, "a small batch is a single Quilt"
    assert len({ref.patch_id for ref in refs}) == len(bodies), "each body addressable"


def test_order_is_preserved(blobs: LocalQuiltStore) -> None:
    """The caller zips refs back against its own list of records, so a reordered
    return would attach each body's ref to the wrong event."""
    bodies = [f"body-{i}".encode() for i in range(20)]
    refs = blobs.put_batch("owner-1", bodies)
    for body, ref in zip(bodies, refs, strict=True):
        assert blobs.get("owner-1", ref) == body


def test_each_patch_reads_without_fetching_the_others(blobs: LocalQuiltStore) -> None:
    """What makes batching safe here: a grant that permits one event must not
    require pulling the bodies of everything batched beside it."""
    bodies = [f"body-{i}".encode() for i in range(5)]
    refs = blobs.put_batch("owner-1", bodies)
    assert blobs.get("owner-1", refs[3]) == bodies[3]


def test_a_batch_over_the_quilt_limit_is_split(blobs: LocalQuiltStore) -> None:
    """A Quilt caps at ~660 patches. A backfill has no useful way to honour that
    itself, so the store splits rather than rejecting."""
    bodies = [f"body-{i}".encode() for i in range(MAX_PATCHES_PER_QUILT + 5)]
    refs = blobs.put_batch("owner-1", bodies)

    assert len(refs) == len(bodies)
    assert len({ref.blob_id for ref in refs}) == 2
    assert blobs.get("owner-1", refs[-1]) == bodies[-1]


def test_put_batch_is_idempotent(blobs: LocalQuiltStore) -> None:
    """Re-ingesting unchanged material must not accumulate copies. Content
    addressing gives this for free, which is why ids are derived rather than
    random -- a backfill overlaps previous backfills by design."""
    bodies = [b"same-a", b"same-b"]
    first = blobs.put_batch("owner-1", bodies)
    second = blobs.put_batch("owner-1", bodies)
    assert [r.blob_id for r in first] == [r.blob_id for r in second]
    assert [r.patch_id for r in first] == [r.patch_id for r in second]
    assert blobs.patches_in("owner-1", first[0].blob_id) == [r.patch_id for r in first]


def test_an_empty_batch_writes_nothing(blobs: LocalQuiltStore) -> None:
    assert blobs.put_batch("owner-1", []) == []


def test_two_owners_never_share_a_quilt(blobs: LocalQuiltStore) -> None:
    """Patch ids are content addresses, so two owners storing identical bytes get
    the same patch id. Their *containers* must still differ.

    Co-locating two people's bodies in one Quilt would be a correlation leak
    independent of encryption: patches in a Quilt are stored and fetched
    together, so a Quilt holding both is public evidence that those two sets of
    bytes belong together. Hence the owner is mixed into the container id.
    """
    ciphertext = b"identical content, two owners"
    mine = blobs.put("owner-1", ciphertext)
    theirs = blobs.put("owner-2", ciphertext)

    assert mine.patch_id == theirs.patch_id, "same bytes, same content address"
    assert mine.blob_id != theirs.blob_id, "but never the same container"


def test_a_ref_does_not_cross_owners(blobs: LocalQuiltStore) -> None:
    """The partition is a separate check from ``permits()``: that one governs
    objects, this one governs bytes, and collapsing them would mean one bug
    reaches both."""
    ciphertext = b"a sealed body"
    mine = blobs.put("owner-1", ciphertext)

    assert blobs.get("owner-1", mine) == ciphertext
    assert blobs.get("owner-3", mine) is None


def test_ids_cannot_escape_their_directory(blobs: LocalQuiltStore) -> None:
    good = blobs.put("owner-1", b"x")
    for bad in ["../x", "a/b", "/etc/passwd", ""]:
        with pytest.raises(ValueError):
            blobs.get("owner-1", BlobRef(good.blob_id, bad, 1, "local-quilt"))
        with pytest.raises(ValueError):
            blobs.get("owner-1", BlobRef(bad, good.patch_id, 1, "local-quilt"))


def test_a_missing_patch_is_none_not_an_error(blobs: LocalQuiltStore) -> None:
    ref = BlobRef(blob_id="0" * 32, patch_id=patch_id_for(b"never stored"), byte_len=1,
                  backend="local-quilt")
    assert blobs.get("owner-1", ref) is None


def test_the_manifest_names_patches_and_nothing_else(blobs: LocalQuiltStore) -> None:
    """A Quilt is enumerable without a separate index, and the manifest carries
    patch ids only. Anything describing the *content* would defeat the point of
    keeping affect metadata out of the store entirely (ADR 0009)."""
    bodies = [b"alpha", b"beta"]
    refs = blobs.put_batch("owner-1", bodies)
    raw = (blobs._quilt_dir("owner-1", refs[0].blob_id) / "quilt.json").read_text()
    assert set(__import__("json").loads(raw)) == {"patches"}
    for body in bodies:
        assert body.decode() not in raw


def test_no_partial_patch_is_left_at_a_valid_id(tmp_path, monkeypatch) -> None:
    """A crash mid-write must not leave a short file at an id that claims to
    address content it does not hold -- a corruption found only by whoever later
    tried to decrypt it."""
    blobs = LocalQuiltStore(tmp_path / "blobs")
    import os as os_module

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os_module, "replace", boom)
    with pytest.raises(OSError):
        blobs.put("owner-1", b"content that never lands")

    assert not list(blobs._owner_dir("owner-1").rglob("*")) or all(
        not p.is_file() for p in blobs._owner_dir("owner-1").rglob("*")
    )


def test_walrus_raises_rather_than_falling_back() -> None:
    """A deployment that thinks it writes to Walrus and actually writes to local
    disk has a confidentiality bug. Failing loudly is the point."""
    store = WalrusQuiltStore("https://publisher.example", "https://aggregator.example")
    with pytest.raises(NotImplementedError, match="Walrus"):
        store.put("owner-1", b"x")
    with pytest.raises(NotImplementedError, match="Walrus"):
        store.put_batch("owner-1", [b"x", b"y"])
    with pytest.raises(NotImplementedError, match="Walrus"):
        store.get("owner-1", BlobRef("q", "p", 1, "walrus-quilt"))


def test_configuration_picks_walrus_when_it_is_set(tmp_path) -> None:
    local = Settings(blob_store_dir=str(tmp_path))
    assert get_blob_store(local).backend == "local-quilt"

    walrus = Settings(
        blob_store_dir=str(tmp_path), walrus_publisher_url="https://publisher.example"
    )
    assert get_blob_store(walrus).backend == "walrus-quilt"
