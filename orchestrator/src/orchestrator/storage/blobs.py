"""Where sealed ciphertext goes: batched, as Quilt patches.

``EncryptedContentRef.blob_id`` existed from the first schema and was always
``None``, because nothing stored the bytes it pointed at -- the ingestion graph
sealed a body, wrote the *reference*, cleared ``event.body`` and dropped the
ciphertext when the run ended. ADR 0002 fixed that with a content-addressed
store. This module is its second shape, and the shape matters: see ADR 0008.

**Why batching is the right primitive, not an optimisation.** A sealed record
body is a ChatGPT transcript, an email, a calendar entry -- kilobytes, and
thousands of them per backfill. One blob per record is precisely the pathology
Quilt exists for: Walrus charges encoding overhead per blob, and batching cuts it
by roughly 106x at 100KB and 420x at 10KB. At our object size that is the
difference between a viable store and a bill proportional to how carefully a
person uses their own memory. So the interface is batch-first, and a single
``put`` is the special case rather than the other way round.

**What a Quilt gives us.** Up to ~660 patches share one container. Each patch is
addressable and readable *without* fetching the rest, which is what makes
batching safe here: a grant that permits one event must not require downloading
the bodies of 659 others to satisfy it. Hence two ids on the ref --
``blob_id`` for the Quilt, ``patch_id`` for the body inside it.

**What a Quilt must not carry.** Walrus supports immutable, native per-patch
metadata -- tags, meant for picking an item out of a batch without reading it.
We write none. The tags are plaintext on a public store and immutable, so a tag
saying what a sealed transcript is *about* would publish, permanently, a
searchable index over the emotional and medical shape of someone's life, next to
the ciphertext that was the whole point. Tagging is exactly the feature a
privacy-first system has to decline. Our own index (Neo4j, under an
``ObjectAcl``) maps event to Quilt and patch, so nothing is lost: retrieval is
permissioned and revocable, and the public store learns only that some bytes
exist. See ``storage/affect.py`` for the metadata that would otherwise have gone
into those tags.

Two properties the interface still enforces, unchanged from ADR 0002:

- **Content-addressed.** A patch id is derived from its ciphertext, so
  re-ingesting unchanged material is idempotent instead of accumulating copies.
  Derived from the sealed bytes and never the plaintext, since hashing a
  plaintext would leak equality of raw content to anyone who can read ids.
- **Owner-partitioned.** ``get`` takes an owner id and will not return another
  owner's bytes even when handed correct ids. The permission layer governs
  *objects*; this governs *bytes*, and collapsing them would mean one bug
  reaches both.

Nothing here can read what it stores *as plaintext*: ``get`` returns the sealed
bytes, and turning those back into a body goes through the enclave. That path is
now assembled -- ``ref_from_encrypted_content`` below converts what a stored
event carries into what ``get`` takes, and ``storage/bodies.py`` joins it to the
gateway's unseal route. It was missing for a while, and only this one function
was missing: both ends existed and nothing converted between them, so a sealed
body was durable and unreadable behind a ref that read as recoverable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)

#: Full blake2b-256, not truncated: a patch id is not a secret, and collision is
#: the only risk worth spending bytes on.
_ID_BYTES = 32

#: Patches per Quilt. Walrus caps a Quilt at roughly 660 files; a batch larger
#: than this is split across several Quilts rather than rejected, because the
#: caller is a backfill and has no useful way to honour the limit itself.
MAX_PATCHES_PER_QUILT = 660


def patch_id_for(ciphertext: bytes) -> str:
    """The content address of one sealed body."""
    return hashlib.blake2b(ciphertext, digest_size=_ID_BYTES).hexdigest()


@dataclass(frozen=True, slots=True)
class BlobRef:
    """Where one sealed body lives.

    ``patch_id`` is ``None`` only for a store that does not batch. Both ids are
    opaque and neither says anything about the content -- that is the point of
    keeping the metadata elsewhere.
    """

    blob_id: str
    patch_id: str | None
    byte_len: int
    backend: str


@runtime_checkable
class BlobStore(Protocol):
    """Durable storage for bytes that are already encrypted."""

    #: Recorded so a reader knows which store to ask.
    backend: str

    def put_batch(self, owner_id: str, ciphertexts: list[bytes]) -> list[BlobRef]:
        """Stores a batch as one or more Quilts. Order-preserving, idempotent."""
        ...

    def put(self, owner_id: str, ciphertext: bytes) -> BlobRef:
        """One body. A batch of one; kept because callers read better for it."""
        ...

    def get(self, owner_id: str, ref: BlobRef) -> bytes | None:
        """The stored ciphertext, or ``None``. Never crosses owners."""
        ...


def ref_from_encrypted_content(ref, backend: str) -> BlobRef:
    """Addresses the stored patch an ``EncryptedContentRef`` points at.

    The missing piece, and it was only ever this small: both ends existed --
    ``EncryptedContentRef`` is what a stored event carries, ``BlobRef`` is what
    ``get`` takes -- and nothing converted between them, so ``get`` had no
    callers and a sealed body was durable and unreadable.

    ``backend`` comes from the configured store rather than from the ref.
    Deliberately not a field on ``EncryptedContentRef``: that would trip the
    schema parity test, change the enclave's measurement, and alter the shape
    `Scope` is being kept in for an on-chain grant object -- all for a
    *deployment* fact. Where this deployment put the bytes is not a property of
    the body.

    The consequence, stated rather than hidden: a body written to local disk and
    later read with Walrus configured is unreadable, because the configured store
    is the one that will be asked. That is the right direction -- ADR 0002 and
    0008 refuse a silent fall back to local disk -- but it has to surface as
    "this backend is not wired" and never as "there is no body".
    """
    if ref.blob_id is None:
        raise ValueError(
            "this ref has no blob id: it predates ADR 0002, when sealing a record "
            "destroyed it. There is nothing stored to read."
        )
    return BlobRef(
        blob_id=ref.blob_id,
        patch_id=ref.patch_id,
        byte_len=ref.byte_len,
        backend=backend,
    )


def _quilt_id_for(owner_id: str, patch_ids: list[str]) -> str:
    """A deterministic container id for a set of patches.

    Content-addressed like the patches, over the *set* of patch ids, so
    re-ingesting an identical batch lands in the same Quilt instead of creating
    a second one holding the same bodies. Walrus will assign its own id; this is
    the local stand-in, and the ref records whichever one applies.
    """
    digest = hashlib.blake2b(digest_size=16)
    digest.update(owner_id.encode())
    for patch in sorted(patch_ids):
        digest.update(patch.encode())
    return digest.hexdigest()


class LocalQuiltStore:
    """Quilts as directories, patches as files inside them.

    The local stand-in for Walrus, deliberately the dullest thing that has the
    same *shape*: a batch becomes one container, each body is independently
    addressable within it, and nothing but ciphertext is written. Keeping the
    shape is the whole point -- when the Walrus implementation lands, the
    ingestion graph and the schema do not change.

    Writes go through a temp file renamed into place, so a crash cannot leave a
    short file at an id that claims to address content it does not hold.
    """

    backend = "local-quilt"

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    def _owner_dir(self, owner_id: str) -> Path:
        # Owner ids are hex, but this builds a path, so it is hashed rather than
        # trusted: a traversal here would let one owner's id address another's
        # directory.
        safe = hashlib.blake2b(owner_id.encode(), digest_size=16).hexdigest()
        return self._root / safe

    def _quilt_dir(self, owner_id: str, quilt_id: str) -> Path:
        if quilt_id != Path(quilt_id).name or not quilt_id:
            raise ValueError(f"illegal quilt id {quilt_id!r}")
        return self._owner_dir(owner_id) / quilt_id

    def put_batch(self, owner_id: str, ciphertexts: list[bytes]) -> list[BlobRef]:
        if not ciphertexts:
            return []
        refs: list[BlobRef] = []
        for start in range(0, len(ciphertexts), MAX_PATCHES_PER_QUILT):
            chunk = ciphertexts[start : start + MAX_PATCHES_PER_QUILT]
            refs.extend(self._put_one_quilt(owner_id, chunk))
        return refs

    def _put_one_quilt(self, owner_id: str, chunk: list[bytes]) -> list[BlobRef]:
        patch_ids = [patch_id_for(c) for c in chunk]
        quilt_id = _quilt_id_for(owner_id, patch_ids)
        directory = self._quilt_dir(owner_id, quilt_id)
        directory.mkdir(parents=True, exist_ok=True)

        # A manifest, so a Quilt can be enumerated without a separate index.
        # Patch ids only -- no tags, no sizes keyed to anything meaningful, and
        # nothing about the content. See the module docstring.
        self._write_atomic(directory / "quilt.json", json.dumps({"patches": patch_ids}).encode())

        for ciphertext, patch in zip(chunk, patch_ids, strict=True):
            target = directory / patch
            if not target.exists():
                self._write_atomic(target, ciphertext)

        log.info("blobs.put_batch quilt=%s patches=%d", quilt_id[:12], len(patch_ids))
        return [
            BlobRef(
                blob_id=quilt_id,
                patch_id=patch,
                byte_len=len(ciphertext),
                backend=self.backend,
            )
            for ciphertext, patch in zip(chunk, patch_ids, strict=True)
        ]

    def put(self, owner_id: str, ciphertext: bytes) -> BlobRef:
        return self.put_batch(owner_id, [ciphertext])[0]

    def get(self, owner_id: str, ref: BlobRef) -> bytes | None:
        if ref.patch_id is None:
            raise ValueError("a local-quilt ref always has a patch id")
        if ref.patch_id != Path(ref.patch_id).name or not ref.patch_id:
            # A patch id is a bare hex name. A separator in it is an attempt to
            # leave the owner's directory, not a typo.
            raise ValueError(f"illegal patch id {ref.patch_id!r}")
        path = self._quilt_dir(owner_id, ref.blob_id) / ref.patch_id
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def patches_in(self, owner_id: str, quilt_id: str) -> list[str]:
        """Patch ids in one Quilt, from its manifest. For tests and repair."""
        try:
            raw = (self._quilt_dir(owner_id, quilt_id) / "quilt.json").read_bytes()
        except FileNotFoundError:
            return []
        return list(json.loads(raw)["patches"])

    @staticmethod
    def _write_atomic(target: Path, payload: bytes) -> None:
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


class WalrusQuiltStore:
    """The eventual store: sealed bodies as Quilt patches on Walrus.

    Still a stub, and now a stub with the right signature and an explicit
    policy. It raises rather than falling back to local disk: a deployment that
    believes it writes to Walrus and is actually writing to the orchestrator's
    disk has a confidentiality bug, not a performance one.

    When this is implemented, two things are non-negotiable. It writes **no
    Walrus-native tags** -- they are immutable plaintext on a public store, so a
    tag describing what a sealed body is about would permanently publish the
    shape of someone's private life beside the ciphertext hiding it. And it
    batches, because per-blob encoding overhead is what Quilt exists to remove
    and our objects are small enough for that to dominate the bill.
    """

    backend = "walrus-quilt"

    def __init__(self, publisher_url: str | None, aggregator_url: str | None) -> None:
        self._publisher_url = publisher_url
        self._aggregator_url = aggregator_url

    def put_batch(self, owner_id: str, ciphertexts: list[bytes]) -> list[BlobRef]:
        raise NotImplementedError(
            "Walrus Quilt writes are not wired yet: needs a publisher reachable through the "
            "enclave's VSOCK tunnel (port 8004), an owner-held key policy, and a store epoch "
            f"to pay for ({len(ciphertexts)} patches pending)"
        )

    def put(self, owner_id: str, ciphertext: bytes) -> BlobRef:
        return self.put_batch(owner_id, [ciphertext])[0]

    def get(self, owner_id: str, ref: BlobRef) -> bytes | None:
        raise NotImplementedError(
            "Walrus Quilt reads are not wired yet: needs an aggregator reachable through the "
            "enclave's VSOCK tunnel (port 8004). A patch is readable without fetching its "
            "Quilt, which is what keeps a single-object read from downloading 659 others"
        )


def get_blob_store(settings) -> BlobStore:
    """Picks the store from configuration.

    Walrus when its endpoints are set, local otherwise. There is deliberately no
    "try Walrus and fall back", for the reason in ``WalrusQuiltStore``.
    """
    if settings.walrus_publisher_url:
        return WalrusQuiltStore(settings.walrus_publisher_url, settings.walrus_aggregator_url)
    return LocalQuiltStore(settings.blob_store_dir)
