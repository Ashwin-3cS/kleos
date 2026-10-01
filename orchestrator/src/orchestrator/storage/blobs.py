"""Where sealed ciphertext goes.

``EncryptedContentRef.blob_id`` has existed since the schema was written and
has always been ``None``, because nothing stored the bytes it was meant to
point at. The ingestion graph sealed a sensitive body in the enclave, carried
the ciphertext in LangGraph state, wrote the *reference* to Neo4j, set
``event.body = None``, and then dropped the ciphertext when the run ended.
The reference pointed at nothing. Sealing a record destroyed it.

This module is the missing half: a content-addressed blob store with the
shape Walrus has, so ``blob_id`` is populated from the first write and Walrus
becomes a second implementation rather than a migration. See ADR 0002.

Two properties the interface exists to enforce:

- **Content-addressed.** The id is derived from the ciphertext, which is what
  Walrus does, and means a re-ingest of unchanged material is idempotent
  rather than accumulating duplicate blobs.
- **Owner-partitioned.** ``get`` takes the owner id and will not return
  another owner's blob even when handed a correct id. The permission layer
  decides who may read an *object*; this decides who may read *bytes*, and
  the two must not be the same check in two places.

Nothing here can read what it stores. The plaintext exists only inside the
enclave, so recovering a body means ``POST /seal/decrypt`` -- which the
gateway does not yet expose (see `gateway/src/store/mod.rs`). Persisting the
ciphertext is what makes that route worth adding; until it exists the bytes
are durable and unreadable, which is the correct order to build these two in.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from pathlib import Path
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)

#: Length of the hex blob id. Full blake2b-256 is 64 chars; a sealed blob's
#: id is not a secret and collisions are the only risk, so the full digest
#: is kept rather than truncated.
_ID_BYTES = 32


def blob_id_for(ciphertext: bytes) -> str:
    """The content address of a ciphertext.

    Derived from the sealed bytes, not the plaintext: this code never sees a
    plaintext, and hashing one would leak equality of raw content to whoever
    can read blob ids.
    """
    return hashlib.blake2b(ciphertext, digest_size=_ID_BYTES).hexdigest()


@runtime_checkable
class BlobStore(Protocol):
    """Durable storage for bytes that are already encrypted."""

    #: Recorded on the ref so a reader knows which store to ask.
    backend: str

    def put(self, owner_id: str, ciphertext: bytes) -> str:
        """Stores ``ciphertext`` and returns its blob id. Idempotent."""
        ...

    def get(self, owner_id: str, blob_id: str) -> bytes | None:
        """The stored ciphertext, or ``None``. Never crosses owners."""
        ...


class LocalBlobStore:
    """Files under one directory, partitioned by owner.

    The local stand-in for Walrus, and deliberately the dullest thing that
    satisfies the interface: one file per blob, named by its content address,
    under a per-owner directory. No index, no metadata, nothing to keep in
    step with Neo4j -- a blob is reachable iff some ref names it, and an
    orphan costs disk and nothing else.

    Writes go through a temporary file in the same directory and are renamed
    into place, so a crash mid-write cannot leave a short file sitting at an
    id that claims to address content it does not hold.
    """

    backend = "local"

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    def _dir_for(self, owner_id: str) -> Path:
        # Owner ids are hex (see `derive_owner_id` in the enclave), but this
        # builds a path, so it is hashed rather than trusted: a traversal
        # here would let one owner's id address another's directory.
        safe = hashlib.blake2b(owner_id.encode(), digest_size=16).hexdigest()
        return self._root / safe

    def put(self, owner_id: str, ciphertext: bytes) -> str:
        blob_id = blob_id_for(ciphertext)
        directory = self._dir_for(owner_id)
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / blob_id
        if target.exists():
            return blob_id
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(ciphertext)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return blob_id

    def get(self, owner_id: str, blob_id: str) -> bytes | None:
        if blob_id != Path(blob_id).name or not blob_id:
            # A blob id is a bare hex name. Anything with a separator in it is
            # an attempt to leave the owner's directory, not a typo.
            raise ValueError(f"illegal blob id {blob_id!r}")
        path = self._dir_for(owner_id) / blob_id
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None


class WalrusBlobStore:
    """The eventual store: encrypted blobs on Walrus under the owner's keys.

    Still a stub, and now a stub with a caller. It raises rather than
    silently falling back to local storage: a deployment that believes it is
    writing to Walrus and is actually writing to the orchestrator's disk has
    a confidentiality bug, not a performance one.
    """

    backend = "walrus"

    def __init__(self, publisher_url: str | None, aggregator_url: str | None) -> None:
        self._publisher_url = publisher_url
        self._aggregator_url = aggregator_url

    def put(self, owner_id: str, ciphertext: bytes) -> str:
        raise NotImplementedError(
            "Walrus writes are not wired yet: needs a publisher endpoint reachable through "
            "the enclave's VSOCK tunnel (port 8004) and an owner-held key policy"
        )

    def get(self, owner_id: str, blob_id: str) -> bytes | None:
        raise NotImplementedError(
            "Walrus reads are not wired yet: needs an aggregator endpoint reachable through "
            "the enclave's VSOCK tunnel (port 8004)"
        )


def get_blob_store(settings) -> BlobStore:
    """Picks the blob store from configuration.

    Walrus when its endpoints are configured, local otherwise. There is no
    "try Walrus and fall back", for the reason in ``WalrusBlobStore``.
    """
    if settings.walrus_publisher_url:
        return WalrusBlobStore(settings.walrus_publisher_url, settings.walrus_aggregator_url)
    return LocalBlobStore(settings.blob_store_dir)
