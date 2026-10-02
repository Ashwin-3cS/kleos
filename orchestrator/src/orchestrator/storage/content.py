"""Encrypting the resolved record's text at rest.

Until now the honest version of the confidentiality model was: sealed record
bodies and OAuth tokens are ciphertext, and the *derived* memory -- who you
talked to, what you decided, what changed -- is written to Neo4j in the clear.
That inverts the sensitivity: for most purposes the resolved record is the more
revealing artifact, and it was the one lying open.

This module closes the larger half of that gap. It separates two things the
README had been treating as one:

- **extraction reads plaintext**, which it must, to produce a record at all;
- **the record sits in plaintext**, which it need not.

Only the second is continuous. An adversary with database access, a stolen
backup, or a read-only replica reads everything, forever; an adversary who
has to catch a specific ingest job in flight has a far narrower window. Closing
the second without the first is most of the benefit for a fraction of the work.

## What is sealed, and what is not

Sealed: the fields that carry what someone said or decided -- an event's summary
and body, a claim's statement, an entity's name and aliases, a citation's quote.

Left in the clear: ids, owner ids, timestamps, labels, edge types, ACL fields,
claim status, commitment dates and entity references, and embeddings.

That split is chosen so the reads keep working. Three of the four read paths --
the supersession history, the citation chain, the neighbourhood walk -- are
purely structural: they traverse edges, statuses and timestamps, and they do not
need a single sealed byte to do their walk. Only ``/query`` needs content, and
keeping embeddings in the clear means even its ranking is unchanged. The one
thing that genuinely stops working is the full-text index, which nothing queried.

**Embeddings staying in the clear is a real residual.** Embedding inversion is a
practical attack, not a theoretical one, so an operator holding vectors holds a
lossy version of the text. This is stage 1: the operator goes from reading
sentences to reconstructing approximations of them. Stage 2 moves vector scoring
into the enclave and closes it; see ADR 0010.

## Why the key never leaves the enclave

The tempting shortcut is envelope encryption: ask the enclave for a data key,
keep it in the orchestrator for the run, encrypt locally. That would be one
round trip instead of hundreds -- and it would put a key that decrypts the whole
store into a process the operator controls, at which point the ciphertext is
decoration.

So every seal and unseal is a call through the gateway into the TEE. It is more
round trips, and the cost lands where it is affordable: ingestion is a background
job, and a *read* only ever unseals the objects that already passed the
permission check, which is at most ``top_k``. The decrypt budget is the
disclosure budget, which is the property worth paying for.

## The marker

A sealed field stays a ``str``, so nothing downstream changes shape. It is
self-labelling -- ``KSEAL1:<key_id>:<base64>`` -- in the same spirit as
``MOCK_SEAL_V1:`` and ``MOCK_ATTESTATION_``: if one of these ever reaches a user
interface or a log, it reads as obviously encrypted rather than as corrupt text.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from ..schema import Claim, Entity, Event, MemoryNode

log = logging.getLogger(__name__)

#: Version in the prefix so a future scheme change can coexist with stored data.
MARKER = "KSEAL1:"

#: Which fields carry content, per node type. The single place this is declared.
#: A field absent from here is a field stored in the clear, so adding one to the
#: schema means deciding which list it belongs in.
CONTENT_FIELDS: dict[type, tuple[str, ...]] = {
    Event: ("summary", "body"),
    Claim: ("statement",),
    Entity: ("name",),
}

#: Fields holding a list of strings, each sealed separately.
CONTENT_LIST_FIELDS: dict[type, tuple[str, ...]] = {
    Entity: ("aliases",),
}


def is_sealed(value: str | None) -> bool:
    return bool(value) and value.startswith(MARKER)


def pack(key_id: str, ciphertext: bytes) -> str:
    """A sealed field, as stored. ``key_id`` travels with it because unsealing
    needs it and the enclave is the only thing that can use it."""
    return f"{MARKER}{key_id}:{base64.b64encode(ciphertext).decode()}"


def unpack(value: str) -> tuple[str, bytes]:
    body = value[len(MARKER) :]
    key_id, _, payload = body.partition(":")
    if not key_id or not payload:
        raise ValueError("malformed sealed field")
    return key_id, base64.b64decode(payload)


class ContentCrypto:
    """Seals and unseals the content fields of stored objects.

    Takes a gateway client rather than a key, because there is no key on this
    side of the boundary to take.
    """

    def __init__(self, gateway) -> None:
        self._gateway = gateway

    # -- sealing ---------------------------------------------------------

    def seal_node(self, node: MemoryNode) -> MemoryNode:
        """Seals every content field in place and returns the node.

        Idempotent per field: an already-sealed value is left alone, so a retry
        after a partial failure does not double-seal and produce something only
        two unseal passes could read.
        """
        for field in CONTENT_FIELDS.get(type(node), ()):
            value = getattr(node, field, None)
            if isinstance(value, str) and value and not is_sealed(value):
                setattr(node, field, self._seal_text(value))
        for field in CONTENT_LIST_FIELDS.get(type(node), ()):
            values = getattr(node, field, None) or []
            setattr(
                node,
                field,
                [
                    v if is_sealed(v) else self._seal_text(v)
                    for v in values
                    if isinstance(v, str) and v
                ],
            )
        self._apply_to_citations(node, self._seal_text, seal=True)
        return node

    def unseal_node(self, node: MemoryNode) -> MemoryNode:
        """The inverse. Called only for objects that already passed the
        permission check -- see the module docstring."""
        for field in CONTENT_FIELDS.get(type(node), ()):
            value = getattr(node, field, None)
            if isinstance(value, str) and is_sealed(value):
                setattr(node, field, self._unseal_text(value))
        for field in CONTENT_LIST_FIELDS.get(type(node), ()):
            values = getattr(node, field, None) or []
            setattr(
                node,
                field,
                [self._unseal_text(v) if is_sealed(v) else v for v in values],
            )
        self._apply_to_citations(node, self._unseal_text, seal=False)
        return node

    def unseal_all(self, nodes: list[MemoryNode]) -> list[MemoryNode]:
        return [self.unseal_node(n) for n in nodes]

    def _apply_to_citations(self, node: MemoryNode, transform, *, seal: bool) -> None:
        """Citation quotes are verbatim source text, so they are content too.

        Nested rather than top-level, which is the one place this registry has to
        know about structure instead of just field names.
        """
        provenance = getattr(node, "provenance", None)
        if provenance is None:
            return
        for citation in provenance.citations:
            quote = citation.quote
            if not quote:
                continue
            if seal and not is_sealed(quote):
                citation.quote = transform(quote)
            elif not seal and is_sealed(quote):
                citation.quote = transform(quote)

    # -- the trust-boundary crossings ------------------------------------

    def _seal_text(self, plaintext: str) -> str:
        sealed = self._gateway.seal_encrypt(plaintext.encode())
        return pack(sealed.ref.key_id, sealed.ciphertext)

    def _unseal_text(self, value: str) -> str:
        key_id, ciphertext = unpack(value)
        return self._gateway.seal_decrypt(ciphertext, key_id).decode()


class NullContentCrypto:
    """Stores content in the clear.

    Exists because sealing requires a reachable gateway and an owner session,
    and a deployment or a test may legitimately have neither. It is **not** a
    fallback: ``Runtime`` picks it only when content encryption is switched off
    explicitly, so a run never silently degrades from sealed to plaintext the way
    it would if this were a rescue path for a failed call.
    """

    def seal_node(self, node: MemoryNode) -> MemoryNode:
        return node

    def unseal_node(self, node: MemoryNode) -> MemoryNode:
        return node

    def unseal_all(self, nodes: list[MemoryNode]) -> list[MemoryNode]:
        return list(nodes)


def text_for_index(node: MemoryNode) -> str:
    """The plaintext an embedding is computed from.

    Called *before* sealing, on purpose: an embedding of ciphertext would be
    noise, and computing it after sealing is the mistake that would make
    retrieval quietly useless while every test that checks structure still
    passed.
    """
    if isinstance(node, Entity):
        return " ".join([node.name, *node.aliases])
    if isinstance(node, Event):
        return f"{node.summary} {node.body or ''}".strip()
    return node.statement


def sealed_field_report(node: MemoryNode) -> dict[str, Any]:
    """Which content fields on this node are sealed. For tests and diagnostics."""
    out: dict[str, Any] = {}
    for field in CONTENT_FIELDS.get(type(node), ()):
        value = getattr(node, field, None)
        if isinstance(value, str) and value:
            out[field] = is_sealed(value)
    for field in CONTENT_LIST_FIELDS.get(type(node), ()):
        values = getattr(node, field, None) or []
        if values:
            out[field] = all(is_sealed(v) for v in values)
    return out
