"""Embedders.

``HashedTokenEmbedder`` is the mock-mode default: a deterministic bag-of-
tokens projection into a fixed-dimension unit vector. It is not semantic --
it only matches on shared vocabulary -- but it is stable across processes
and needs no key, which is what makes the end-to-end mock run reproducible.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol, runtime_checkable

from ..config import Settings

_TOKEN_RE = re.compile(r"[a-z0-9]+")


@runtime_checkable
class Embedder(Protocol):
    dim: int

    def embed(self, text: str) -> list[float]: ...


class HashedTokenEmbedder:
    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        tokens = _TOKEN_RE.findall(text.lower())
        for token in tokens:
            digest = hashlib.sha256(token.encode()).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[bucket] += sign
        norm = math.sqrt(sum(v * v for v in vector))
        if norm == 0.0:
            # Neo4j's cosine index rejects an all-zero vector.
            vector[0] = 1.0
            return vector
        return [v / norm for v in vector]


class LocalEmbedder:
    """A real, semantic embedder that runs here.

    ONNX on CPU via ``fastembed``, defaulting to ``BAAI/bge-small-en-v1.5``: 384
    dimensions, about 67MB of weights, no API key, no torch.

    **Local rather than hosted, for reasons that are not cost.** Embedding text
    means sending it somewhere, and the text here is the resolved record -- the
    thing ADR 0010 encrypts at rest. Encrypting a database and then streaming the
    same sentences to a third party to be vectorised would be theatre. A hosted
    embedder also makes ``test_content_at_rest`` flaky, since it asserts a stored
    vector equals a freshly computed one: true of a pinned local model, not of a
    versioned endpoint. And embeddings are on the ingest path for every object, so
    a network round trip per object would set the backfill rate.

    Weights download once on first use and are cached, which puts the network
    dependency at install time rather than at query time.
    """

    def __init__(self, settings: Settings) -> None:
        from fastembed import TextEmbedding

        self._model_name = settings.embedding_model
        self._model = TextEmbedding(model_name=self._model_name)
        # Read from the model, not from configuration. Those two disagreeing is
        # what silently breaks the Neo4j vector index, so the model is the
        # authority and `verify_dim` is what makes a mismatch loud.
        self.dim = len(next(iter(self._model.embed(["dimension probe"]))))

    @property
    def name(self) -> str:
        return self._model_name

    def embed(self, text: str) -> list[float]:
        # fastembed is batch-first; one string is a batch of one. Callers with a
        # list should use `embed_many`, which is several times faster per item.
        return [float(v) for v in next(iter(self._model.embed([text or " "])))]

    def embed_many(self, texts: list[str]) -> list[list[float]]:
        """Batched. Order-preserving, because callers zip the result back against
        their own list of objects."""
        if not texts:
            return []
        return [
            [float(v) for v in vector]
            for vector in self._model.embed([t or " " for t in texts])
        ]


def verify_dim(embedder: Embedder, configured: int) -> None:
    """Fails loudly when the model's width is not what is configured.

    The Neo4j vector index is built from configuration while vectors come from the
    model, and nothing downstream notices them disagreeing: writes land as
    properties the index will not cover, and reads fail much later and elsewhere.
    Checked once at startup instead.
    """
    if embedder.dim != configured:
        raise ValueError(
            f"embedder produces {embedder.dim}-dimensional vectors but EMBEDDING_DIM "
            f"is {configured}. These must agree -- the Neo4j vector index is built from "
            f"the configured value, so a mismatch makes every write silently unindexed. "
            f"Set EMBEDDING_DIM={embedder.dim}."
        )


def get_embedder(settings: Settings) -> Embedder:
    if not settings.use_real_embedder:
        return HashedTokenEmbedder(settings.embedding_dim)
    return LocalEmbedder(settings)
