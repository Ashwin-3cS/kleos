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


class VoyageEmbedder:
    """Real embedder for ``ORCHESTRATOR_MODE=live``."""

    def __init__(self, settings: Settings) -> None:
        self.dim = settings.embedding_dim
        self._settings = settings

    def embed(self, text: str) -> list[float]:
        raise NotImplementedError(
            "live embeddings are not wired: needs a VOYAGE_API_KEY (or another provider) "
            "and an embedding_dim matching that model, which must also match the Neo4j "
            "vector index created by storage.migrations"
        )


def get_embedder(settings: Settings) -> Embedder:
    if settings.is_mock:
        return HashedTokenEmbedder(settings.embedding_dim)
    return VoyageEmbedder(settings)
