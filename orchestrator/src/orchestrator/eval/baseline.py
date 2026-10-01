"""A plain RAG baseline: chunk, embed, cosine, return text.

This is what the resolved record is being measured *against*, so it has to be
a fair opponent rather than a straw man. Everything that is not resolution is
held identical:

- the same raw records,
- the same chunker each source declares,
- the same embedder the real retrieval path uses,
- the same top-k.

What it does **not** have is the resolved layer: no entities, no claims, no
supersession, no citations, no graph proximity, no permission-checked ACLs. It
returns the chunks whose embeddings are nearest the question, which is what a
competent RAG-over-documents implementation does.

Two deliberate choices about fairness:

**The baseline sees the raw bodies.** The resolved path stores a sensitive body
sealed and keeps it out of the event; the baseline indexes the plaintext.
That makes the baseline *stronger* than it could legitimately be in this
product. Handicapping it to match would flatter the comparison, and the point
of the harness is to find out whether resolution wins on merit.

**It is scored on the same unit.** Both systems' answers are reduced to the set
of source records they rest on, because the baseline cannot name a claim id.
See `questions.py`.

It is in-memory by design: writing baseline chunks into Neo4j would put
unresolved text under the same labels the real retrieval path searches, and the
comparison would start measuring a polluted index.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..retrieval.index import chunk_for_source
from .corpus import Record


@dataclass(frozen=True, slots=True)
class Chunk:
    connector: str
    external_id: str
    text: str
    occurred_at_ms: int
    embedding: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class Hit:
    chunk: Chunk
    score: float

    @property
    def record(self) -> tuple[str, str]:
        return (self.chunk.connector, self.chunk.external_id)


def _cosine(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class PlainRag:
    """Chunk-level vector search over the raw corpus."""

    name = "plain-rag"

    def __init__(self, records: tuple[Record, ...], embedder, registry=None) -> None:
        self._embedder = embedder
        self._chunks: list[Chunk] = []
        for record in records:
            text = f"{record.title}. {record.body}"
            for piece in chunk_for_source(text, record.connector, registry):
                self._chunks.append(
                    Chunk(
                        connector=record.connector,
                        external_id=record.external_id,
                        text=piece,
                        occurred_at_ms=record.occurred_at_ms,
                        embedding=tuple(embedder.embed(piece)),
                    )
                )

    def __len__(self) -> int:
        return len(self._chunks)

    def retrieve(self, question: str, top_k: int) -> list[Hit]:
        query = tuple(self._embedder.embed(question))
        scored = [Hit(chunk=chunk, score=_cosine(query, chunk.embedding)) for chunk in self._chunks]
        # Ties by (connector, external_id) so a run is reproducible; with the
        # hashed-token embedder ties are common and dict order would otherwise
        # show up as a quality difference between runs.
        scored.sort(key=lambda h: (-h.score, h.chunk.external_id, h.chunk.text[:32]))
        return scored[:top_k]

    def answer(self, question: str, top_k: int, not_after_ms: int | None = None) -> dict:
        """The baseline's best effort at an answer.

        ``not_after_ms`` is honoured because the comparison would otherwise be
        unfair in the *other* direction: the resolved path gets the time window
        from the grant scope, and a baseline with no way to express one would
        lose the "what did I know on date D" question to a missing feature
        rather than to a missing capability. A production RAG system would
        filter on a timestamp, so this one does too.
        """
        hits = [
            hit
            for hit in self.retrieve(question, top_k * 3)
            if not_after_ms is None or hit.chunk.occurred_at_ms <= not_after_ms
        ][:top_k]
        return {
            "records": [hit.record for hit in hits],
            # Per chunk as well as joined: the harness scores whether a stale
            # assertion is present in what the reader is shown, which is a
            # question about the chunks rather than about the records they
            # came from.
            "texts": [hit.chunk.text for hit in hits],
            "text": "\n".join(f"- {hit.chunk.text}" for hit in hits),
            # Structurally zero, and the honest value: there is no resolved
            # status on a chunk of raw text, so the baseline cannot mark
            # anything superseded, and cannot cite anything but itself.
            "marked_stale": [],
            "citations": [],
        }
