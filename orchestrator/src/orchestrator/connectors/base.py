from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..config import Settings
from ..enums import SourceId
from ..schema import RawRecord

#: Splits one record's text into retrieval-sized chunks.
Chunker = Callable[[str], list[str]]


@runtime_checkable
class SourceConnector(Protocol):
    """Pulls raw activity from one source, for one owner.

    Connectors are dumb on purpose: they normalise into ``RawRecord`` and
    nothing else. Deciding what any of it *means* is the extractor's job,
    and deciding whether it contradicts something already known is the
    resolver's.
    """

    name: str

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        """Yields ``owner_id``'s records that occurred at or after ``since_ms``."""
        ...


def pack_paragraphs(max_chars: int) -> Chunker:
    """The default shape: split on blank lines, pack to a character budget."""

    def chunk(text: str) -> list[str]:
        units = [u.strip() for u in text.split("\n\n") if u.strip()] or [text.strip()]
        chunks: list[str] = []
        current = ""
        for unit in units:
            if current and len(current) + len(unit) + 2 > max_chars:
                chunks.append(current)
                current = unit
            else:
                current = f"{current}\n\n{unit}" if current else unit
        if current:
            chunks.append(current)
        return chunks

    return chunk


#: Used for a source that declares no chunker, and for text whose source is
#: not registered at all -- retrieval degrades to a sane split rather than
#: failing long after ingest reported success.
default_chunker: Chunker = pack_paragraphs(1000)


@dataclass(frozen=True, slots=True)
class ConnectorSpec:
    """Everything the rest of the service needs to know about one source.

    Declared next to the connector itself so adding a source is one module
    plus one registration, with no edits to retrieval, config or the graphs.
    """

    source_id: SourceId
    display_name: str
    factory: Callable[[Settings], SourceConnector]
    chunker: Chunker = default_chunker
    requires_oauth: bool = False
    oauth_scopes: tuple[str, ...] = field(default=())
    #: A fixture stand-in used when ``ORCHESTRATOR_MODE=mock``. A source that
    #: declares none behaves identically in mock and live mode -- see
    #: ``ConnectorRegistry.connector``.
    mock_factory: Callable[[Settings], SourceConnector] | None = None
