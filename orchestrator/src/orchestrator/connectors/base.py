from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from ..schema import RawRecord


@runtime_checkable
class SourceConnector(Protocol):
    """Pulls raw activity from one source.

    Connectors are dumb on purpose: they normalise into ``RawRecord`` and
    nothing else. Deciding what any of it *means* is the extractor's job,
    and deciding whether it contradicts something already known is the
    resolver's.
    """

    name: str

    def fetch(self, since_ms: int) -> Iterable[RawRecord]:
        """Yields records that occurred at or after ``since_ms``."""
        ...
