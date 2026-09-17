from __future__ import annotations

from collections.abc import Iterable

from ..config import Settings
from ..schema import RawRecord


class GoogleConnector:
    """Gmail/Calendar/Drive activity for a connected Google account."""

    name = "google"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, since_ms: int) -> Iterable[RawRecord]:
        raise NotImplementedError(
            "Google connector needs a stored per-owner refresh token and Gmail/Calendar "
            "scopes; Phase 1 OAuth only proves identity, it does not request data scopes"
        )
