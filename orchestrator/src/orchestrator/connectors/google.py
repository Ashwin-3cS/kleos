from __future__ import annotations

from collections.abc import Iterable

from ..config import Settings
from ..schema import RawRecord
from .base import ConnectorSpec, pack_paragraphs


class GoogleConnector:
    """Gmail/Calendar/Drive activity for a connected Google account."""

    name = "google"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        raise NotImplementedError(
            "Google connector needs a stored per-owner refresh token and Gmail/Calendar "
            "scopes; Phase 1 OAuth only proves identity, it does not request data scopes"
        )


SPEC = ConnectorSpec(
    source_id="google",
    display_name="Google (Gmail, Calendar)",
    factory=GoogleConnector,
    chunker=pack_paragraphs(1200),
    requires_oauth=True,
    oauth_scopes=(
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar.readonly",
    ),
)
