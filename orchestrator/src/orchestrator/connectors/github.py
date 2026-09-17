from __future__ import annotations

from collections.abc import Iterable

from ..config import Settings
from ..schema import RawRecord


class GitHubConnector:
    """Commits, PRs, issues and review comments for a connected account."""

    name = "github"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, since_ms: int) -> Iterable[RawRecord]:
        raise NotImplementedError(
            "GitHub connector needs a stored per-owner token with repo scope; Phase 1 "
            "OAuth only proves identity, it does not request data scopes"
        )
