from __future__ import annotations

from ..config import Settings
from ..enums import SourceId
from .base import SourceConnector
from .github import GitHubConnector
from .google import GoogleConnector
from .mock import MockConnector

__all__ = [
    "GitHubConnector",
    "GoogleConnector",
    "MockConnector",
    "SourceConnector",
    "get_connector",
]


def get_connector(source: SourceId, settings: Settings) -> SourceConnector:
    if settings.is_mock or source == "mock":
        return MockConnector()
    if source == "google":
        return GoogleConnector(settings)
    if source == "github":
        return GitHubConnector(settings)
    raise ValueError(f"no connector for source {source!r}")
