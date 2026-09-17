from __future__ import annotations

from ..config import Settings
from ..enums import SourceKind
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


def get_connector(source: SourceKind, settings: Settings) -> SourceConnector:
    if settings.is_mock or source is SourceKind.MOCK:
        return MockConnector()
    if source is SourceKind.GOOGLE:
        return GoogleConnector(settings)
    if source is SourceKind.GITHUB:
        return GitHubConnector(settings)
    raise ValueError(f"no connector for source {source!r}")
