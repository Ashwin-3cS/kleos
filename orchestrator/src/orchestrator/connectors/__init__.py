from __future__ import annotations

from ..config import Settings
from ..enums import SourceId
from .base import Chunker, ConnectorSpec, SourceConnector
from .github import GitHubConnector
from .google import GoogleConnector
from .mock import MockConnector
from .registry import REGISTRY, ConnectorRegistry, UnknownSourceError, register

__all__ = [
    "REGISTRY",
    "Chunker",
    "ConnectorRegistry",
    "ConnectorSpec",
    "GitHubConnector",
    "GoogleConnector",
    "MockConnector",
    "SourceConnector",
    "UnknownSourceError",
    "get_connector",
    "register",
]


def get_connector(source: SourceId, settings: Settings) -> SourceConnector:
    """Convenience wrapper over the process-wide registry.

    Anything holding a ``Runtime`` should go through ``runtime.registry``
    instead, so a registry the caller extended is the one that is used.
    """
    return REGISTRY.connector(source, settings)
