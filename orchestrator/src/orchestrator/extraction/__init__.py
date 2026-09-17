from __future__ import annotations

from ..config import Settings
from .base import Extractor
from .llm import LLMExtractor
from .mock import MockExtractor

__all__ = ["Extractor", "LLMExtractor", "MockExtractor", "get_extractor"]


def get_extractor(settings: Settings) -> Extractor:
    return MockExtractor() if settings.is_mock else LLMExtractor(settings)
