from __future__ import annotations

from collections.abc import Iterable

from ..config import Settings
from ..schema import RawRecord
from .base import ConnectorSpec, pack_paragraphs


class GitHubConnector:
    """Commits, PRs, issues and review comments for a connected account."""

    name = "github"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        raise NotImplementedError(
            "GitHub connector needs a stored per-owner token with repo scope; Phase 1 "
            "OAuth only proves identity, it does not request data scopes"
        )


_pack = pack_paragraphs(600)


def chunk_diff(text: str) -> list[str]:
    """Splits on hunk boundaries when the text is diff-shaped.

    A diff hunk is already the atomic unit of a code change; packing several
    into one chunk only blurs which change a hit came from.
    """
    if "\n@@" not in text:
        return _pack(text)
    parts = [p for p in text.split("\n@@") if p.strip()]
    return [parts[0].strip()] + [f"@@{p}".strip() for p in parts[1:]]


SPEC = ConnectorSpec(
    source_id="github",
    display_name="GitHub",
    factory=GitHubConnector,
    chunker=chunk_diff,
    requires_oauth=True,
    oauth_scopes=("read:user", "repo"),
)
