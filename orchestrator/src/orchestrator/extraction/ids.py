from __future__ import annotations

import hashlib


def stable_id(prefix: str, *parts: str) -> str:
    """Content-addressed id so re-ingesting the same record is idempotent."""
    digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:20]
    return f"{prefix}_{digest}"
