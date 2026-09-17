"""Enqueueable ingestion entrypoints.

Each task builds its own runtime: an RQ worker forks per job, so a Neo4j
driver or HTTP client inherited from the parent process would be unsafe to
reuse across the fork.
"""

from __future__ import annotations

import logging
from typing import Any

from ..graphs.runtime import Runtime

log = logging.getLogger(__name__)


def ingest_source(
    owner_id: str,
    source: str = "mock",
    since_ms: int = 0,
    session_token: str | None = None,
) -> dict[str, Any]:
    from ..graphs.ingestion import run_ingestion

    runtime = Runtime.build()
    try:
        result = run_ingestion(
            runtime,
            owner_id=owner_id,
            source=source,
            since_ms=since_ms,
            session_token=session_token,
        )
        log.info("ingest_source done owner=%s %s", owner_id, result.as_dict())
        return result.as_dict()
    finally:
        runtime.close()
