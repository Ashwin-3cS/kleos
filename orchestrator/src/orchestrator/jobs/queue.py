"""RQ queue setup.

Ingestion is enqueued rather than run inline from day one: connecting a
source means backfilling a large history in bursts, and an HTTP request is
the wrong lifetime for that. Queries stay synchronous -- an agent asking a
question wants an answer, not a job id.
"""

from __future__ import annotations

from redis import Redis
from rq import Queue

from ..config import Settings, get_settings


def get_redis(settings: Settings | None = None) -> Redis:
    settings = settings or get_settings()
    return Redis.from_url(settings.redis_url)


def get_queue(settings: Settings | None = None, connection: Redis | None = None) -> Queue:
    settings = settings or get_settings()
    return Queue(
        settings.ingestion_queue,
        connection=connection or get_redis(settings),
        default_timeout=900,
    )
