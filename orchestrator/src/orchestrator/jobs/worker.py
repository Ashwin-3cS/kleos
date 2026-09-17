"""RQ worker entrypoint: ``python -m orchestrator.jobs.worker``."""

from __future__ import annotations

import logging

from rq import Worker

from ..config import get_settings
from .queue import get_queue, get_redis


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    connection = get_redis(settings)
    queue = get_queue(settings, connection)
    logging.getLogger(__name__).info(
        "worker starting mode=%s queue=%s redis=%s",
        settings.mode,
        settings.ingestion_queue,
        settings.redis_url,
    )
    Worker([queue], connection=connection).work(with_scheduler=False)


if __name__ == "__main__":
    main()
