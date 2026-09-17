"""FastAPI surface of the orchestrator.

Two shapes on purpose: ingestion is enqueued and returns a job id, queries
run synchronously and return an answer. Nothing here does any memory work
itself -- it is a thin edge over the two graphs.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import get_settings
from .graphs.query import run_query
from .graphs.runtime import Runtime
from .jobs.queue import get_queue
from .jobs.tasks import ingest_source

log = logging.getLogger(__name__)

_runtime: Runtime | None = None


def runtime() -> Runtime:
    if _runtime is None:
        raise HTTPException(status_code=503, detail="orchestrator runtime is not ready")
    return _runtime


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _runtime
    _runtime = Runtime.build()
    try:
        yield
    finally:
        _runtime.close()
        _runtime = None


app = FastAPI(title="memorai orchestrator", version="0.1.0", lifespan=lifespan)


class IngestRequest(BaseModel):
    owner_id: str
    source: str = "mock"
    since_ms: int = 0
    #: Owner session from the gateway, needed only to seal sensitive bodies.
    session_token: str | None = None


class IngestResponse(BaseModel):
    job_id: str
    queue: str


class QueryRequest(BaseModel):
    question: str
    grant_token: str
    top_k: int = Field(default=8, ge=1, le=50)


@app.get("/health")
def health() -> dict[str, Any]:
    settings = get_settings()
    status: dict[str, Any] = {"status": "ok", "mode": settings.mode}
    try:
        runtime().store.verify()
        status["neo4j"] = "ok"
    except Exception as exc:  # noqa: BLE001
        status["neo4j"] = f"unreachable: {exc}"
        status["status"] = "degraded"
    try:
        get_queue(settings).connection.ping()
        status["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        status["redis"] = f"unreachable: {exc}"
        status["status"] = "degraded"
    try:
        status["gateway"] = runtime().gateway.health()
    except Exception as exc:  # noqa: BLE001
        status["gateway"] = f"unreachable: {exc}"
        status["status"] = "degraded"
    return status


@app.post("/ingest", response_model=IngestResponse, status_code=202)
def enqueue_ingest(req: IngestRequest) -> IngestResponse:
    settings = get_settings()
    queue = get_queue(settings)
    job = queue.enqueue(
        ingest_source,
        owner_id=req.owner_id,
        source=req.source,
        since_ms=req.since_ms,
        session_token=req.session_token,
    )
    log.info("enqueued ingestion job=%s owner=%s source=%s", job.id, req.owner_id, req.source)
    return IngestResponse(job_id=job.id, queue=settings.ingestion_queue)


@app.get("/ingest/{job_id}")
def ingest_status(job_id: str) -> dict[str, Any]:
    queue = get_queue()
    job = queue.fetch_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"no such job {job_id}")
    return {
        "job_id": job.id,
        "status": job.get_status(refresh=True),
        "result": job.return_value(refresh=True),
        "error": job.exc_info,
    }


@app.post("/query")
def query(req: QueryRequest) -> dict[str, Any]:
    answer = run_query(runtime(), req.question, req.grant_token, top_k=req.top_k)
    return answer.as_dict()


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
