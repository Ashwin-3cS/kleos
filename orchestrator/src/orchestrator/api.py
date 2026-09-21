"""FastAPI surface of the orchestrator.

Two shapes on purpose: ingestion is enqueued and returns a job id, queries
run synchronously and return an answer. Nothing here does any memory work
itself -- it is a thin edge over the two graphs.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .config import get_settings
from .connectors.registry import REGISTRY
from .graphs.history import context_chain, why_did_this_shift
from .graphs.neighbourhood import neighbourhood
from .graphs.query import run_query
from .graphs.runtime import Runtime
from .jobs.queue import get_queue
from .jobs.tasks import ingest_source

log = logging.getLogger(__name__)

_STATIC = Path(__file__).resolve().parent / "static"

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


class ShiftRequest(BaseModel):
    claim_id: str
    grant_token: str


class ContextRequest(BaseModel):
    object_id: str
    grant_token: str
    hops: int = Field(default=3, ge=1, le=6)


class NeighbourhoodRequest(BaseModel):
    seed_ids: list[str] = Field(min_length=1, max_length=25)
    grant_token: str
    # Capped low on purpose: hops are the cost knob here, and 3 hops out of a
    # busy entity already reaches most of an owner's graph.
    hops: int = Field(default=2, ge=1, le=4)


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


@app.get("/sources")
def sources() -> dict[str, Any]:
    settings = get_settings()
    return {
        "sources": [
            {
                "id": spec.source_id,
                "display_name": spec.display_name,
                "requires_oauth": spec.requires_oauth,
                "oauth_scopes": list(spec.oauth_scopes),
                "enabled": settings.source_enabled(spec.source_id),
                "mock_fixtures": spec.mock_factory is not None,
            }
            for spec in REGISTRY.specs()
        ]
    }


@app.post("/ingest", response_model=IngestResponse, status_code=202)
def enqueue_ingest(req: IngestRequest) -> IngestResponse:
    settings = get_settings()
    # Rejected here rather than deep in the graph: an unknown source would
    # otherwise surface as a failed background job with a traceback.
    if req.source not in REGISTRY:
        raise HTTPException(
            status_code=400,
            detail=f"unknown source {req.source!r}; known sources: {', '.join(REGISTRY.ids())}",
        )
    if not settings.source_enabled(req.source):
        raise HTTPException(
            status_code=400, detail=f"source {req.source!r} is not enabled in this deployment"
        )
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


@app.post("/memory/shift")
def shift(req: ShiftRequest) -> dict[str, Any]:
    """Why a decision shifted: the supersession chain and the evidence that
    moved it. Permission-checked per claim, like every other read."""
    return why_did_this_shift(runtime(), req.claim_id, req.grant_token).as_dict()


@app.post("/memory/context")
def context(req: ContextRequest) -> dict[str, Any]:
    """The citation chain around one object, which crosses sources wherever
    the underlying material does."""
    return context_chain(runtime(), req.object_id, req.grant_token, hops=req.hops).as_dict()


@app.post("/memory/neighbourhood")
def memory_neighbourhood(req: NeighbourhoodRequest) -> dict[str, Any]:
    """Nodes and edges within ``hops`` of the seeds, permission-filtered.

    Objects the grant does not cover are dropped rather than returned as
    placeholders -- in an open-ended walk the placeholders would themselves
    disclose the graph's shape -- and the response reports how many were
    dropped so the caller knows the picture is partial.
    """
    return neighbourhood(
        runtime(), req.seed_ids, req.grant_token, hops=req.hops
    ).as_dict()


@app.get("/explorer", include_in_schema=False)
def explorer() -> FileResponse:
    """The read-only graph explorer: one static page over the endpoint above.

    Served from the orchestrator itself because it reads localhost-only data
    under a grant token typed into it; there is nowhere external it could be
    hosted without moving both of those off this machine.
    """
    return FileResponse(_STATIC / "explorer.html", media_type="text/html")


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
