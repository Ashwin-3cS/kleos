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
from .connectors.direct import SOURCES as DIRECT_SOURCES
from .connectors.direct import TEXT as DIRECT_TEXT
from .connectors.direct import build_record, is_push_source
from .connectors.registry import REGISTRY
from .graphs.history import context_chain, why_did_this_shift
from .graphs.ingestion import run_ingestion
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


app = FastAPI(title="Kleos orchestrator", version="0.1.0", lifespan=lifespan)


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


class RememberRequest(BaseModel):
    """Something the person is telling the system directly."""

    owner_id: str
    text: str = Field(min_length=1, max_length=100_000)
    #: `text` or `voice`. Separate sources so a grant can cover one and not the
    #: other -- "read what I wrote down, not what I said out loud" is a real
    #: distinction and `permits()` can only express it if the ids differ.
    source: str = DIRECT_TEXT
    #: When the thing happened, if it was not now. A note about last Tuesday
    #: belongs on last Tuesday: `occurred_at_ms` is what every time-windowed scope
    #: and every "what did I know then" read is written against.
    occurred_at_ms: int | None = None
    #: Seals the utterance in the enclave before storage, which needs a session.
    sensitive: bool = False
    #: Owner session, required only to seal.
    session_token: str | None = None


class ReadLogRequest(BaseModel):
    #: An **owner** session, not a grant. See ADR 0005.
    session_token: str
    limit: int = Field(default=50, ge=1, le=500)


class MutationLogRequest(BaseModel):
    #: An **owner** session, not a grant. Same rule as the read log, and for a
    #: sharper reason: a mutation log read across agents tells one agent what
    #: another has been doing.
    session_token: str
    limit: int = Field(default=50, ge=1, le=500)


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


@app.post("/remember", status_code=201)
def remember(req: RememberRequest) -> dict[str, Any]:
    """Tell the system something, and have it become memory now.

    **Synchronous, unlike `/ingest`.** A backfill is enqueued because connecting a
    source means pulling a large history in bursts, which is the wrong lifetime for
    an HTTP request. A person who has just said one sentence is in the opposite
    situation: they want to know it landed, and handing them a job id to poll would
    be the wrong answer to "did you get that".

    Runs the same ingestion graph as every other source. The record is pushed in
    rather than pulled, and everything after that -- extraction, resolution,
    sealing, the write -- is identical, because a thing the person said is a record
    like any other once it exists. A separate graph would mean two paths that have
    to be kept resolving the same way.
    """
    settings = get_settings()
    if not is_push_source(req.source):
        raise HTTPException(
            status_code=400,
            detail=(
                f"{req.source!r} is not a push source; expected one of "
                f"{', '.join(DIRECT_SOURCES)}. Pulled sources go through POST /ingest."
            ),
        )
    if not settings.source_enabled(req.source):
        raise HTTPException(
            status_code=400, detail=f"source {req.source!r} is not enabled in this deployment"
        )
    if req.sensitive and not req.session_token:
        # Sealing crosses the trust boundary, and the gateway takes the owner from
        # the session rather than from us. Refused up front rather than failing
        # inside the graph, where it would surface as a skipped record.
        raise HTTPException(
            status_code=400,
            detail="sensitive=true needs session_token: sealing happens in the enclave, "
            "under the owner the session names",
        )

    record = build_record(
        owner_id=req.owner_id,
        text=req.text,
        source=req.source,
        occurred_at_ms=req.occurred_at_ms,
        sensitive=req.sensitive,
    )
    result = run_ingestion(
        runtime(),
        req.owner_id,
        source=req.source,
        session_token=req.session_token,
        records=[record],
        # Keyed by the record, not by the owner and source: two utterances must not
        # share a checkpoint thread, or the second would resume the first's state.
        thread_id=f"remember:{record.external_id}",
    )
    log.info(
        "remembered owner=%s source=%s external_id=%s claims=%d",
        req.owner_id,
        req.source,
        record.external_id,
        result.claims,
    )
    return {"external_id": record.external_id, **result.as_dict()}


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


@app.post("/memory/reads")
def memory_reads(req: ReadLogRequest) -> dict[str, Any]:
    """What agents have actually read, for the owner of this session.

    The only **owner**-authenticated read the orchestrator serves: every other
    one is authorised by an agent grant, and this is the record of what those
    grants disclosed. An agent able to read it could see which objects other
    agents were shown -- a disclosure channel around the permission check
    rather than a record of it -- so it takes a session token, resolved by the
    gateway, and there is no grant-authorised path to it and no MCP tool.
    See ADR 0005.
    """
    try:
        owner_id = runtime().gateway.introspect_session(req.session_token)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"invalid owner session: {exc}") from exc
    return runtime().read_log.summary(owner_id, limit=req.limit)


@app.post("/memory/mutations")
def memory_mutations(req: MutationLogRequest) -> dict[str, Any]:
    """Every state change to this owner's memory: what changed, who changed it,
    and which rule decided.

    **Owner**-authenticated, beside the read log and for the same reason, which
    is sharper here. The read log tells an owner what one grant was shown; a
    mutation log read wholesale would tell *an agent* what other agents have
    been writing -- the activity of every other agent on the same memory, around
    the permission check rather than through it. So there is no grant-authorised
    path to this and no MCP tool.

    A briefing does surface mutations, but only for the specific objects the
    asking agent has just been permitted to see: a per-object disclosure that
    follows a permission check, not a feed.
    """
    try:
        owner_id = runtime().gateway.introspect_session(req.session_token)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"invalid owner session: {exc}") from exc
    entries = runtime().mutations.recent(owner_id, limit=req.limit)
    return {
        "owner_id": owner_id,
        "mutations": len(entries),
        "entries": [e.as_dict() for e in entries],
    }


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
