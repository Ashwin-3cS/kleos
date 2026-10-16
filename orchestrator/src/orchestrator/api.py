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
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import mcp_server
from .config import get_settings
from .connectors.direct import SOURCES as DIRECT_SOURCES
from .connectors.direct import TEXT as DIRECT_TEXT
from .connectors.direct import build_record, is_push_source
from .connectors.registry import REGISTRY
from .graphs.brief import SealedBriefingUnsupported, brief_before_acting
from .graphs.decide import WriteRefused, consolidate_session, record_decision
from .graphs.history import context_chain, why_did_this_shift
from .graphs.ingestion import run_ingestion
from .graphs.neighbourhood import neighbourhood
from .graphs.query import run_query
from .graphs.runtime import Runtime
from .jobs.queue import get_queue
from .jobs.tasks import ingest_source
from .storage.sessions import SessionError

log = logging.getLogger(__name__)

_STATIC = Path(__file__).resolve().parent / "static"

_runtime: Runtime | None = None


def runtime() -> Runtime:
    if _runtime is None:
        raise HTTPException(status_code=503, detail="orchestrator runtime is not ready")
    return _runtime


def require_owner(session_token: str) -> str:
    """Resolves an **owner** session to its owner id, or refuses with a 401.

    Extracted from the two byte-identical blocks that used to sit inline in the
    read-log and mutation-log handlers, before the dashboard made it four. The
    duplication was not the problem so much as what it invited: four copies of an
    authentication check drift, and the one that drifts is the one nobody reads.

    The orchestrator holds no signing key, so this is a round trip to the gateway
    (`/auth/session/introspect`). That is the point rather than the cost -- the
    service that verifies owner sessions is the one that issues them.

    A grant token is **refused here**, loudly, and there is a test for it. The two
    auth modes take a string that looks the same and mean entirely different
    things: a grant says "this agent may read these objects", a session says "this
    is the person". Confusing them in this direction would hand an agent the
    owner's own view of what every other agent has been doing.
    """
    try:
        return runtime().gateway.introspect_session(session_token)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"invalid owner session: {exc}") from exc


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _runtime
    _runtime = Runtime.build()
    if _MCP_APP is not None:
        # The tools get the runtime this service already built rather than
        # building their own: two `Runtime.build()` calls in one interpreter mean
        # two Neo4j driver pools, two Redis connections and two copies of the
        # embedding model resident in memory.
        mcp_server.set_runtime(_runtime)
    try:
        if _MCP_APP is None:
            yield
        else:
            # Mounting a Starlette app does not run its lifespan, and the MCP
            # session manager is started there. Without this every request
            # reaches a manager that was never started, which fails per-request
            # rather than at boot -- the worst place to find out.
            async with mcp_server.session_manager().run():
                yield
    finally:
        _runtime.close()
        _runtime = None


#: Built at import time, because mounting has to happen before the app serves.
#: Only the session manager's lifetime belongs in `lifespan`.
_MCP_APP = mcp_server.http_app() if get_settings().mcp_http_enabled else None

app = FastAPI(title="Kleos orchestrator", version="0.1.0", lifespan=lifespan)

if _MCP_APP is not None:
    app.mount("/mcp", _MCP_APP)
    log.info("MCP tools mounted at /mcp (streamable HTTP)")


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


class BriefRequest(BaseModel):
    #: What the agent is about to do, not what it is asking.
    intent: str = Field(min_length=1, max_length=2000)
    grant_token: str
    session_id: str | None = None
    top_k: int = Field(default=8, ge=1, le=50)
    include_body: bool = False


class DecideRequest(BaseModel):
    grant_token: str
    #: The decision as a durable assertion, not a deliberation.
    statement: str = Field(min_length=1, max_length=2000)
    #: Required, not optional: the next agent's briefing is built out of it.
    reason: str = Field(min_length=1, max_length=2000)
    session_id: str | None = None
    memory_kind: str = "episodic"
    sensitive: bool = False


class MutationLogRequest(BaseModel):
    #: An **owner** session, not a grant. Same rule as the read log, and for a
    #: sharper reason: a mutation log read across agents tells one agent what
    #: another has been doing.
    session_token: str
    limit: int = Field(default=50, ge=1, le=500)


class SessionLogRequest(BaseModel):
    #: An **owner** session. Listing sessions across agents is the same
    #: disclosure shape as the mutation log: it tells whoever asks what every
    #: other agent has been working on.
    session_token: str
    #: The gateway-verified device, not the `agent_id` label. Optional: without
    #: it, every device.
    device_id: str | None = None
    limit: int = Field(default=50, ge=1, le=500)


class ActionLogRequest(BaseModel):
    #: An **owner** session. What was done in the world on the owner's behalf is
    #: the owner's record.
    session_token: str
    limit: int = Field(default=50, ge=1, le=500)


class ConsolidateRequest(BaseModel):
    #: A grant that says `may_write` **and** `may_unseal`: the blocks are sealed,
    #: and turning them into claims is a write. Grant-authenticated rather than
    #: owner-authenticated even when the owner pressed the button, so that one
    #: gate decides every claim-producing write and every such write carries a
    #: grant fingerprint. See ADR 0023.
    grant_token: str
    session_id: str


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
    owner_id = require_owner(req.session_token)
    return runtime().read_log.summary(owner_id, limit=req.limit)


@app.post("/memory/brief")
def memory_brief(req: BriefRequest) -> dict[str, Any]:
    """What an agent should know before acting: who decided what, and why.

    Grant-authenticated like every other agent read. Composes the query graph and
    the supersession read rather than retrieving for itself, so each keeps its own
    permission check and writes its own log entry -- plus one entry for the
    composite, which is what lets an owner see *what the agent was about to do*
    rather than only which objects it was shown.

    Returns 409 against a store whose content is sealed at rest: a briefing
    reads the claims' own text to write its advisories, and since ADR 0024 that
    text exists only inside the enclave. 409 rather than 501, because the
    capability is not missing from the build -- it conflicts with the state this
    deployment is in, and `POST /query` serves the same memory as a sealed
    answer.
    """
    try:
        return brief_before_acting(
            runtime(),
            req.intent,
            req.grant_token,
            session_id=req.session_id,
            top_k=req.top_k,
            include_body=req.include_body,
        ).as_dict()
    except SealedBriefingUnsupported as refused:
        raise HTTPException(status_code=409, detail=str(refused)) from refused


@app.post("/memory/decide", status_code=201)
def memory_decide(req: DecideRequest) -> dict[str, Any]:
    """Record what an agent decided, under a grant that says it may.

    The HTTP sibling of the `record_decision` MCP tool, and the only
    grant-authorised *write* this service serves -- `POST /remember` is the
    owner's own push path and authenticates differently.

    A refusal comes back as `201` with `refused: true` rather than as a `403`.
    The same choice the MCP tool makes and for the same reason: a decline is a
    real answer, and the deny reason is the useful part of it. A status code
    alone cannot say "your grant may write, but not as that source".
    """
    try:
        recorded = record_decision(
            runtime(),
            req.grant_token,
            req.statement,
            req.reason,
            session_id=req.session_id,
            memory_kind=req.memory_kind,
            sensitive=req.sensitive,
        )
    except WriteRefused as refused:
        return {"refused": True, "reason": refused.reason, "detail": str(refused)}
    except SessionError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"refused": False, **recorded.as_dict()}


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
    owner_id = require_owner(req.session_token)
    entries = runtime().mutations.recent(owner_id, limit=req.limit)
    return {
        "owner_id": owner_id,
        "mutations": len(entries),
        "entries": [e.as_dict() for e in entries],
    }


@app.post("/memory/sessions")
def memory_sessions(req: SessionLogRequest) -> dict[str, Any]:
    """What each of this owner's agents has been working on, and whether it has
    been distilled into memory yet.

    **Owner**-authenticated, with the mutation log's reasoning: a listing across
    sessions tells whoever asks what every other agent has been doing. The
    harness itself never needs this -- an agent addresses the session it already
    holds -- so there is no grant path and no MCP tool.

    Holds no block content. A session node is an index into the blob store by
    design, so this answers "how much, from whom, distilled or not" without
    unsealing anything. The answer to "what did it actually say" is consolidation,
    which is a write and is gated as one.
    """
    owner_id = require_owner(req.session_token)
    sessions = runtime().sessions.recent(
        owner_id, limit=req.limit, device_id=req.device_id
    )
    return {
        "owner_id": owner_id,
        "device_id": req.device_id,
        "sessions": len(sessions),
        # The freshness signal, computed here rather than left to the client:
        # `consolidated_at_ms is None` is the only thing that distinguishes
        # "never distilled" from "distilled, concluded nothing", and a client
        # inferring it from an empty claim list would get the common case wrong.
        "undistilled": sum(
            1 for s in sessions if s.consolidated_at_ms is None and s.block_count
        ),
        "entries": [s.as_dict() for s in sessions],
    }


@app.post("/memory/actions")
def memory_actions(req: ActionLogRequest) -> dict[str, Any]:
    """Every action an agent asked the enclave to perform, and what came back.

    **Owner**-authenticated, beside the read and mutation logs, and the most
    consequential of the three: a read discloses and a mutation changes the
    record, but an action sent mail or posted a comment. It cannot be undone by
    rewriting a row, which is why the record of it is append-only and why a
    failed attempt is in here too -- "tried and failed" is a different fact from
    "never tried".

    Carries no arguments, because an action's arguments are the content it acted
    on. What is here is the digest, which makes a repeat recognisable without
    being readable.
    """
    owner_id = require_owner(req.session_token)
    entries = runtime().actions.recent(owner_id, limit=req.limit)
    return {
        "owner_id": owner_id,
        "actions": len(entries),
        "entries": [e.as_dict() for e in entries],
    }


@app.post("/memory/consolidate", status_code=201)
def memory_consolidate(req: ConsolidateRequest) -> dict[str, Any]:
    """Turn what a session concluded into memory, and leave the rest alone.

    The second state transition, over HTTP: blocks are *stored* until this runs,
    and only what it writes becomes *searchable*. Almost nothing should.

    **Grant**-authenticated, including when the owner triggered it from the
    dashboard -- the dashboard signs a short-lived grant with the owner's own
    device key rather than reaching for an owner-authority path. One gate decides
    every claim-producing write, and every such write carries a `grant_fp`. The
    cost is that the grant is a powerful one (write plus unseal across every
    kind), which is why it is minted per click and expires in under a minute.
    See ADR 0023.

    **A refusal arrives in `errors`, not in `refused`.** Consolidation declines
    *per conclusion* so that a grant covering episodes but not procedures keeps
    the episodes, which means nothing escapes to the handler and `refused` stays
    false even when every conclusion was turned away. The branch below is a
    backstop for a future gate that fires earlier; the signal a client has to
    read today is `errors`, and one that reports `refused` alone will tell the
    owner a wholly refused run succeeded.
    """
    try:
        consolidated = consolidate_session(runtime(), req.grant_token, req.session_id)
    except WriteRefused as refused:
        return {"refused": True, "reason": refused.reason, "detail": str(refused)}
    except SessionError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"refused": False, **consolidated.as_dict()}


@app.get("/explorer", include_in_schema=False)
def explorer() -> FileResponse:
    """The read-only graph explorer: one static page over the endpoint above.

    Served from the orchestrator itself because it reads localhost-only data
    under a grant token typed into it; there is nowhere external it could be
    hosted without moving both of those off this machine.
    """
    return FileResponse(_STATIC / "explorer.html", media_type="text/html")


#: Where `ui/` builds to. Committed, so running Kleos needs Python and nothing
#: else -- Node is a development dependency of the UI, not of the service.
_UI = _STATIC / "ui"

if (_UI / "index.html").exists():
    # Mounted rather than routed one file at a time, because Vite emits hashed
    # asset names and a hand-written `FileResponse` per file cannot know them.
    # Mounted *before* the catch-all below, since the first match wins and the
    # catch-all would otherwise answer every asset request with the index page.
    app.mount("/ui/assets", StaticFiles(directory=_UI / "assets"), name="ui-assets")


@app.get("/ui", include_in_schema=False)
@app.get("/ui/{path:path}", include_in_schema=False)
def dashboard(path: str = "") -> FileResponse:
    """The owner's dashboard: access policy, memory, and what agents have done.

    One page for every path under `/ui`, because it routes client-side. That is
    also what makes `/ui/oauth/land` work: it is the provider's redirect target,
    configured as `GOOGLE_REDIRECT_URI`, and the page reads `code` and `state`
    off its own query string. The redirect therefore lands on **this** origin
    rather than on the gateway's, which is the whole reason the browser can read
    the session token at all. See ADR 0023.

    Served from the orchestrator, like the explorer, and for a sharper reason: it
    holds the owner's device key and talks to owner-authenticated routes. Being
    same-origin with those routes is what keeps this service free of a CORS
    allow-list, which would be the one change most likely to make them reachable
    from somewhere else.
    """
    index = _UI / "index.html"
    if not index.exists():
        raise HTTPException(
            status_code=503,
            detail="the dashboard is not built; run `npm ci && npm run build` in ui/",
        )
    return FileResponse(index, media_type="text/html")


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
