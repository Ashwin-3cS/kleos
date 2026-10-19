"""MCP server: the surface every plugged-in agent speaks to.

This is the product surface. An authorized agent -- Claude Code on one device,
ChatGPT on another -- connects over MCP, asks questions of a person's memory,
and keeps its own working context here while it does.

**There is no credential channel in MCP.** A tool call carries arguments and
nothing else, so the grant token is an argument on every call, and a
`session_id` is never sufficient on its own: every call that uses one also
re-presents the grant. That is a real limitation of this transport rather than
a style choice, and it is why a leaked session id buys an attacker nothing it
could not already do with the grant it would still need.

What is exposed, and what is not:

- **Reads** -- `query_memory`, `why_this_shifted`, `memory_context_chain`. No
  neighbourhood tool: it is a visualization payload, and handing an agent an
  adjacency list would be a cheap structure-enumeration primitive (seed, walk,
  re-seed) for no gain in answer quality. No read-log tool: an agent that could
  read the log would see what *other* agents were shown, which is a disclosure
  channel around the permission check rather than a record of it.
- **Session state** -- `open_session`, `append_context`, `close_session`. An
  agent's short-term memory: stored, and deliberately not searchable until it is
  consolidated. See ADR 0016 and `storage/sessions.py`.
- **The briefing** -- `brief_before_acting`, which is the point of the whole
  layer: before an agent acts, it is told what another agent already decided on
  the same subject, who decided it and on what basis. Composed out of the reads
  above rather than retrieving for itself, so each one keeps its own permission
  check and its own log entry.
- **One action** -- `request_action`, under a grant that says `may_act` *and*
  names the action. The agent submits an intent and receives an
  acknowledgement: it never receives the credential the action needed, or the
  material that credential unlocks. See `enclave/src/services/actions.rs`.
- **One write** -- `record_decision`, and only under a grant whose scope says
  `may_write`. Deny-by-default, so every grant issued before that field existed
  is read-only. What an agent writes takes the `agent` source whatever it asks
  for, and carries a precedence class taken from the grant rather than from the
  agent: without `may_supersede_owner` its claim *contradicts* the person's
  rather than replacing it. See ADR 0017 and `graphs/decide.py`.

## Two transports, and why the choice matters

``python -m orchestrator.mcp_server`` speaks **stdio**, which is what a local
agent spawns as a subprocess. That is the whole story when the harness and the
agent are on the same machine.

They are not, for a hosted harness. The point of this layer is that several
agents on several devices share one graph, and stdio cannot express that: each
device would run its own orchestrator and they could only "share" memory by all
pointing at one database over the network, which means shipping database
credentials to every device and losing the gateway as a boundary. Worse than the
single-machine story, not better.

So this module also serves **streamable HTTP**, mounted into the orchestrator's
own FastAPI app at ``/mcp`` when ``MCP_HTTP_ENABLED`` is set.

**Off by default, deliberately.** Turning it on takes a surface reachable only by
a process on the same machine and makes it reachable by anything that can open a
socket to the orchestrator. Nothing is disclosed by that -- every tool below takes
a ``grant_token`` and refuses without one, so there is no ambient authority to
borrow -- but an unauthenticated caller can still list the tools and probe them,
and that is a deployment decision rather than a default.

Run with:

    python -m orchestrator.mcp_server                 # stdio, for a local agent
    MCP_HTTP_ENABLED=1 python -m orchestrator.api     # http, at /mcp
"""

from __future__ import annotations

import logging

from mcp.server.mcpserver import MCPServer

from .graphs.act import request_action as act
from .graphs.brief import SealedBriefingUnsupported
from .graphs.brief import brief_before_acting as brief
from .graphs.decide import WriteRefused, consolidate_session
from .graphs.decide import record_decision as decide
from .graphs.history import context_chain, why_did_this_shift
from .graphs.query import run_query
from .graphs.reason import SubjectNotFound, reason_about
from .graphs.runtime import Runtime

log = logging.getLogger(__name__)

#: The server object. `MCPServer` is what `FastMCP` was renamed to in the SDK's
#: 2.0; the decorator and `run()` surface is the same. The name is what a client
#: lists the server under, so it is the one an owner reads in their MCP config.
mcp = MCPServer("kleos")

_runtime: Runtime | None = None


def _get_runtime() -> Runtime:
    global _runtime
    if _runtime is None:
        _runtime = Runtime.build()
    return _runtime


def set_runtime(runtime: Runtime) -> None:
    """Hands this module a `Runtime` someone else already built.

    Used when the tools are mounted into the orchestrator's FastAPI app rather
    than run as their own process. Without it the two would each call
    `Runtime.build()` in the same interpreter, which means two Neo4j driver
    pools, two Redis connections and -- the one that actually hurts -- two copies
    of the embedding model resident in memory.
    """
    global _runtime
    _runtime = runtime


@mcp.tool()
def query_memory(question: str, grant_token: str, top_k: int = 8) -> dict:
    """Query the owner's memory within the scope of a grant token.

    Returns an answer with citations, or an explicit refusal listing why
    each candidate was out of scope. A refusal is a real answer: the tool
    never guesses at what it was not allowed to read.
    """
    answer = run_query(_get_runtime(), question, grant_token, top_k=top_k)
    return answer.as_dict()


@mcp.tool()
def why_this_shifted(claim_id: str, grant_token: str) -> dict:
    """Why a decision changed: the ordered supersession chain for one claim,
    and at each step the citations that appear in the superseding claim and
    not in the one it replaced -- the evidence that moved the decision.

    Accepts the current claim, the original, or anything in between. Links a
    grant does not cover come back withheld, with a reason and no content,
    rather than being silently dropped from the chain.
    """
    return why_did_this_shift(_get_runtime(), claim_id, grant_token).as_dict()


@mcp.tool()
def memory_context_chain(object_id: str, grant_token: str, hops: int = 3) -> dict:
    """What an object was derived from and what was derived from it, walked
    over citation edges. Chains cross sources wherever the material does.
    """
    return context_chain(_get_runtime(), object_id, grant_token, hops=hops).as_dict()


# -- session state ------------------------------------------------------


@mcp.tool()
def open_session(grant_token: str) -> dict:
    """Opens a working session for the agent presenting this grant.

    The session id is minted here, never accepted from the caller: an
    agent-chosen id is an unauthenticated string two agents could collide on,
    and attribution is the whole point of having one.

    `identity_basis` says how much the returned identity is worth. `device_key`
    means the gateway verified an Ed25519 signature against a key the owner
    registered -- rely on it. `label` means the gateway did not report a key, so
    all that is known is the `agent_id` the owner typed into the scope before
    signing it, which nothing authenticates.
    """
    runtime = _get_runtime()
    resolved = runtime.gateway.introspect_grant(grant_token)
    settings = runtime.settings
    session = runtime.sessions.open_session(
        owner_id=resolved.scope.owner_id,
        agent_id=resolved.scope.agent_id,
        device_id=resolved.device_id,
        grant_fp=resolved.grant_fp,
        ttl_secs=settings.agent_session_ttl_secs,
        grant_expires_at_ms=resolved.scope.expires_at_ms,
    )
    return {
        "session_id": session.id,
        "agent_id": session.agent_id,
        "device_id": session.device_id,
        "identity_basis": "device_key" if resolved.device_id else "label",
        "expires_at_ms": session.expires_at_ms,
        "max_blocks": settings.agent_session_max_blocks,
        "max_bytes": settings.agent_session_max_bytes,
    }


@mcp.tool()
def append_context(session_id: str, grant_token: str, block: str) -> dict:
    """Appends one block of working context to this session.

    A block is whatever the agent is currently working from: the turn it just
    took, what a tool returned, a scratchpad, the contents of a file it opened.
    It is stored sealed and is **not** retrievable as memory -- nothing here
    reaches the vector index until `close_session` consolidates it.

    Deliberately **not** gated on a write-capable grant. Appending to your own
    scratchpad produces nothing searchable, nothing carrying an ACL and nothing
    the resolver sees; the grant that opened the session is what permits it. The
    write gate is for the tool that mints a claim.

    A block over the byte cap is refused rather than truncated: a truncated
    scratchpad is one that silently lost the part the decision turned on.
    """
    runtime = _get_runtime()
    resolved = runtime.gateway.introspect_grant(grant_token)
    settings = runtime.settings
    stored = runtime.sessions.append_block(
        owner_id=resolved.scope.owner_id,
        session_id=session_id,
        block=block,
        max_blocks=settings.agent_session_max_blocks,
        max_bytes=settings.agent_session_max_bytes,
    )
    return {
        "session_id": session_id,
        "block_index": stored.index,
        "byte_len": stored.byte_len,
        "searchable": False,
    }


@mcp.tool()
def close_session(session_id: str, grant_token: str, consolidate: bool = False) -> dict:
    """Closes the session. Its blocks stay stored and stay unsearchable.

    `consolidate=True` reads this session's blocks back and keeps whatever it
    concluded that outlives the session -- as ordinary claims, kinded, attributed
    to this device, and resolvable against the person's own decisions. It needs
    the same `may_write` a direct write does, because the outcome is identical: a
    claim in the person's record. A session is not a licence to write.

    **Most sessions conclude nothing, and `consolidate=False` is the right
    default.** A session that decided nothing should leave nothing in the
    person's memory, and what an agent definitely wants remembered it says
    outright with `record_decision` rather than hoping consolidation notices.

    Consolidation happens **before** the close, so a failure leaves the session
    open and retryable rather than closed with its work lost.
    """
    runtime = _get_runtime()
    resolved = runtime.gateway.introspect_grant(grant_token)
    consolidated = None
    if consolidate:
        consolidated = consolidate_session(runtime, grant_token, session_id)
    session = runtime.sessions.close(resolved.scope.owner_id, session_id)
    return {
        "session_id": session.id,
        "closed_at_ms": session.closed_at_ms,
        "block_count": session.block_count,
        "consolidated_into": list(session.consolidated_into),
        "consolidation": consolidated.as_dict() if consolidated else None,
    }


# -- before acting ------------------------------------------------------


@mcp.tool()
def brief_before_acting(
    intent: str,
    grant_token: str,
    session_id: str | None = None,
    top_k: int = 8,
    include_body: bool = False,
) -> dict:
    """Find out what is already decided about what you are about to do.

    Call this **before** acting, with an intent rather than a question -- "I am
    about to pick a database for Lantern" -- because the thing you most need to
    know is the thing you do not know to ask about.

    Returns what is relevant with citations, any supersession chains those claims
    sit in, who changed each one and on what basis, and `advisories`: one
    rendered line each, ready to put straight into your context without parsing
    anything.

    Every advisory names the **device** and says whether that identity is
    authenticated. `device-authenticated` means the gateway verified a signature
    against a key the owner registered; "label only" means all that is known is a
    string the owner typed, which nothing checks.

    A conflicting decision outside your grant comes back as *withheld* rather
    than omitted: you are told it exists and that you may not read it. An agent
    told "no conflicts" acts; an agent told "a conflict you cannot see" asks.

    `include_body` asks for the raw material behind what was disclosed, and needs
    a grant that also says `may_unseal` -- seeing a resolved claim and reading the
    transcript it came from are different disclosures.

    There is deliberately no structure in the result: no adjacency, no node
    lists. An agent that could walk the graph could map a memory it cannot read.

    **Unavailable against a store whose content is sealed at rest.** A briefing
    writes its advisories from the claims' own text, and since ADR 0024 that
    text exists only inside the enclave. Comes back as `refused` with the
    reason, and `query_memory` is the tool that works -- it relays an answer
    sealed to your device.
    """
    try:
        briefing = brief(
            _get_runtime(),
            intent,
            grant_token,
            session_id=session_id,
            top_k=top_k,
            include_body=include_body,
        )
    except SealedBriefingUnsupported as refused:
        # Returned rather than raised, for the reason `record_decision` gives
        # below: an exception crossing MCP reaches the agent as "Error executing
        # tool" with the reason stripped, and an agent that cannot tell a
        # refusal from a bug retries the bug.
        return {
            "refused": True,
            "reason": "content_sealed_at_rest",
            "detail": str(refused),
        }
    return {"refused": False, **briefing.as_dict()}


# -- writing ------------------------------------------------------------


@mcp.tool()
def record_decision(
    grant_token: str,
    statement: str,
    reason: str,
    session_id: str | None = None,
    memory_kind: str = "episodic",
    sensitive: bool = False,
) -> dict:
    """Record a decision you have just made, and why, into the owner's memory.

    `statement` is the decision as a durable assertion -- "Lantern uses Neo4j"
    rather than "I think we should probably use Neo4j". `reason` is **required**:
    the next agent's briefing is built out of it, and a stored decision with no
    stated basis tells that agent nothing it can act on.

    `memory_kind` is `episodic` (what was decided), `procedural` (how something
    is done) or `tacit` (a heuristic drawn from experience). A tacit claim is an
    inference *about* the person rather than something they said, so labelling
    one raises its sensitivity and the grant is checked at that level.

    Refused unless the grant says `may_write`, and the refusal names the reason.
    Your claim is recorded as `reference` unless the grant also says
    `may_supersede_owner`, in which case it is a `delegate` write -- the
    difference being whether it may replace one of the owner's own decisions or
    only contradict it, visibly, with both sides kept.
    """
    try:
        recorded = decide(
            _get_runtime(),
            grant_token,
            statement,
            reason,
            session_id=session_id,
            memory_kind=memory_kind,
            sensitive=sensitive,
        )
    except WriteRefused as refused:
        # **Returned, not raised.** An exception crossing MCP reaches the agent
        # as "Error executing tool record_decision" with the reason stripped, so
        # a refusal becomes indistinguishable from a bug -- and the whole point
        # of carrying deny reasons is that a decline is a real answer. Found by
        # driving a real client; an in-process test calls the function and sees
        # the exception intact, which is exactly the layer it cannot check.
        return {
            "refused": True,
            "reason": refused.reason,
            "detail": str(refused),
        }
    return {"refused": False, **recorded.as_dict()}


@mcp.tool()
def reason_across_sessions(grant_token: str, subject: str) -> dict:
    """Ask the harness what the sessions about one subject add up to.

    Everything else here reasons narrowly: a decision is resolved against stored
    claims one at a time, and a session is consolidated with only its own blocks
    in view. This looks at **every claim about one subject**, across every
    session and every device that wrote one, and asks what holds across them
    that no single claim says.

    `subject` is a name memory already knows -- a project, an artifact, a topic.
    Matched the way canonicalisation matches entities, so "Lantern" and "project
    Lantern" and a stored alias all reach the same subject.

    **What comes back is written as claims, not prose.** Each conclusion goes
    into the record as an ordinary claim, which means a later pass can supersede
    it and the resolver compares it against what is already stored. Its
    authority is `reference` whatever your grant says: an inference the harness
    drew may contradict what somebody decided, visibly and with both sides kept,
    and may never replace it.

    They are attributed to **the harness**, with `identity_basis: derived` --
    nobody asserted them. A briefing renders them as such, and an agent reading
    one should weigh it accordingly: these are the lines to push back on.

    Declines with `declined` set when fewer than two sessions have written about
    the subject, because one session's claims were already reasoned over when it
    closed. Concluding nothing is a normal outcome and comes back as `ran: true`
    with an empty `conclusions`. Reaching the same conclusions a previous pass
    already recorded comes back as `conclusions` present, `written` empty and no
    `errors` -- the pass is idempotent, so running it again is cheap and safe.

    Needs `may_write`: this writes to the record.
    """
    try:
        result = reason_about(_get_runtime(), grant_token, subject)
    except SubjectNotFound as missing:
        # Returned rather than raised, for the reason `record_decision` gives:
        # an exception crossing MCP arrives with its message stripped, and "the
        # subject is not in memory yet" is an answer rather than a fault.
        return {"refused": True, "reason": "subject_not_found", "detail": str(missing)}
    except WriteRefused as refused:
        return {"refused": True, "reason": refused.reason, "detail": str(refused)}
    return {"refused": False, **result.as_dict()}


# -- acting -------------------------------------------------------------


@mcp.tool()
def request_action(
    action_id: str,
    grant_token: str,
    args: dict | None = None,
    session_id: str | None = None,
) -> dict:
    """Ask for something sensitive to be *done* on the owner's behalf.

    You submit an intent -- which action, with which arguments -- and receive an
    **acknowledgement**: whether it happened, a digest over what it did, and one
    line of summary. You do not receive the credential the action needed, and you
    do not receive the material that credential unlocks. The work happens inside
    the enclave, which resolves the credential itself and drops it before
    replying.

    Needs a grant that says `may_act` **and** names this `action_id`. Both,
    because a grant saying only the first would be a grant to do anything the
    build knows how to do.

    The action list is compiled into the enclave, so an unknown id is refused and
    the refusal says what *is* known. A refusal comes back as `ok: false` rather
    than as an error, because an attempt made and failed is a different fact from
    an attempt never made -- and both are recorded against your device.

    If a result is too large to summarise it comes back as a sealed reference
    rather than as content, and reading it needs a grant that also says
    `may_unseal`: acknowledgement by default, disclosure as a second step.
    """
    result = act(
        _get_runtime(),
        grant_token,
        action_id,
        args or {},
        session_id=session_id,
    )
    return result.as_dict()


def http_app(path: str = "/", host: str = "127.0.0.1"):
    """The tools as an ASGI app, for mounting into the orchestrator.

    `path` is the route *inside* this app, so the default of "/" plus a mount at
    "/mcp" puts the endpoint exactly where a client expects it. Building it at
    "/mcp" and mounting at "/" would work too and would put the MCP routes in the
    same table as the memory API, where a future route could shadow one.

    DNS-rebinding protection is left on (the SDK's default). It is the check that
    stops a page the owner happens to visit from scripting requests to a harness
    listening on their own machine, which is the realistic attack on a local
    HTTP server and costs nothing to keep.

    Calling this is also what creates the session manager, which the caller must
    then run -- see `session_manager` below.
    """
    return mcp.streamable_http_app(streamable_http_path=path, host=host)


def session_manager():
    """The session manager for the app `http_app` built.

    Separate because it does not exist until then: the SDK creates it lazily and
    raises if asked for it first. The host application has to enter its
    `run()` in its own lifespan, or every request gets a session manager that was
    never started.
    """
    return mcp.session_manager


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
