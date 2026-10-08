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

Run with: ``python -m orchestrator.mcp_server`` (stdio transport).
"""

from __future__ import annotations

import logging

from mcp.server.mcpserver import MCPServer

from .graphs.history import context_chain, why_did_this_shift
from .graphs.query import run_query
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

    `consolidate=False` is a real and correct outcome, not a degenerate one: a
    session that decided nothing should leave nothing in the person's memory.
    What an agent wants remembered it says with `record_decision`.
    """
    runtime = _get_runtime()
    resolved = runtime.gateway.introspect_grant(grant_token)
    if consolidate:
        # Raises rather than quietly closing without consolidating, which would
        # make "I asked for my work to be kept" look like it had been.
        raise NotImplementedError(
            "consolidation is not wired yet: closing with consolidate=True would "
            "silently keep nothing. Use record_decision for what should be "
            "remembered, and close with consolidate=False."
        )
    session = runtime.sessions.close(resolved.scope.owner_id, session_id)
    return {
        "session_id": session.id,
        "closed_at_ms": session.closed_at_ms,
        "block_count": session.block_count,
        "consolidated_into": list(session.consolidated_into),
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
