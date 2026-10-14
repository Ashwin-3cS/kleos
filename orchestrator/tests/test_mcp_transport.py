"""The two properties that make serving MCP over HTTP defensible.

Over stdio these tools are reachable only by a process on the same machine, so
the transport itself is the access control. Over HTTP they are reachable by
anything that can open a socket, and the access control has to be in the tools.

It is: every one of them takes a grant token and refuses without it. There is no
ambient authority to borrow, which is why exposing the endpoint discloses
nothing on its own. Both halves of that are asserted here, because both are the
kind of thing a later convenience quietly breaks -- a tool added without a grant
argument, or a default flipped to make local development smoother.

The transports themselves are exercised by `scripts/mcp_smoke.py`, which runs
the *same scenario* over both against a real client. That is where drift between
them would show up; this file is about the invariants that hold before either
transport is chosen.
"""

from __future__ import annotations

import inspect

from orchestrator import mcp_server
from orchestrator.config import Settings

#: Every tool the server exposes. Mirrors `EXPECTED_TOOLS` in `mcp_smoke.py`.
TOOLS = [
    "query_memory",
    "why_this_shifted",
    "memory_context_chain",
    "open_session",
    "append_context",
    "close_session",
    "brief_before_acting",
    "record_decision",
    "request_action",
]


def test_every_tool_requires_a_grant_token() -> None:
    """The property that makes the HTTP endpoint safe to expose.

    Not "most tools" and not "the ones that read" -- *every* one, with no default,
    so a call that omits it fails at the signature rather than somewhere deeper
    under an identity nobody checked. A tool added here without a grant argument
    would be callable by anyone who can reach the port.
    """
    for name in TOOLS:
        func = getattr(mcp_server, name)
        params = inspect.signature(func).parameters
        assert "grant_token" in params, f"{name} takes no grant token"
        assert params["grant_token"].default is inspect.Parameter.empty, (
            f"{name} has a default grant token, so it can be called without one"
        )


def test_no_tool_takes_an_owner_session() -> None:
    """The other direction. An owner session authorises the read log, the
    mutation log and device registration -- things an *agent* must never reach,
    because they disclose what other agents have been doing. A tool accepting one
    would be a path from an agent to the owner's own view."""
    for name in TOOLS:
        params = inspect.signature(getattr(mcp_server, name)).parameters
        assert "session_token" not in params, (
            f"{name} accepts an owner session; agents authenticate with grants"
        )


def test_http_is_off_unless_someone_turned_it_on() -> None:
    """A default that flips is how a local-only surface becomes a public one
    without anybody deciding to make it public."""
    assert Settings().mcp_http_enabled is False


def test_the_http_app_serves_the_tools_at_the_mount_root() -> None:
    """Built at "/" so a mount at "/mcp" puts the endpoint where a client expects
    it. Building it at "/mcp" and mounting at "/" would also work and would put
    the MCP routes in the same table as the memory API, where a later route could
    shadow one."""
    app = mcp_server.http_app()
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/" in paths, paths

    # Created lazily by the call above, and the host application has to run it.
    # Asking before building raises, which is why these are two functions.
    assert mcp_server.session_manager() is not None


def test_the_tools_share_a_runtime_rather_than_building_a_second(settings, store) -> None:
    """Two `Runtime.build()` calls in one interpreter mean two Neo4j driver
    pools, two Redis connections and two copies of the embedding model resident
    in memory. Mounted into the orchestrator, the tools take the one it built."""
    from orchestrator.graphs.runtime import Runtime

    runtime = Runtime.build(settings=settings, migrate=False)
    try:
        mcp_server.set_runtime(runtime)
        assert mcp_server._get_runtime() is runtime
    finally:
        mcp_server._runtime = None
        runtime.close()
