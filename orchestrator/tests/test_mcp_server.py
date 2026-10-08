"""The MCP tool surface, asserted rather than assumed.

This module had never been imported by anything. `mcp>=1.2` in `pyproject.toml`
silently allowed the SDK major that renamed `FastMCP` to `MCPServer`, so the
server could not load at all -- and nothing noticed, because no test touched it
and it had never been driven from a real client.

What this file holds is the shape of the surface: which tools exist, and which
deliberately do not. Both halves matter. The absences are decisions -- no
neighbourhood tool (it would be a structure-enumeration primitive), no read-log
tool (an agent would see what other agents were shown) -- and a decision that is
only recorded in a docstring is one the next person removes by accident.
"""

from __future__ import annotations

import asyncio

from orchestrator import mcp_server

#: Every tool an agent can call, and nothing else.
EXPECTED = {
    "query_memory",
    "why_this_shifted",
    "memory_context_chain",
    "open_session",
    "append_context",
    "close_session",
    "record_decision",
    "brief_before_acting",
}

#: Names that must never appear. Each is a decision with its reason recorded in
#: `mcp_server`'s module docstring or the root README.
#: The one write, so the absence of the others stays deliberate.
WRITES = {"record_decision"}

FORBIDDEN = {
    "memory_neighbourhood",  # a cheap seed-walk-reseed structure enumerator
    "neighbourhood",
    "agent_reads",  # one agent reading what other agents were shown
    "read_log",
    "memory_mutations",  # the same, for writes
}


def _tool_names() -> set[str]:
    return {tool.name for tool in asyncio.run(mcp_server.mcp.list_tools())}


def test_the_server_imports_and_registers_its_tools() -> None:
    """The regression this file exists for: the module loading at all."""
    assert _tool_names() == EXPECTED


def test_no_tool_reads_without_a_grant_token() -> None:
    """The grant is the whole permission story, so every tool has to carry one.
    A tool that resolved a session id alone would be an authentication channel
    MCP does not actually have."""
    for tool in asyncio.run(mcp_server.mcp.list_tools()):
        params = tool.input_schema.get("properties", {})
        assert "grant_token" in params, f"{tool.name} takes no grant token"
        assert "grant_token" in tool.input_schema.get("required", []), (
            f"{tool.name} treats its grant token as optional"
        )


def test_the_deliberate_absences_stay_absent() -> None:
    assert _tool_names() & FORBIDDEN == set()


def test_every_tool_documents_itself() -> None:
    """The description is what a plugged-in agent reads to decide whether to call
    it, so an undocumented tool is one that gets called wrongly."""
    for tool in asyncio.run(mcp_server.mcp.list_tools()):
        assert tool.description and len(tool.description) > 40, tool.name


def test_only_one_tool_writes() -> None:
    """A second write tool is a decision, not an implementation detail: the write
    gate, the precedence class and the `agent` source are all enforced in one
    place, and a tool that wrote by another route would bypass all three."""
    writes = _tool_names() & WRITES
    assert writes == WRITES
    suspicious = {
        n for n in _tool_names() - WRITES if any(
            v in n for v in ("write", "store", "remember", "upsert", "delete", "ingest")
        )
    }
    assert not suspicious, f"these look like write paths: {suspicious}"
