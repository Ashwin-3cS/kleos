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
    "reason_across_sessions",
    "brief_before_acting",
    "request_action",
}

#: Names that must never appear. Each is a decision with its reason recorded in
#: `mcp_server`'s module docstring or the root README.
#: The writes, so the absence of any other stays deliberate. Both of these reach
#: the record through `record_decision`; see `test_every_write_goes_through_the_gate`.
WRITES = {"record_decision", "reason_across_sessions"}

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


def test_only_the_declared_tools_write() -> None:
    """A write tool is a decision, not an implementation detail: the write gate,
    the precedence class and the `agent` source are all enforced in one place,
    and a tool that wrote by another route would bypass all three.

    There are two now. `reason_across_sessions` (ADR 0025) writes the harness's
    own cross-session conclusions -- and writes them *through* `record_decision`,
    which is what keeps "one place" true with two entry points. The next test
    is the one that checks that, rather than trusting this list.
    """
    writes = _tool_names() & WRITES
    assert writes == WRITES
    suspicious = {
        n for n in _tool_names() - WRITES if any(
            v in n for v in ("write", "store", "remember", "upsert", "delete", "ingest")
        )
    }
    assert not suspicious, f"these look like write paths: {suspicious}"


def test_a_refusal_is_returned_rather_than_raised() -> None:
    """An exception crossing MCP reaches the agent as "Error executing tool
    record_decision" with the reason stripped, which is indistinguishable from a
    bug -- and the whole point of carrying deny reasons is that a decline is a
    real answer.

    Asserted on the source, because the behaviour only differs over the
    transport: an in-process caller sees the exception intact either way, which
    is exactly why this went unnoticed until a real client was pointed at it.
    """
    import inspect

    source = inspect.getsource(mcp_server.record_decision)
    assert "except WriteRefused" in source, (
        "record_decision must catch its refusal and return it"
    )
    assert '"refused": True' in source


def test_every_write_goes_through_the_gate() -> None:
    """Two tools write, and only one write path exists.

    `WRITES` above is a list someone maintains, so on its own it says nothing
    about whether a second write tool actually reuses the gate or merely claims
    to. This reads the source: a write tool that reached the store directly
    would decide `may_write`, the `agent` source and the precedence class for
    itself, and the first two of those are the whole of ADR 0017.
    """
    import inspect

    from orchestrator.graphs import reason as reason_graph

    assert "record_decision(" in inspect.getsource(reason_graph.reason_about), (
        "reason_about must write through record_decision, not around it"
    )
    # And as a derived write specifically: without this it would take its
    # precedence class from `may_supersede_owner` like an agent's own decision,
    # which is exactly what ADR 0025 forbids for an inference nobody asserted.
    assert "derived=True" in inspect.getsource(reason_graph.reason_about)


def test_the_reasoning_tool_returns_its_refusals() -> None:
    """Same reason as `record_decision`'s: a refusal that crosses MCP as an
    exception arrives with its message stripped, and both of this tool's
    declines -- an unknown subject and a grant that may not write -- are answers
    rather than faults."""
    import inspect

    source = inspect.getsource(mcp_server.reason_across_sessions)
    assert "except SubjectNotFound" in source
    assert "except WriteRefused" in source
    assert source.count('"refused": True') >= 2
