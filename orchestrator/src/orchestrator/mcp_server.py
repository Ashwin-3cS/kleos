"""MCP server exposing the query graph as a tool.

This is the product surface: an authorized agent connects over MCP and asks
questions of a person's memory. It intentionally exposes only the query
path -- there is no MCP tool that writes memory, and none that reads without
a grant token, because the grant is the whole permission story.

Run with: ``python -m orchestrator.mcp_server`` (stdio transport).
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from .graphs.query import run_query
from .graphs.runtime import Runtime

log = logging.getLogger(__name__)

mcp = FastMCP("memorai")

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


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
