"""What a tool is.

A tool is something the system can *do* on the person's behalf, as opposed to a
connector, which is somewhere data comes *from*. The distinction matters because
they fail differently: a connector that cannot reach its source has nothing to say
and that is the end of it, while a tool reaches outward on demand, can be pointed at
anything, and is therefore the first thing in this service that an attacker can
influence the behaviour of.

The shape mirrors `connectors/base.py` deliberately rather than inventing a second
plugin pattern. One spec object, one registry, declared next to the implementation,
so adding a tool is one module plus one registration -- and so that `ENABLED_TOOLS`
can narrow a deployment the way `ENABLED_SOURCES` already narrows one.

Every tool returns a `ToolResult` rather than raising on failure. A tool failing is
an ordinary outcome -- a page is gone, a host is down -- and the thing that calls
tools has to be able to record the attempt either way. Raising would make "it was
tried and did not work" indistinguishable from "it was never tried", which is
exactly the distinction a trace needs to keep.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..config import Settings


@dataclass(frozen=True, slots=True)
class ToolResult:
    """The outcome of one tool call.

    Uniform across tools so that whatever drives them -- the ingestion graph today,
    an agentic loop later -- can record an attempt without knowing which tool it
    was. ``digest`` exists for that record: a trace should say what came back
    without copying it, because a trace store that holds every fetched page is a
    second uncontrolled copy of the open web.
    """

    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    #: Short, loggable summary of what came back. Never the payload itself.
    digest: str = ""

    @classmethod
    def failed(cls, error: str) -> ToolResult:
        return cls(ok=False, error=error, digest=error[:200])


@runtime_checkable
class Tool(Protocol):
    """Tools are dumb on purpose, exactly as connectors are.

    A tool does one thing and reports what happened. Deciding *whether* to call it,
    what to do with the result, and whether the result is trustworthy all belong to
    the caller -- which is what keeps a tool from quietly becoming a place where
    policy lives.
    """

    name: str

    def run(self, **kwargs: Any) -> ToolResult: ...


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Everything the rest of the service needs to know about one tool.

    Declared beside the implementation so adding a tool touches one module and one
    registration, and nothing in the graphs, the schema, or Rust.
    """

    tool_id: str
    display_name: str
    factory: Callable[[Settings], Tool]
    #: One line, written for whoever or whatever is choosing a tool. This becomes
    #: the description an agent sees when the loop lands, so it describes the
    #: effect rather than the implementation.
    description: str = ""
    #: Whether a successful call can put something into memory. False for every
    #: tool here today: `fetch_url` and `extract_page` both only *produce*
    #: candidates, and the ingestion graph decides what is written. Kept explicit
    #: because "which tools can write" is the question an audit asks first, and it
    #: should be answerable from the registry rather than by reading code.
    writes_memory: bool = False
    #: Whether a call reaches outside this machine. Separate from `writes_memory`
    #: because they are different risks: one can be influenced by a stranger, the
    #: other changes the record.
    reaches_network: bool = False
