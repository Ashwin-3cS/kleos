"""The registry of tools this build can run.

Mirrors `connectors/registry.py` closely and on purpose. The connector registry
already solved this problem -- declare a spec beside the implementation, validate the
id, reject duplicates loudly, allow a per-run copy, narrow a deployment with an
allow-list -- and a second plugin pattern with different semantics would be a second
thing to keep correct for no gain.

One difference worth naming: a tool id is validated against the same rules as a
source id (`[a-z0-9_-]`, 1-64 chars). Source ids are validated because they are
compared as opaque strings inside a permission check, where a case or whitespace
variant would look identical in a grant UI and never match. Tool ids are not in that
check today, and they are validated anyway, because `ENABLED_TOOLS` compares them the
same way and the day a grant scopes tools the rule will already hold.
"""

from __future__ import annotations

from pydantic import TypeAdapter

from ..config import Settings
from ..enums import SourceId
from .base import Tool, ToolSpec

__all__ = [
    "REGISTRY",
    "ToolRegistry",
    "UnknownToolError",
    "register",
]

_TOOL_ID = TypeAdapter(SourceId)


class UnknownToolError(LookupError):
    """Raised for a tool id nothing is registered for."""

    def __init__(self, tool: str, known: list[str]) -> None:
        self.tool = tool
        self.known = known
        super().__init__(f"unknown tool {tool!r}; known tools: {', '.join(known) or 'none'}")


class ToolRegistry:
    def __init__(self, specs: dict[str, ToolSpec] | None = None) -> None:
        self._specs: dict[str, ToolSpec] = dict(specs or {})

    def register(self, spec: ToolSpec) -> ToolSpec:
        # Loud on both failure modes, for the reasons the connector registry is:
        # a malformed id would never match an allow-list, and a duplicate would
        # silently shadow whichever registration lost the import race.
        _TOOL_ID.validate_python(spec.tool_id)
        existing = self._specs.get(spec.tool_id)
        if existing is not None and existing is not spec:
            raise ValueError(f"tool {spec.tool_id!r} is already registered")
        self._specs[spec.tool_id] = spec
        return spec

    def spec(self, tool: str) -> ToolSpec:
        try:
            return self._specs[tool]
        except KeyError:
            raise UnknownToolError(tool, self.ids()) from None

    def __contains__(self, tool: object) -> bool:
        return tool in self._specs

    def ids(self) -> list[str]:
        return sorted(self._specs)

    def specs(self) -> list[ToolSpec]:
        return [self._specs[i] for i in self.ids()]

    def copy(self) -> ToolRegistry:
        """An independent registry seeded with the same specs.

        Lets a test, or a per-tenant deployment, add or withhold a tool without
        mutating process-global state.
        """
        return ToolRegistry(self._specs)

    def tool(self, tool_id: str, settings: Settings) -> Tool:
        """Builds the tool, refusing one this deployment has switched off.

        Checked here rather than at the call site so that a disabled tool cannot be
        reached by any path -- an allow-list enforced in one place out of three is
        not an allow-list.
        """
        spec = self.spec(tool_id)
        if not settings.tool_enabled(tool_id):
            raise UnknownToolError(tool_id, self.enabled_ids(settings))
        return spec.factory(settings)

    def enabled_ids(self, settings: Settings) -> list[str]:
        return [i for i in self.ids() if settings.tool_enabled(i)]


#: Process-wide registry of the tools this build ships with.
REGISTRY = ToolRegistry()


def register(spec: ToolSpec) -> ToolSpec:
    return REGISTRY.register(spec)


def _register_builtins() -> None:
    from .extract_page import SPEC as EXTRACT_PAGE_SPEC
    from .fetch_url import SPEC as FETCH_URL_SPEC

    for spec in (FETCH_URL_SPEC, EXTRACT_PAGE_SPEC):
        REGISTRY.register(spec)


_register_builtins()
