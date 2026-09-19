"""The registry of known sources.

Source *ids* are open (see ``enums.SourceId``): the enclave, and everything
else on the trust path, treats them as opaque strings so that adding a
connector never changes the measurement an attestation commits to. Which
sources this deployment actually knows how to fetch is a host-side product
concern, and this is where it lives.

Adding a connector is: write the module, declare a ``ConnectorSpec``,
register it. Nothing in Rust, ``enums.py``, ``retrieval/`` or the graphs
has to change.
"""

from __future__ import annotations

from pydantic import TypeAdapter

from ..config import Settings
from ..enums import SourceId
from .base import Chunker, ConnectorSpec, SourceConnector, default_chunker

__all__ = [
    "REGISTRY",
    "ConnectorRegistry",
    "UnknownSourceError",
    "register",
]


_SOURCE_ID = TypeAdapter(SourceId)


class UnknownSourceError(LookupError):
    """Raised for a source id no connector is registered for."""

    def __init__(self, source: str, known: list[str]) -> None:
        self.source = source
        self.known = known
        super().__init__(f"unknown source {source!r}; known sources: {', '.join(known) or 'none'}")


class ConnectorRegistry:
    def __init__(self, specs: dict[str, ConnectorSpec] | None = None) -> None:
        self._specs: dict[str, ConnectorSpec] = dict(specs or {})

    def register(self, spec: ConnectorSpec) -> ConnectorSpec:
        # Loud on both failure modes: a malformed id would be accepted by the
        # store and then never match a grant scope, and a duplicate would
        # silently shadow whichever connector lost the import race.
        _SOURCE_ID.validate_python(spec.source_id)
        if spec.oauth_scopes and not spec.requires_oauth:
            raise ValueError(f"{spec.source_id!r} declares oauth scopes but not requires_oauth")
        existing = self._specs.get(spec.source_id)
        if existing is not None and existing is not spec:
            raise ValueError(f"source {spec.source_id!r} is already registered")
        self._specs[spec.source_id] = spec
        return spec

    def spec(self, source: str) -> ConnectorSpec:
        try:
            return self._specs[source]
        except KeyError:
            raise UnknownSourceError(source, self.ids()) from None

    def __contains__(self, source: object) -> bool:
        return source in self._specs

    def ids(self) -> list[str]:
        return sorted(self._specs)

    def specs(self) -> list[ConnectorSpec]:
        return [self._specs[i] for i in self.ids()]

    def copy(self) -> ConnectorRegistry:
        """An independent registry seeded with the same specs.

        Lets a caller (a test, or a per-tenant deployment) add a connector
        without mutating process-global state.
        """
        return ConnectorRegistry(self._specs)

    def connector(self, source: str, settings: Settings) -> SourceConnector:
        """Builds the connector for ``source``.

        Mock mode applies per source, not globally: a source gets its fixture
        stand-in only if it declared one. Previously every source in mock mode
        returned the mock fixtures, so a half-finished connector looked like it
        worked. A source with no fixture now behaves the same in both modes --
        for the Google/GitHub stubs that means raising, which is the truth.
        """
        spec = self.spec(source)
        if settings.use_fixture_connectors and spec.mock_factory is not None:
            return spec.mock_factory(settings)
        return spec.factory(settings)

    def chunker(self, source: str) -> Chunker:
        """The source's chunker, or the default for an unregistered source.

        Deliberately total: chunking runs at retrieval time, long after ingest
        reported success, and is the wrong place to discover a missing
        registration.
        """
        spec = self._specs.get(source)
        return spec.chunker if spec is not None else default_chunker


#: Process-wide registry of the connectors this build ships with.
REGISTRY = ConnectorRegistry()


def register(spec: ConnectorSpec) -> ConnectorSpec:
    return REGISTRY.register(spec)


def _register_builtins() -> None:
    from .chatgpt import SPEC as CHATGPT_SPEC
    from .github import SPEC as GITHUB_SPEC
    from .google import SPEC as GOOGLE_SPEC
    from .mock import SPEC as MOCK_SPEC

    for spec in (MOCK_SPEC, GOOGLE_SPEC, GITHUB_SPEC, CHATGPT_SPEC):
        REGISTRY.register(spec)


_register_builtins()
