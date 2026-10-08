"""The tool registry, and the conditional edge that decides whether to use it.

The registry mirrors the connector registry on purpose, so these tests mirror
`test_connector_registry.py`: the property worth holding is that a tool is one module
plus one registration, and that a deployment can switch one off in a place that every
path goes through.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.tools.base import ToolResult, ToolSpec
from orchestrator.tools.registry import (
    REGISTRY,
    ToolRegistry,
    UnknownToolError,
)

OWNER = "owner-tools"


class _Recorder:
    """A tool that exists only in this file, which is the property being tested."""

    name = "recorder"

    def __init__(self, settings: Settings) -> None:
        self.calls: list[dict] = []

    def run(self, **kwargs) -> ToolResult:
        self.calls.append(kwargs)
        return ToolResult(ok=True, data={"echo": kwargs}, digest="recorded")


RECORDER_SPEC = ToolSpec(
    tool_id="recorder",
    display_name="Recorder",
    factory=_Recorder,
    description="Records the arguments it was called with.",
)


def test_the_builtin_tools_are_registered() -> None:
    assert "fetch_url" in REGISTRY
    assert "extract_page" in REGISTRY


def test_every_tool_declares_what_it_can_do() -> None:
    """"Which tools can write memory" and "which reach the network" are the questions
    an audit asks first, and they should be answerable from the registry rather than
    by reading code."""
    for spec in REGISTRY.specs():
        assert isinstance(spec.writes_memory, bool)
        assert isinstance(spec.reaches_network, bool)
        assert spec.description, f"{spec.tool_id} needs a description"


def test_no_tool_writes_memory_today() -> None:
    """Both tools only *produce* candidates; the ingestion graph decides what is
    written. If this ever changes, the permission story changes with it and this test
    is where that conversation starts."""
    assert all(not spec.writes_memory for spec in REGISTRY.specs())


def test_a_tool_can_be_registered_and_built(settings) -> None:
    registry = REGISTRY.copy()
    registry.register(RECORDER_SPEC)
    tool = registry.tool("recorder", settings)
    result = tool.run(x=1)
    assert result.ok and result.data["echo"] == {"x": 1}


def test_a_copy_does_not_leak_into_the_process_registry(settings) -> None:
    registry = REGISTRY.copy()
    registry.register(RECORDER_SPEC)
    assert "recorder" in registry
    assert "recorder" not in REGISTRY


def test_a_duplicate_registration_is_refused() -> None:
    registry = ToolRegistry()
    registry.register(RECORDER_SPEC)
    registry.register(RECORDER_SPEC)  # the same spec is a no-op
    other = ToolSpec(tool_id="recorder", display_name="Other", factory=_Recorder)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(other)


def test_a_malformed_tool_id_is_refused() -> None:
    """Validated for the same reason a source id is: ENABLED_TOOLS compares them as
    opaque strings, and a case or whitespace variant would never match."""
    from pydantic import ValidationError

    registry = ToolRegistry()
    for bad in ["Recorder", " recorder", "recorder ", "", "a" * 65]:
        with pytest.raises(ValidationError):
            registry.register(ToolSpec(tool_id=bad, display_name="x", factory=_Recorder))


def test_an_unknown_tool_names_the_known_ones() -> None:
    with pytest.raises(UnknownToolError) as caught:
        REGISTRY.copy().spec("nope")
    assert "fetch_url" in str(caught.value)


def test_a_disabled_tool_cannot_be_built(settings) -> None:
    """Enforced inside the registry rather than at the call site: an allow-list
    enforced in one place out of three is not an allow-list."""
    narrowed = settings.model_copy(update={"enabled_tools": ["fetch_url"]})
    registry = REGISTRY.copy()

    # `fetch_url` and not `extract_page` as the permitted one: building
    # `extract_page` constructs an LLM client and therefore needs an API key, so
    # asserting the allow-list through it made a keyless mock-mode run fail on a
    # test about neither keys nor LLMs.
    assert registry.tool("fetch_url", narrowed) is not None
    with pytest.raises(UnknownToolError):
        registry.tool("extract_page", narrowed)


def test_an_empty_allow_list_enables_everything(settings) -> None:
    assert settings.enabled_tools == []
    assert set(REGISTRY.enabled_ids(settings)) == set(REGISTRY.ids())


# -- the conditional edge -----------------------------------------------


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(settings)
    rt.store.wipe_owner(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def test_enrichment_is_off_by_default(settings) -> None:
    """Following a link reaches the open web on the person's behalf. That should be a
    deliberate choice, not something a fresh checkout does."""
    assert settings.enrich_from_urls is False


def test_a_record_with_no_url_does_not_enrich(runtime: Runtime) -> None:
    """The reason the edge is conditional: most records contain no URL, and a node
    that runs unconditionally to discover it has nothing to do is a node that will
    eventually be made to do something anyway."""
    from orchestrator.connectors.direct import build_record

    on = runtime.settings.model_copy(update={"enrich_from_urls": True})
    runtime.settings = on

    record = build_record(OWNER, "a thought with no links at all", occurred_at_ms=1_000)
    result = run_ingestion(
        runtime, OWNER, source="text", records=[record], thread_id="tools-no-url"
    )
    assert result.enrichment == [], "nothing to fetch means no attempts"
    assert result.events == 1


def test_a_url_is_not_followed_while_enrichment_is_off(runtime: Runtime) -> None:
    from orchestrator.connectors.direct import build_record

    record = build_record(
        OWNER, "see https://example.invalid/page for details", occurred_at_ms=1_000
    )
    result = run_ingestion(
        runtime, OWNER, source="text", records=[record], thread_id="tools-off"
    )
    assert result.enrichment == []
    assert result.events == 1, "the utterance itself is still remembered"
