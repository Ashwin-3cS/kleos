"""What this install can do with the model it has, or has not.

The bug these guard against is not a crash. It is silence: without a model,
ingesting a real source writes nothing and raises nothing, and closing a
session keeps nothing and says nothing. Both are correct behaviours -- a regex
that guessed what a session concluded would write invented claims under an
authenticated device id -- and both read, to someone new, as "this is broken".

So what is tested here is that the install *says which*.
"""

from __future__ import annotations

import pytest

from orchestrator import models
from orchestrator.config import Settings
from orchestrator.graphs.runtime import Runtime

OWNER = "owner-model-status"


@pytest.fixture
def runtime(settings: Settings, store):
    rt = Runtime.build(settings=settings, migrate=False)
    rt.store.wipe_owner(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.close()


def _settings(**overrides) -> Settings:
    base = {
        "extractor": "mock",
        "llm_base_url": "https://api.groq.com/openai/v1",
        "llm_api_key": None,
        # The default points at a file next to the checkout, which would make
        # this test depend on whether the developer happens to have one.
        "llm_api_key_file": None,
    }
    return Settings(**{**base, **overrides})


# -- describe -----------------------------------------------------------


def test_no_model_is_reported_as_unconfigured_not_as_broken():
    status = models.describe(_settings())
    assert not status.configured
    assert status.extractor == "mock"
    assert status.key_source == "none"
    assert "memory works" in status.summary


def test_a_hosted_provider_with_a_key_is_configured():
    status = models.describe(_settings(extractor="llm", llm_api_key="sk-test"))
    assert status.configured
    assert status.key_source == "env-or-file"
    assert "model configured" in status.summary


def test_a_hosted_provider_without_a_key_is_not_configured():
    status = models.describe(_settings(extractor="llm"))
    assert not status.configured
    assert status.key_source == "none"


def test_a_local_endpoint_needs_no_key():
    """A llama.cpp or vLLM takes any key or none.

    Reporting that as a misconfiguration would train someone to ignore the
    warning that matters.
    """
    status = models.describe(
        _settings(extractor="llm", llm_base_url="http://127.0.0.1:8080/v1")
    )
    assert status.configured
    assert status.key_source == "not-needed"


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:8080/v1", "http://localhost:1234/v1", "http://[::1]:8080/v1"],
)
def test_local_endpoints_are_recognised(url: str):
    assert models.looks_local(url)


@pytest.mark.parametrize(
    "url",
    ["https://api.groq.com/openai/v1", "https://api.openai.com/v1"],
)
def test_hosted_endpoints_are_not(url: str):
    assert not models.looks_local(url)


# -- the capability table ----------------------------------------------


def test_the_agent_loop_is_keyless_and_says_so():
    """The useful half of the answer.

    Someone deciding whether to run this without a key needs to know that
    recording a decision, briefing and querying all work -- the claim is the
    statement the agent already wrote, and the read path formats rather than
    synthesises.
    """
    status = models.describe(_settings())
    for capability in ("record_decision", "brief_before_acting", "query_memory"):
        assert status.capabilities[capability]["status"] == models.KEYLESS


def test_ingestion_is_named_as_needing_a_model():
    status = models.describe(_settings())
    ingest = status.capabilities["ingest_a_source"]
    assert ingest["status"] == models.NEEDS_MODEL
    assert "no claims and no error" in ingest["why"]


def test_the_partly_working_ones_are_not_rounded_either_way():
    """Consolidation and reasoning both do something without a model.

    Calling them "needs a model" would be as wrong as calling them keyless:
    marked `Decision:` lines are kept, and the reasoning rules find churn and
    cross-device disagreement, which is arithmetic rather than judgement.
    """
    status = models.describe(_settings())
    assert status.capabilities["consolidate_a_session"]["status"] == models.PARTIAL
    assert status.capabilities["reason_across_sessions"]["status"] == models.PARTIAL


# -- probe --------------------------------------------------------------


def test_probing_an_unconfigured_install_touches_no_network():
    # If it dialled anything this would fail: the URL is a real host and the
    # test suite runs offline.
    status = models.probe(_settings(llm_base_url="https://api.groq.com/openai/v1"))
    assert status.reachable is None


def test_an_unreachable_endpoint_is_reported_with_the_reason(monkeypatch):
    import httpx

    def boom(*_a, **_k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", boom)
    status = models.probe(
        _settings(extractor="llm", llm_base_url="http://127.0.0.1:9/v1")
    )
    assert status.reachable is False
    assert "ConnectError" in status.detail
    assert "unreachable" in status.summary


def test_a_wrong_key_is_distinguished_from_an_unreachable_endpoint(monkeypatch):
    """401 and "connection refused" send a person to different places."""
    import httpx

    monkeypatch.setattr(
        httpx, "get", lambda *a, **k: httpx.Response(401, request=httpx.Request("GET", "http://x"))
    )
    status = models.probe(_settings(extractor="llm", llm_api_key="wrong"))
    assert status.reachable is False
    assert "key is wrong or expired" in status.detail


def test_a_restricted_models_route_is_not_called_unreachable(monkeypatch):
    """Some gateways refuse /models and serve completions perfectly well.

    Calling that "unreachable" would be a false alarm about the one thing
    people most need to trust.
    """
    import httpx

    monkeypatch.setattr(
        httpx, "get", lambda *a, **k: httpx.Response(404, request=httpx.Request("GET", "http://x"))
    )
    status = models.probe(_settings(extractor="llm", llm_api_key="sk-test"))
    assert status.reachable is True
    assert "completions may still work" in status.detail


def test_a_reachable_endpoint_is_ready(monkeypatch):
    import httpx

    monkeypatch.setattr(
        httpx, "get", lambda *a, **k: httpx.Response(200, request=httpx.Request("GET", "http://x"))
    )
    status = models.probe(_settings(extractor="llm", llm_api_key="sk-test"))
    assert status.reachable is True
    assert status.summary.startswith("model ready")


# -- the two silences ---------------------------------------------------
#
# Both of these were found live rather than reasoned about, and both read as
# "the product does not work" to someone who has not been told.


def test_ingesting_real_prose_without_a_model_says_why(runtime):
    """`records: 1, claims: 0, errors: []` with no explanation.

    The condition counts entities and claims and **not** events, because a
    pushed utterance is stored as an event whatever happens -- that is the
    record itself, not something extraction worked out. Counting it meant the
    note never fired on `/remember`, which is the path where it matters most.
    """
    from orchestrator.connectors.direct import TEXT, build_record
    from orchestrator.graphs.ingestion import run_ingestion

    record = build_record(
        owner_id=OWNER,
        text="I want to move storage onto something that can do graph proximity.",
        source=TEXT,
        occurred_at_ms=None,
        sensitive=False,
    )
    result = run_ingestion(
        runtime, OWNER, source=TEXT, records=[record], thread_id="note-check"
    )
    assert result.records == 1
    assert result.claims == 0
    assert result.note is not None
    assert "no model is configured" in result.note


def test_a_run_that_extracted_something_gets_no_note(runtime):
    """The fixture grammar is what the mock extractor *can* read.

    A run that produced claims needs no explanation, and a note on every
    keyless run would be noise people learn to skip.
    """
    from orchestrator.graphs.ingestion import run_ingestion

    result = run_ingestion(runtime, OWNER, source="mock", thread_id="note-none")
    assert result.claims > 0
    assert result.note is None
