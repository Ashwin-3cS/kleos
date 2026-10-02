"""Telling the system something, and having it become memory.

Every other source is a pull: a connector is handed an owner and a watermark and
goes to fetch what happened. That is wrong for "I learnt RAG from this URL" --
nothing exists to go and fetch, the record exists because a person decided to say
it. These tests cover the push path and the two properties that make it safe to
share the ingestion graph with pulled sources.
"""

from __future__ import annotations

import pytest

from orchestrator.connectors.direct import (
    SOURCES,
    TEXT,
    VOICE,
    PushOnlyConnector,
    build_record,
    is_push_source,
)
from orchestrator.enums import EntityKind, Sensitivity
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.permissions import Scope, evaluate

OWNER = "owner-remember"


@pytest.fixture
def runtime(settings, store):
    rt = Runtime.build(settings)
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_read_log(OWNER)
    rt.close()


# -- the record ---------------------------------------------------------


def test_the_same_utterance_at_the_same_moment_is_one_record() -> None:
    """A retried request must write nothing new, the way every other id here
    behaves."""
    a = build_record(OWNER, "I learnt RAG today", occurred_at_ms=1_000)
    b = build_record(OWNER, "I learnt RAG today", occurred_at_ms=1_000)
    assert a.external_id == b.external_id


def test_the_same_sentence_later_is_a_second_record() -> None:
    """Because it is. Saying the same thing again tomorrow is a new event, not a
    duplicate of yesterday's."""
    a = build_record(OWNER, "standup went fine", occurred_at_ms=1_000)
    b = build_record(OWNER, "standup went fine", occurred_at_ms=2_000)
    assert a.external_id != b.external_id


def test_two_owners_saying_the_same_thing_do_not_collide() -> None:
    a = build_record("owner-a", "same words", occurred_at_ms=1_000)
    b = build_record("owner-b", "same words", occurred_at_ms=1_000)
    assert a.external_id != b.external_id


def test_the_url_in_the_text_is_not_the_records_url() -> None:
    """``SourceRef.url`` means *where this record lives*, and an utterance lives
    nowhere. A URL inside it is something the person referred to, which is a
    different relationship and gets its own event when it is fetched."""
    record = build_record(OWNER, "I learnt RAG from https://example.invalid/rag")
    assert record.url is None
    assert "https://example.invalid/rag" in record.body


def test_the_title_is_a_label_and_the_body_is_everything() -> None:
    text = "a very long note " * 40
    record = build_record(OWNER, text)
    assert record.body == text
    assert len(record.title) < len(text)
    assert "\n" not in record.title


def test_the_timestamp_defaults_to_now_but_can_be_backdated() -> None:
    """A note about last Tuesday belongs on last Tuesday: occurred_at_ms is what
    every time-windowed scope and every "what did I know then" read is written
    against."""
    backdated = build_record(OWNER, "about last week", occurred_at_ms=42)
    assert backdated.occurred_at_ms == 42
    assert build_record(OWNER, "now").occurred_at_ms > 42


# -- the source cannot be pulled ----------------------------------------


@pytest.mark.parametrize("source", SOURCES)
def test_a_push_source_refuses_to_be_pulled(source: str) -> None:
    """A connector returning [] here would make `POST /ingest --source text` look
    like a successful no-op forever."""
    with pytest.raises(NotImplementedError, match="push source"):
        list(PushOnlyConnector(source).fetch(OWNER, 0))


def test_push_sources_are_registered_like_any_other(runtime: Runtime) -> None:
    """Everything downstream needs them to be: a source id for the ACL and grant
    scoping, a chunker for retrieval, a display name for the UI."""
    for source in SOURCES:
        assert source in runtime.registry
        spec = runtime.registry.spec(source)
        assert spec.display_name
        # Packs to a character budget rather than splitting every blank line, so a
        # short utterance stays whole and a long pasted note still chunks.
        assert spec.chunker("one\n\ntwo") == ["one\n\ntwo"]
        long_note = "\n\n".join(["a paragraph of about forty characters"] * 60)
        assert len(spec.chunker(long_note)) > 1


def test_a_push_source_has_no_mock_fixture(runtime: Runtime) -> None:
    """A fixture here would make mock mode return invented utterances, which is the
    one thing a source representing "what the person actually said" must not do."""
    for source in SOURCES:
        assert runtime.registry.spec(source).mock_factory is None


def test_is_push_source_distinguishes_them() -> None:
    assert is_push_source(TEXT) and is_push_source(VOICE)
    assert not is_push_source("mock")
    assert not is_push_source("chatgpt")


# -- through the graph --------------------------------------------------


def test_a_pushed_record_becomes_memory(runtime: Runtime) -> None:
    record = build_record(
        OWNER,
        "Mina decided that project Lantern will use Postgres for durable storage.",
        occurred_at_ms=1_767_571_200_000,
    )
    result = run_ingestion(
        runtime, OWNER, source=TEXT, records=[record], thread_id="push-basic"
    )

    assert result.records == 1
    assert result.events == 1
    assert result.claims >= 1, "a decision stated outright should produce a claim"
    assert not result.errors

    stored = runtime.store.count(OWNER)
    assert stored.get("Event") == 1


def test_the_pushed_record_is_used_instead_of_pulling(runtime: Runtime) -> None:
    """The push path's whole mechanism: `fetch` must not reach the connector, which
    would raise. If this passes, nothing fell back to a pull."""
    record = build_record(OWNER, "a note that was pushed", occurred_at_ms=1_000)
    result = run_ingestion(
        runtime, OWNER, source=VOICE, records=[record], thread_id="push-no-pull"
    )
    assert result.records == 1
    assert not result.errors


def test_pulling_a_push_source_still_fails(runtime: Runtime) -> None:
    """Supplying no records means a pull, and a pull is an error for these sources
    rather than an empty success."""
    with pytest.raises(NotImplementedError, match="push source"):
        run_ingestion(runtime, OWNER, source=TEXT, thread_id="push-pull-fails")


def test_everything_after_fetch_is_the_same_path(runtime: Runtime) -> None:
    """A pushed record goes through the same extraction, resolution and write as a
    pulled one -- which is why there is one graph and not two that have to be kept
    resolving the same way."""
    first = build_record(
        OWNER,
        "Mina decided that project Lantern will use Sqlite for durable storage.",
        occurred_at_ms=1_000_000,
    )
    second = build_record(
        OWNER,
        "Mina decided that project Lantern will use Postgres for durable storage.",
        occurred_at_ms=2_000_000,
    )
    run_ingestion(runtime, OWNER, source=TEXT, records=[first], thread_id="push-super-1")
    result = run_ingestion(
        runtime, OWNER, source=TEXT, records=[second], thread_id="push-super-2"
    )
    assert result.supersessions, (
        "resolution must work on pushed records: a later decision about the same "
        "thing supersedes the earlier one exactly as it does for a pulled source"
    )


# -- text and voice are genuinely separate ------------------------------


def test_a_grant_for_text_does_not_cover_voice(runtime: Runtime) -> None:
    """The reason they are two source ids rather than one with a flag. "Read what I
    wrote down, not what I said out loud in my kitchen" is a real distinction, and
    `permits()` can only express it if the ids differ."""
    spoken = build_record(OWNER, "something I said out loud", source=VOICE, occurred_at_ms=1)
    run_ingestion(runtime, OWNER, source=VOICE, records=[spoken], thread_id="push-voice")

    rows = runtime.store._run(
        "MATCH (n:Event {owner_id: $owner_id}) RETURN n.id AS id", owner_id=OWNER
    )
    stored = runtime.store.get_many(OWNER, [r["id"] for r in rows])
    assert stored

    text_only = Scope(
        agent_id="agent-text",
        owner_id=OWNER,
        sources=[TEXT],
        entity_kinds=list(EntityKind),
        max_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    for item in stored:
        decision = evaluate(text_only, item.node.acl, 2_000)
        assert not decision.allowed, "a text-only grant must not see a voice record"
        assert decision.reason.value == "source_not_in_scope"
