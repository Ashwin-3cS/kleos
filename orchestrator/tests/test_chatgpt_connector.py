"""The ChatGPT connector: parser, chunker, and a mock-mode ingest.

No network, no keys, no real export data. The fixture below is synthetic
but shaped like the real thing: a regeneration branch, a null message on the
root, null timestamps, an empty turn, a non-string content part, and a
system message that must not reach the transcript.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from orchestrator.config import Settings
from orchestrator.connectors import REGISTRY
from orchestrator.connectors.chatgpt import (
    MOCK_EXPORT,
    ChatGPTConnector,
    ChatGPTExportNotFoundError,
    chunk_transcript,
    parse_export,
    resolve_export_path,
    walk_linear,
)
from orchestrator.connectors.registry import ConnectorRegistry
from orchestrator.graphs.ingestion import run_ingestion
from orchestrator.graphs.runtime import Runtime
from orchestrator.retrieval.index import chunk_for_source

OWNER = "owner-chatgpt"

SEC = 1_735_689_600.0  # 2025-01-01T00:00:00Z
DAY = 86_400.0


def _msg(node_id, role, text, *, parent, children, create_time=SEC, **extra):
    content = extra.pop("content", {"content_type": "text", "parts": [text]})
    return {
        "id": node_id,
        "parent": parent,
        "children": children,
        "message": {
            "id": node_id,
            "author": {"role": role},
            "create_time": create_time,
            "content": content,
            **extra,
        },
    }


#: One conversation with a regeneration branch: `m2` was regenerated as
#: `m2b`, and only the later branch survived.
_BRANCHED = {
    "title": "Zephyr queue",
    "create_time": SEC,
    "update_time": SEC + 600,
    "conversation_id": "conv-branched",
    "mapping": {
        "root": {"id": "root", "message": None, "parent": None, "children": ["sys"]},
        "sys": _msg("sys", "system", "", parent="root", children=["m1"]),
        "m1": _msg("m1", "user", "Which queue should Zephyr use?", parent="sys",
                   children=["m2", "m2b"]),
        "m2": _msg("m2", "assistant", "An older, discarded answer.", parent="m1", children=[]),
        "m2b": _msg("m2b", "assistant", "Dana decided that project Zephyr will use Redis.",
                    parent="m1", children=["m3"], create_time=SEC + 300),
        "m3": _msg("m3", "user", "", parent="m2b", children=["m4"], create_time=None),
        "m4": _msg(
            "m4",
            "user",
            None,
            parent="m3",
            children=[],
            create_time=SEC + 600,
            content={"content_type": "multimodal_text",
                     "parts": [{"content_type": "image_asset_pointer"}, "and the diagram"]},
        ),
    },
}

#: Nothing usable: a null message, a hidden turn and a tool turn.
_EMPTY = {
    "title": None,
    "create_time": None,
    "update_time": None,
    "id": "conv-empty",
    "mapping": {
        "root": {"id": "root", "message": None, "parent": None, "children": ["t1"]},
        "t1": _msg("t1", "tool", "internal plumbing", parent="root", children=["h1"]),
        "h1": _msg("h1", "assistant", "hidden", parent="t1", children=[],
                   metadata={"is_visually_hidden_from_conversation": True}),
    },
}

#: Untitled, so the title is derived from the first user turn; timestamps
#: only on the messages.
_UNTITLED = {
    "title": None,
    "create_time": None,
    "update_time": None,
    "conversation_id": "conv-untitled",
    "mapping": {
        "root": {"id": "root", "message": None, "parent": None, "children": ["m1"]},
        "m1": _msg("m1", "user", "Carol noted that project Beacon will ship behind a flag.",
                   parent="root", children=[], create_time=SEC + 10 * DAY),
    },
}

EXPORT = [_BRANCHED, _EMPTY, _UNTITLED, "not a conversation", None]


# --- parsing --------------------------------------------------------------


def test_transcript_follows_the_surviving_regeneration_branch():
    ids = [m["id"] for m in walk_linear(_BRANCHED["mapping"])]
    assert ids == ["sys", "m1", "m2b", "m3", "m4"]
    assert "m2" not in ids, "the discarded regeneration must not be in the transcript"


def test_parser_is_defensive_about_real_export_shapes():
    records = list(parse_export(EXPORT, sensitive=False))

    # conv-empty yields nothing: tool + hidden turns only.
    assert [r.external_id for r in records] == ["conv-branched", "conv-untitled"]

    branched = records[0]
    assert branched.title == "Zephyr queue"
    assert branched.occurred_at_ms == int(SEC * 1000)
    assert "An older, discarded answer" not in branched.body
    assert "system:" not in branched.body
    # The empty turn is dropped; the non-string part becomes a placeholder.
    assert branched.body.splitlines()[0].startswith("user: Which queue")
    assert "[image_asset_pointer]" in branched.body
    assert "and the diagram" in branched.body

    untitled = records[1]
    assert untitled.title.startswith("Carol noted that project Beacon")
    # No conversation create_time: falls back to the earliest message time.
    assert untitled.occurred_at_ms == int((SEC + 10 * DAY) * 1000)


def test_metadata_carries_chatgpt_specific_fields():
    record = next(iter(parse_export(EXPORT, sensitive=False)))
    assert record.metadata["conversation_id"] == "conv-branched"
    assert record.metadata["message_count"] == 3
    assert record.metadata["user_messages"] == 2
    assert record.metadata["assistant_messages"] == 1
    assert record.url == "https://chatgpt.com/c/conv-branched"


def test_since_ms_filters_on_last_activity_not_start_time():
    later = int((SEC + DAY) * 1000)
    ids = [r.external_id for r in parse_export(EXPORT, later, sensitive=False)]
    assert ids == ["conv-untitled"]

    # A conversation that started long ago but was updated recently is still
    # new information, so it comes back.
    revived = dict(_BRANCHED, update_time=SEC + 20 * DAY)
    assert [r.external_id for r in parse_export([revived], later, sensitive=False)] == [
        "conv-branched"
    ]


def test_sensitive_defaults_to_true_and_is_configurable():
    assert Settings().chatgpt_sensitive is True
    assert all(r.sensitive for r in parse_export(EXPORT))
    assert not any(r.sensitive for r in parse_export(EXPORT, sensitive=False))


# --- chunking -------------------------------------------------------------


def test_chunker_splits_on_message_boundaries_not_blank_lines():
    transcript = "user: a question\n\nassistant: line one\n\nline two\n\nuser: thanks"
    assert chunk_transcript(transcript, max_chars=40) == [
        "user: a question",
        "assistant: line one\n\nline two",
        "user: thanks",
    ]


def test_chunker_packs_short_turns_and_splits_an_oversized_one():
    short = "user: hi\n\nassistant: hello"
    assert chunk_transcript(short) == [short]

    huge = "assistant: " + ("x" * 400 + "\n\n") * 5
    chunks = chunk_transcript(f"user: go\n\n{huge}".strip(), max_chars=500)
    assert len(chunks) > 1
    assert all(len(c) <= 500 for c in chunks)


def test_chunking_dispatches_through_the_registry():
    # A long assistant turn with a blank line in it. The default chunker packs
    # the question together with the first half of the answer; the ChatGPT one
    # never starts a chunk mid-message.
    transcript = f"user: q\n\nassistant: {'a' * 750}\n\n{'b' * 740}"
    chatgpt_chunks = chunk_for_source(transcript, "chatgpt", REGISTRY)
    google_chunks = chunk_for_source(transcript, "google", REGISTRY)
    assert chatgpt_chunks[0] == "user: q"
    assert google_chunks[0].startswith("user: q\n\nassistant:")


# --- locating the export --------------------------------------------------


def test_export_is_found_as_raw_json_or_as_the_zip(tmp_path: Path):
    payload = json.dumps(MOCK_EXPORT)

    (tmp_path / "alice").mkdir()
    (tmp_path / "alice" / "conversations.json").write_text(payload)
    assert resolve_export_path(tmp_path, "alice").name == "conversations.json"

    (tmp_path / "bob.json").write_text(payload)
    assert resolve_export_path(tmp_path, "bob").name == "bob.json"

    zip_path = tmp_path / "carol.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("conversations.json", payload)
        archive.writestr("chat.html", "<html></html>")
    assert resolve_export_path(tmp_path, "carol") == zip_path

    settings = Settings(chatgpt_export_dir=str(tmp_path), chatgpt_sensitive=False)
    for owner in ("alice", "bob", "carol"):
        records = list(ChatGPTConnector(settings).fetch(owner, 0))
        assert [r.external_id for r in records] == ["chatgpt-mock-001", "chatgpt-mock-002"]


def test_a_missing_export_says_exactly_what_to_do(tmp_path: Path):
    settings = Settings(chatgpt_export_dir=str(tmp_path))
    with pytest.raises(ChatGPTExportNotFoundError) as caught:
        list(ChatGPTConnector(settings).fetch("nobody", 0))
    message = str(caught.value)
    assert "Settings -> Data controls -> Export data" in message
    assert str(tmp_path / "nobody" / "conversations.json") in message

    with pytest.raises(ChatGPTExportNotFoundError, match="CHATGPT_EXPORT_DIR is not set"):
        list(ChatGPTConnector(Settings(chatgpt_export_dir=None)).fetch("nobody", 0))

    with pytest.raises(ValueError, match="refusing to build an export path"):
        resolve_export_path(tmp_path, "../../etc/passwd")


# --- mock mode and ingestion ---------------------------------------------


def test_mock_mode_works_with_no_export_file_present():
    settings = Settings(mode="mock", chatgpt_export_dir=None)
    connector = REGISTRY.connector("chatgpt", settings)
    records = list(connector.fetch(OWNER, 0))
    assert [r.external_id for r in records] == ["chatgpt-mock-001", "chatgpt-mock-002"]
    assert all(r.sensitive for r in records)


@pytest.fixture
def registry() -> ConnectorRegistry:
    return REGISTRY.copy()


def _runtime(settings, registry):
    rt = Runtime.build(settings, registry=registry)
    rt.store.wipe_owner(OWNER)
    return rt


def test_mock_ingestion_writes_resolved_memory(store, settings, registry):
    """Non-sensitive so the event body is written without a gateway.

    The sealed-by-default path is the one below; it is the failure mode that
    matters, and it is the same one ``test_end_to_end`` asserts for the mock
    source.
    """
    rt = _runtime(settings.model_copy(update={"chatgpt_sensitive": False}), registry)
    try:
        result = run_ingestion(rt, owner_id=OWNER, source="chatgpt")
        assert result.errors == []
        assert result.records == 2
        assert result.entities > 0
        assert result.claims > 0
        assert result.supersessions, "the second conversation supersedes the first decision"
        assert rt.store.count(OWNER).get("Event", 0) == 2
    finally:
        rt.store.wipe_owner(OWNER)
        rt.close()


def test_by_default_a_transcript_is_not_stored_without_the_enclave(store, settings, registry):
    rt = _runtime(settings, registry)
    try:
        result = run_ingestion(rt, owner_id=OWNER, source="chatgpt")
        if result.sealed:
            pytest.skip("a gateway is running; the failure path is not exercised here")
        assert result.records == 2
        assert all("seal failed" in e or "was not sealed" in e for e in result.errors)
        assert rt.store.count(OWNER).get("Event", 0) == 0
    finally:
        rt.store.wipe_owner(OWNER)
        rt.close()
