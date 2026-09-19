"""ChatGPT conversation history, from the user's own data export.

There is no OAuth-able endpoint that returns a person's past ChatGPT
conversations, so this is a **file-import** connector rather than an API
one: the person runs Settings -> Data controls -> Export data, OpenAI
emails them a `.zip`, and they drop it (or the `conversations.json` inside
it) where ``CHATGPT_EXPORT_DIR`` points. ``requires_oauth`` is therefore
false, and nothing about this source needs a stored token.

Two decisions are worth stating, since neither is forced by the format:

**One record per conversation, not per message.** The value of the store is
a *resolved* graph, and the unit that carries meaning is the exchange, not
the turn: "we settled on Neo4j" is a question, an answer and a follow-up,
and a per-message record would cut the decision away from its reasoning,
strand pronouns with no referent, and bury the graph under thousands of
"thanks" events. An `Event` is an atomic ingested fact with one `SourceRef`,
and a conversation is the smallest thing here that is actually a fact about
the person's life. Transcript length is a retrieval problem, and retrieval
already has the tool for it -- this module's own chunker, below.

**Sensitive by default.** See ``Settings.chatgpt_sensitive``.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from ..config import Settings
from ..schema import RawRecord
from .base import ConnectorSpec, pack_paragraphs

SOURCE_ID = "chatgpt"

#: Roles worth keeping in a transcript. `system` is the hidden prompt and
#: `tool` is plumbing; neither is something the person said or was told.
_KEPT_ROLES = ("user", "assistant")

_MAX_TITLE_CHARS = 80


class ChatGPTExportNotFoundError(FileNotFoundError):
    """Raised when no export can be found for an owner.

    The message is the whole user experience of this connector's failure
    mode, so it says what to do, not just what went wrong.
    """

    def __init__(self, owner_id: str, looked_in: list[Path] | None, configured: bool) -> None:
        if not configured:
            detail = (
                "CHATGPT_EXPORT_DIR is not set, so there is nowhere to look for an export."
            )
        else:
            paths = "\n  ".join(str(p) for p in (looked_in or []))
            detail = f"No export found for owner {owner_id!r}. Looked for:\n  {paths}"
        super().__init__(
            f"{detail}\n\n"
            "ChatGPT has no conversation-history API; the only source is your own data "
            "export. In ChatGPT: Settings -> Data controls -> Export data. OpenAI emails "
            "you a .zip; put the .zip (or the conversations.json inside it) at one of the "
            "paths above and re-run the ingest."
        )
        self.owner_id = owner_id


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


def _ms(seconds: Any) -> int | None:
    """Epoch seconds (float, and frequently null) -> epoch ms."""
    if isinstance(seconds, (int, float)) and not isinstance(seconds, bool):
        return int(seconds * 1000)
    return None


def _part_text(part: Any) -> str:
    """One `content.parts` entry as text.

    Parts are usually strings, but non-text content types (images, audio
    pointers) put an object here instead. A placeholder keeps the turn
    visible in the transcript without pretending to have its content.
    """
    if isinstance(part, str):
        return part
    if isinstance(part, dict):
        for key in ("text", "content"):
            value = part.get(key)
            if isinstance(value, str) and value.strip():
                return value
        kind = part.get("content_type")
        return f"[{kind}]" if isinstance(kind, str) else ""
    return ""


def _message_text(message: dict) -> str:
    content = message.get("content")
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts")
    if isinstance(parts, list):
        joined = "\n".join(t for t in (_part_text(p) for p in parts) if t.strip())
    else:
        text = content.get("text")
        joined = text if isinstance(text, str) else ""
    return joined.strip()


def _role(message: dict) -> str | None:
    author = message.get("author")
    role = author.get("role") if isinstance(author, dict) else None
    return role if isinstance(role, str) else None


def _is_hidden(message: dict) -> bool:
    metadata = message.get("metadata")
    return bool(
        isinstance(metadata, dict)
        and metadata.get("is_visually_hidden_from_conversation")
    )


def _roots(mapping: dict[str, Any]) -> list[str]:
    roots = [
        node_id
        for node_id, node in mapping.items()
        if isinstance(node, dict) and node.get("parent") not in mapping
    ]
    return roots or list(mapping)


def walk_linear(mapping: dict[str, Any]) -> list[dict]:
    """The surviving branch of a conversation tree, root to leaf.

    `mapping` is a tree, not a list: regenerating a response forks it. The
    last child at each branch point is the most recent regeneration, which
    is the version the person actually kept, so that is the transcript.
    """
    if not isinstance(mapping, dict) or not mapping:
        return []

    messages: list[dict] = []
    seen: set[str] = set()
    node_id: str | None = next(iter(_roots(mapping)), None)
    while node_id is not None and node_id not in seen:
        seen.add(node_id)
        node = mapping.get(node_id)
        if not isinstance(node, dict):
            break
        message = node.get("message")
        if isinstance(message, dict):
            messages.append(message)
        children = node.get("children")
        children = [c for c in children if isinstance(c, str)] if isinstance(children, list) else []
        node_id = children[-1] if children else None
    return messages


def _turns(messages: list[dict]) -> list[tuple[str, str, int | None]]:
    turns: list[tuple[str, str, int | None]] = []
    for message in messages:
        role = _role(message)
        if role not in _KEPT_ROLES or _is_hidden(message):
            continue
        text = _message_text(message)
        if not text:
            continue
        turns.append((role, text, _ms(message.get("create_time"))))
    return turns


def _title_for(conversation: dict, turns: list[tuple[str, str, int | None]]) -> str:
    title = conversation.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    first_user = next((t for role, t, _ in turns if role == "user"), None)
    if first_user:
        flattened = " ".join(first_user.split())
        return flattened[:_MAX_TITLE_CHARS]
    return "Untitled ChatGPT conversation"


def conversation_to_record(
    conversation: Any, *, sensitive: bool
) -> tuple[RawRecord, int] | None:
    """One conversation -> one ``RawRecord``, plus its last-activity time.

    Returns ``None`` for anything with no usable turns (empty shells and
    system-only stubs both occur in real exports). Last activity is returned
    separately because it is the right thing to filter ``since_ms`` on while
    ``occurred_at_ms`` stays the time the conversation *started*.
    """
    if not isinstance(conversation, dict):
        return None
    mapping = conversation.get("mapping")
    turns = _turns(walk_linear(mapping if isinstance(mapping, dict) else {}))
    if not turns:
        return None

    external_id = conversation.get("conversation_id") or conversation.get("id")
    if not isinstance(external_id, str) or not external_id:
        return None

    message_times = [t for _, _, t in turns if t is not None]
    created_ms = (
        _ms(conversation.get("create_time"))
        or (min(message_times) if message_times else None)
        or _ms(conversation.get("update_time"))
        or 0
    )
    last_activity_ms = max(
        [created_ms, _ms(conversation.get("update_time")) or 0, *message_times]
    )

    record = RawRecord(
        external_id=external_id,
        connector=SOURCE_ID,
        occurred_at_ms=created_ms,
        title=_title_for(conversation, turns),
        body=render_transcript(turns),
        url=f"https://chatgpt.com/c/{external_id}",
        sensitive=sensitive,
        # No participants: the only human in a ChatGPT transcript is the
        # owner, and the assistant is not a person. Inventing an entity for
        # it would put "ChatGPT" in the graph as someone the owner talks to.
        participants=[],
        metadata={
            "conversation_id": external_id,
            "message_count": len(turns),
            "user_messages": sum(1 for role, _, _ in turns if role == "user"),
            "assistant_messages": sum(1 for role, _, _ in turns if role == "assistant"),
            "models": sorted(_models(mapping if isinstance(mapping, dict) else {})),
            "last_activity_ms": last_activity_ms,
            "is_archived": bool(conversation.get("is_archived")),
        },
    )
    return record, last_activity_ms


def _models(mapping: dict[str, Any]) -> set[str]:
    models: set[str] = set()
    for node in mapping.values():
        if not isinstance(node, dict):
            continue
        message = node.get("message")
        metadata = message.get("metadata") if isinstance(message, dict) else None
        slug = metadata.get("model_slug") if isinstance(metadata, dict) else None
        if isinstance(slug, str) and slug:
            models.add(slug)
    return models


def parse_export(
    payload: Any, since_ms: int = 0, *, sensitive: bool = True
) -> Iterator[RawRecord]:
    """``conversations.json`` (already decoded) -> records at/after ``since_ms``."""
    conversations = payload if isinstance(payload, list) else []
    for conversation in conversations:
        parsed = conversation_to_record(conversation, sensitive=sensitive)
        if parsed is None:
            continue
        record, last_activity_ms = parsed
        # Filtered on last activity, not start time: a months-old thread the
        # person added a message to yesterday is new information.
        if last_activity_ms >= since_ms:
            yield record


# --------------------------------------------------------------------------
# transcript rendering and chunking
# --------------------------------------------------------------------------

_ROLE_PREFIX = re.compile(r"\n\n(?=(?:user|assistant): )")


def render_transcript(turns: Iterable[tuple[str, str, int | None]]) -> str:
    return "\n\n".join(f"{role}: {text}" for role, text, _ in turns)


_pack = pack_paragraphs(1200)


def chunk_transcript(text: str, max_chars: int = 1200) -> list[str]:
    """Splits a transcript on message boundaries, packing to a budget.

    Blank-line packing is wrong here: a single assistant turn is full of
    blank lines, so the default chunker would slice a coherent answer into
    fragments that each lose the question they answer. The atomic unit of a
    chat is the turn, so chunks only ever start at one.
    """
    turns = [t for t in _ROLE_PREFIX.split(text) if t.strip()]
    if not turns:
        return _pack(text)

    chunks: list[str] = []
    current = ""
    for turn in turns:
        if len(turn) > max_chars:
            # One turn over budget: flush, then fall back to paragraph
            # packing *within* that turn rather than emitting a huge chunk.
            if current:
                chunks.append(current)
                current = ""
            chunks.extend(pack_paragraphs(max_chars)(turn))
            continue
        if current and len(current) + len(turn) + 2 > max_chars:
            chunks.append(current)
            current = turn
        else:
            current = f"{current}\n\n{turn}" if current else turn
    if current:
        chunks.append(current)
    return chunks


# --------------------------------------------------------------------------
# locating the export
# --------------------------------------------------------------------------

_SAFE_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
_CONVERSATIONS = "conversations.json"


def candidate_paths(export_dir: Path, owner_id: str) -> list[Path]:
    """Where an owner's export may sit, in the order they are tried."""
    return [
        export_dir / owner_id / _CONVERSATIONS,
        export_dir / f"{owner_id}.json",
        export_dir / f"{owner_id}.zip",
        export_dir / owner_id,  # any *.zip inside a per-owner directory
    ]


def _load_zip(path: Path) -> Any:
    with zipfile.ZipFile(path) as archive:
        member = next(
            (
                n
                for n in archive.namelist()
                if n == _CONVERSATIONS or n.endswith(f"/{_CONVERSATIONS}")
            ),
            None,
        )
        if member is None:
            raise ValueError(f"{path} contains no {_CONVERSATIONS}; is it a ChatGPT export?")
        with archive.open(member) as handle:
            return json.load(handle)


def load_export(path: Path) -> Any:
    """Decodes an export from either the raw JSON or the `.zip` as it arrives."""
    if zipfile.is_zipfile(path):
        return _load_zip(path)
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_export_path(export_dir: Path | None, owner_id: str) -> Path:
    if not _SAFE_OWNER.match(owner_id):
        raise ValueError(f"refusing to build an export path from owner id {owner_id!r}")
    if export_dir is None:
        raise ChatGPTExportNotFoundError(owner_id, None, configured=False)

    candidates = candidate_paths(export_dir, owner_id)
    for candidate in candidates[:3]:
        if candidate.is_file():
            return candidate
    owner_dir = candidates[3]
    if owner_dir.is_dir():
        zips = sorted(owner_dir.glob("*.zip"))
        if zips:
            return zips[-1]
    raise ChatGPTExportNotFoundError(owner_id, candidates, configured=True)


# --------------------------------------------------------------------------
# the connector
# --------------------------------------------------------------------------


class ChatGPTConnector:
    """Conversations from an on-disk ChatGPT data export."""

    name = SOURCE_ID

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        directory = self._settings.chatgpt_export_dir
        path = resolve_export_path(Path(directory).expanduser() if directory else None, owner_id)
        payload = load_export(path)
        return list(
            parse_export(payload, since_ms, sensitive=self._settings.chatgpt_sensitive)
        )


#: A miniature export, used when ``ORCHESTRATOR_MODE=mock`` so the source
#: works with no export file present. Deliberately fed through the real
#: parser rather than being a list of ready-made records.
MOCK_EXPORT: list[dict] = [
    {
        "title": "Atlas datastore",
        "create_time": 1_735_689_600.0,
        "update_time": 1_735_689_900.0,
        "conversation_id": "chatgpt-mock-001",
        "mapping": {
            "root": {"id": "root", "message": None, "parent": None, "children": ["m1"]},
            "m1": {
                "id": "m1",
                "parent": "root",
                "children": ["m2"],
                "message": {
                    "id": "m1",
                    "author": {"role": "user"},
                    "create_time": 1_735_689_600.0,
                    "content": {
                        "content_type": "text",
                        "parts": [
                            "Alice decided that project Atlas will use Postgres for "
                            "the primary datastore. Does that hold up?"
                        ],
                    },
                },
            },
            "m2": {
                "id": "m2",
                "parent": "m1",
                "children": [],
                "message": {
                    "id": "m2",
                    "author": {"role": "assistant"},
                    "create_time": 1_735_689_660.0,
                    "content": {
                        "content_type": "text",
                        "parts": ["Postgres is a reasonable default for that workload."],
                    },
                    "metadata": {"model_slug": "gpt-4o"},
                },
            },
        },
    },
    {
        "title": "Atlas storage revisited",
        "create_time": 1_735_948_800.0,
        "update_time": 1_735_949_000.0,
        "conversation_id": "chatgpt-mock-002",
        "mapping": {
            "root": {"id": "root", "message": None, "parent": None, "children": ["m1"]},
            "m1": {
                "id": "m1",
                "parent": "root",
                "children": ["m2"],
                "message": {
                    "id": "m1",
                    "author": {"role": "user"},
                    "create_time": 1_735_948_800.0,
                    "content": {
                        "content_type": "text",
                        "parts": [
                            "Bob decided that project Atlas will use Neo4j for the "
                            "primary datastore instead."
                        ],
                    },
                },
            },
            "m2": {
                "id": "m2",
                "parent": "m1",
                "children": [],
                "message": {
                    "id": "m2",
                    "author": {"role": "assistant"},
                    "create_time": 1_735_948_860.0,
                    "content": {
                        "content_type": "text",
                        "parts": ["Noted -- a graph store fits the traversal requirement."],
                    },
                    "metadata": {"model_slug": "gpt-4o"},
                },
            },
        },
    },
]


class MockChatGPTConnector:
    """The same parser, over a bundled export, so mock mode needs no file."""

    name = SOURCE_ID

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        return list(
            parse_export(MOCK_EXPORT, since_ms, sensitive=self._settings.chatgpt_sensitive)
        )


SPEC = ConnectorSpec(
    source_id=SOURCE_ID,
    display_name="ChatGPT (data export)",
    factory=ChatGPTConnector,
    chunker=chunk_transcript,
    # Not an oversight: OpenAI exposes no conversation-history API to
    # authorise against. The person exports their own data instead.
    requires_oauth=False,
    mock_factory=MockChatGPTConnector,
)
