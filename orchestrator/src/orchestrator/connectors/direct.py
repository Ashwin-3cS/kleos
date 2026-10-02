"""Things the person tells the system directly, by typing or by speaking.

Every other source in this service is a **pull**: a connector is handed an owner
and a watermark and goes to fetch what happened. That is the right shape for a
mailbox or an export, and the wrong shape for someone saying *"I learnt RAG from
this URL"* -- there is nothing to go and fetch, the record already exists, and it
exists because a person decided to say it.

So `text` and `voice` are **push** sources. They are registered here like any other
source, because everything downstream needs them to be -- a source id for the ACL
and for grant scoping, a chunker for retrieval, a display name for the UI -- but
their `fetch` raises. Records arrive through `POST /remember` and are handed to the
ingestion graph directly. The factory raising is the same honesty the Google and
GitHub stubs practise: a source that cannot be pulled says so rather than returning
an empty list and looking like it worked.

**Why `text` and `voice` are separate sources rather than one with a flag.** They
differ in exactly the way a `SourceId` is for. A grant scoped to `text` and not
`voice` is a real thing someone would want -- "read what I wrote down, not what I
said out loud in my kitchen" -- and `permits()` can express that for free only if
they are distinct ids. Collapsing them into one source with a metadata flag would
put that distinction somewhere the permission check cannot see.

Voice arrives already transcribed. Speech-to-text happens before this boundary; the
route takes text and does not care whether a keyboard or a microphone produced it.
What differs is register, not mechanism: a spoken note is usually more intimate than
a typed one, which is why `sensitive` is a per-request flag rather than a property of
the source.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from ..extraction.ids import stable_id
from ..schema import RawRecord
from .base import ConnectorSpec, pack_paragraphs

#: Typed. Notes, pasted text, anything the person wrote deliberately.
TEXT = "text"
#: Spoken, then transcribed elsewhere.
VOICE = "voice"

SOURCES = (TEXT, VOICE)


class PushOnlyConnector:
    """Declares a source that cannot be pulled.

    Exists so the registry has a real spec for `text` and `voice` -- the chunker,
    the display name, the source id used in every ACL -- while making the pull path
    an error rather than a silent empty result. A connector that returned `[]` here
    would make `POST /ingest --source text` look like a successful no-op forever.
    """

    def __init__(self, source_id: str) -> None:
        self.name = source_id
        self._source_id = source_id

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        raise NotImplementedError(
            f"{self._source_id!r} is a push source: there is nothing to fetch. "
            f"Records arrive through POST /remember, which hands them to the "
            f"ingestion graph directly."
        )


def _spec(source_id: str, display_name: str) -> ConnectorSpec:
    return ConnectorSpec(
        source_id=source_id,
        display_name=display_name,
        factory=lambda settings, s=source_id: PushOnlyConnector(s),
        # An utterance is one thought, usually short, and splitting on blank lines
        # is the right default for something a person typed. A long pasted note
        # still chunks sensibly; a spoken sentence stays whole.
        chunker=pack_paragraphs(900),
        # No mock_factory on purpose: a fixture here would make `ORCHESTRATOR_MODE=mock`
        # silently return invented utterances, which is the one thing a source
        # representing "what the person actually said" must never do.
    )


TEXT_SPEC = _spec(TEXT, "Typed notes")
VOICE_SPEC = _spec(VOICE, "Voice notes (transcribed)")

SPECS = (TEXT_SPEC, VOICE_SPEC)


def is_push_source(source: str) -> bool:
    return source in SOURCES


#: Enough of the utterance to recognise it in a list. The whole text is the body;
#: this is only a label.
_TITLE_CHARS = 90


def build_record(
    owner_id: str,
    text: str,
    source: str = TEXT,
    occurred_at_ms: int | None = None,
    sensitive: bool = False,
) -> RawRecord:
    """Turns something a person said into a record the ingestion graph accepts.

    ``external_id`` is a content address over the owner, the source, the text and
    the timestamp, which makes saying the same thing at the same moment idempotent
    in the same way every other id in this service is -- a retried request writes
    nothing new, and saying the same sentence again tomorrow is a second record,
    because it is.

    ``url`` stays ``None`` deliberately, even when the text contains one.
    ``SourceRef.url`` means *where this record lives*, and an utterance lives
    nowhere; a URL inside it is something the person referred to, which is a
    different relationship and gets its own event when it is fetched.
    """
    stamp = occurred_at_ms if occurred_at_ms is not None else int(time.time() * 1000)
    external_id = stable_id("utt", owner_id, source, str(stamp), text)
    # Truncated at a word boundary, so the label never ends in half a URL. Nothing
    # follows URLs out of a title any more either, but a title that reads as a valid
    # address is misleading on its own.
    flat = " ".join(text.split())
    title = flat if len(flat) <= _TITLE_CHARS else flat[:_TITLE_CHARS].rsplit(" ", 1)[0]
    return RawRecord(
        external_id=external_id,
        connector=source,
        occurred_at_ms=stamp,
        title=title,
        body=text,
        url=None,
        sensitive=sensitive,
        participants=[],
        metadata={},
    )
