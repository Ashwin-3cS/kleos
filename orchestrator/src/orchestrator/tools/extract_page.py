"""Turn a fetched page into memory objects.

Reuses the LLM extractor's machinery and **not** its prompt, because a web page and
an utterance are different kinds of thing and asking the same question of both
produces nonsense in one of them.

An utterance is someone's activity: decisions they made, commitments they gave,
things that happened to them. A reference page is a description of a subject. If the
activity prompt is pointed at a page about retrieval-augmented generation, the model
dutifully reports that "the author decided that RAG will use a vector store" — a
claim attributed to nobody, about a decision nobody made, now sitting in a person's
memory as though they had made it.

So this prompt asks for something narrower: what the page is about, and what it
asserts about that subject, with no actor and no commitments. The result is reference
material the person has read, which is what it is.

**Nothing here decides what is written.** The tool returns candidates; the ingestion
graph decides, and the rules about what a web-derived claim may do to a user-derived
one live in the resolver where they can be enforced once. See ADR 0014.
"""

from __future__ import annotations

import logging

from ..config import Settings
from ..extraction.llm import ExtractionError, LLMExtractor
from ..schema import RawRecord
from .base import ToolResult, ToolSpec

log = logging.getLogger(__name__)

TOOL_ID = "extract_page"

#: The source id every object derived from a fetched page carries. Its own source, so
#: a grant over the person's own material does not implicitly cover the open web.
WEB_SOURCE = "web"

PAGE_PROMPT = """\
You extract reference knowledge from one web page that a person has read.

Return JSON only, in exactly this shape:
{"entities": [{"kind": "person|project|artifact|organization|topic", "name": str}],
 "claims": [{"statement": str, "subjects": [str], "confidence": float,
             "commitment": null}]}

ENTITIES are the subjects the page is about -- the technology, the technique, the
tool, the organization. Use the shortest natural name ("RAG", not "the RAG
technique"). Include a `topic` entity for the page's main subject.

CLAIMS are what the page asserts about those subjects: durable, factual statements
someone could later disagree with. Write them as statements about the subject, with
no actor at all -- "retrieval-augmented generation combines a retriever with a
generator", never "the author explains that...". The page is not a person and did
not decide anything.

SUBJECTS are entity names you also returned, and are what the claim is about.

COMMITMENT is always null. A page cannot owe anyone anything.

Do not extract the person who is reading, their opinions, or anything about their
work -- none of that is on this page. Do not report navigation, boilerplate,
cookie notices or calls to action as claims. A page that asserts nothing durable
yields no claims, and returning none is correct.

Never assert that a claim supersedes or contradicts anything.
"""


class ExtractPageTool:
    """One fetched page in, a `Candidate` out.

    Builds on `LLMExtractor` rather than duplicating the JSON-to-schema mapping,
    which is where the fiddly parts live -- entity ids, commitment resolution,
    provenance, the ACL. Only the prompt differs, and the prompt is the thing that
    had to differ.
    """

    name = TOOL_ID

    def __init__(self, settings: Settings) -> None:
        self._extractor = LLMExtractor(settings)
        # Swapped for the duration: the extractor is otherwise identical, and
        # subclassing it to change one constant would hide that fact.
        self._extractor.system_prompt = PAGE_PROMPT
        self._max_chars = settings.extract_page_max_chars

    def close(self) -> None:
        self._extractor.close()

    def run(
        self,
        owner_id: str = "",
        url: str = "",
        title: str = "",
        text: str = "",
        occurred_at_ms: int = 0,
        cites: str = "",
        **_: object,
    ) -> ToolResult:
        if not owner_id or not text:
            return ToolResult.failed("extract_page needs owner_id and text")

        budget = self._max_chars
        full_len = len(text)
        if full_len > budget:
            # Cut at a paragraph boundary when there is one nearby, so the model is
            # not handed half a sentence. The opening of a reference page is where the
            # definition lives; what follows is usually history and navigation.
            head = text[:budget]
            cut = head.rfind("\n")
            text = head[:cut] if cut > budget // 2 else head
            log.info("extract_page %s truncated %d -> %d chars", url, full_len, len(text))

        record = RawRecord(
            external_id=f"web:{url}",
            connector=WEB_SOURCE,
            occurred_at_ms=occurred_at_ms,
            title=title or url,
            body=text,
            url=url,
            # A public page is not sensitive, and marking it so would seal it in the
            # enclave for no benefit while making the body unreadable without a
            # round trip. See the sensitivity rule in ADR 0014.
            sensitive=False,
            participants=[],
            # Names the utterance that referred to this page, which the ingestion
            # graph turns into a CITES edge. This is what makes "what did I learn
            # this from" answerable by the context-chain read that already exists.
            metadata={
                **({"cites": [cites]} if cites else {}),
                # Honest about having read part of a page rather than all of it, so a
                # reader can tell a claim drawn from an opening paragraph from one
                # drawn from a whole document.
                **(
                    {"truncated_from_chars": full_len}
                    if full_len > len(text)
                    else {}
                ),
            },
        )

        try:
            candidate = self._extractor.extract(owner_id, record)
        except ExtractionError as exc:
            return ToolResult.failed(f"page extraction failed: {exc}")

        log.info(
            "extract_page %s -> %d entities, %d claims",
            url,
            len(candidate.entities),
            len(candidate.claims),
        )
        return ToolResult(
            ok=True,
            data={"candidate": candidate, "record": record},
            digest=(
                f"{url}: {len(candidate.entities)} entities, {len(candidate.claims)} claims"
            ),
        )


SPEC = ToolSpec(
    tool_id=TOOL_ID,
    display_name="Understand a fetched page",
    factory=ExtractPageTool,
    description=(
        "Extract the subjects a fetched page is about and what it asserts about "
        "them, as reference knowledge rather than the person's own activity."
    ),
    writes_memory=False,
    reaches_network=True,
)
