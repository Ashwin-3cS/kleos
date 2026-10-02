"""Following what the person referred to.

"I learnt RAG from this URL" contains two things: an assertion about the person, and
a pointer to something they read. The first is handled by extraction like any other
utterance. This is the second — fetch the page, understand what it is, and keep it as
reference material linked back to the sentence that mentioned it.

It runs as a node in the ingestion graph with **the first conditional edge in this
codebase**: records usually contain no URL, and a node that runs unconditionally to
discover it has nothing to do is a node that will eventually be made to do something
anyway.

## The three rules

These are not configurable, and each exists because of a specific way this could go
wrong.

**1. A web-derived claim can never supersede a user-derived one.** This is the whole
mitigation for prompt injection. A page that says "the user has decided to use
Postgres" will be extracted as a claim about Postgres — the resolver compares claims
about the same subjects, and without this rule the page would be able to overwrite
what the person actually said. Enforced in `resolution/resolver.py` by source
precedence, so it holds for every path into the resolver rather than only this one.

**2. Fetched material is its own source at public sensitivity.** `sources=["web"]`,
not the utterance's source, so a grant over the person's own material does not
implicitly cover the open web. `permits()` already requires every source on an object
to be in scope, so this costs nothing to enforce.

**3. Provenance records the tool.** `derived_by` names the fetch and the extractor, so
a reader can tell a claim read off a page from one the person made. Without it the two
are indistinguishable in a stored record, which is the same failure as rule 1 one
layer down.

## What it does not do

It does not decide to fetch anything on its own. The URL is one the person put in
their own sentence, which is what makes this fetch unambiguously something they asked
for. An agent choosing its own URLs is a different thing with a different safety
argument, and it is not this.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..connectors.web import WEB
from ..schema import Candidate, RawRecord
from ..tools.base import ToolResult
from ..tools.extract_page import TOOL_ID as EXTRACT_PAGE
from ..tools.fetch_url import TOOL_ID as FETCH_URL
from .runtime import Runtime

log = logging.getLogger(__name__)

#: Deliberately conservative. Matches an absolute http(s) URL and stops at the
#: characters that normally end one in prose, so a trailing full stop or a closing
#: bracket does not become part of the address.
_URL_RE = re.compile(r"https?://[^\s<>\"'\]\)}]+")

#: Trailing punctuation that is almost always sentence punctuation rather than URL.
_TRAILING = ".,;:!?'\"`"


def urls_in(text: str) -> list[str]:
    """Absolute URLs in a piece of text, in order, de-duplicated.

    Order preserved because the first URL in a sentence is usually the one being
    referred to, and de-duplicated because a person pasting the same link twice did
    not ask for two fetches.
    """
    found: list[str] = []
    for match in _URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(_TRAILING)
        if url and url not in found:
            found.append(url)
    return found


def urls_in_records(records: list[dict]) -> dict[str, list[str]]:
    """``{external_id: [url, ...]}`` for every record that mentions one.

    **The body only, never the title.** A title here is a derived label -- for a
    pushed record it is the first ninety characters of the body -- so a URL found in
    one may be a *fragment* of a real URL that the truncation cut in half. That is
    not hypothetical: the first live run of this scanned the title too, found
    `.../wiki/Retrieval` where the body said
    `.../wiki/Retrieval-augmented_generation`, and fetched both. The fragment was a
    real page, so nothing failed and the record quietly gained claims about the wrong
    subject.

    A record's own `url` is also not followed. That is where the record came from, not
    something it refers to, and fetching it would re-read the thing we already have.
    """
    out: dict[str, list[str]] = {}
    for raw in records:
        found = urls_in(raw.get("body") or "")
        if found:
            out[raw["external_id"]] = found
    return out


def _max_pages(runtime: Runtime, found: dict[str, list[str]]) -> int:
    del found
    return runtime.settings.enrich_max_pages


def enrich_records(runtime: Runtime, owner_id: str, records: list[dict]) -> dict[str, Any]:
    """Fetches the URLs a batch refers to and extracts each page.

    Returns candidates to be merged into the run, plus the attempts made -- including
    the failed ones. A failure is recorded rather than raised: a dead link in a note
    is an ordinary fact about the note, and it must not stop the note itself from
    being remembered.
    """
    found = urls_in_records(records)
    if not found:
        return {"candidates": [], "attempts": []}

    budget = _max_pages(runtime, found)
    attempts: list[dict[str, Any]] = []
    candidates: list[Candidate] = []
    seen: set[str] = set()

    fetch = runtime.tools.tool(FETCH_URL, runtime.settings)
    extract = runtime.tools.tool(EXTRACT_PAGE, runtime.settings)
    try:
        for external_id, urls in found.items():
            occurred_at_ms = next(
                (r["occurred_at_ms"] for r in records if r["external_id"] == external_id), 0
            )
            for url in urls:
                if url in seen:
                    continue
                if len(seen) >= budget:
                    log.info("enrich: page budget of %d reached, stopping", budget)
                    attempts.append(
                        {
                            "step": "budget",
                            "url": url,
                            "ok": False,
                            "error": f"page budget of {budget} reached",
                        }
                    )
                    continue
                seen.add(url)

                fetched = fetch.run(url=url)
                attempts.append(
                    {"step": FETCH_URL, "url": url, "ok": fetched.ok, "error": fetched.error}
                )
                if not fetched.ok:
                    log.info("enrich: %s", fetched.error)
                    continue

                page = extract.run(
                    owner_id=owner_id,
                    url=fetched.data["url"],
                    title=fetched.data["title"],
                    text=fetched.data["text"],
                    occurred_at_ms=occurred_at_ms,
                    # Names the utterance, which the write node turns into a CITES
                    # edge -- so "what did I learn this from" is answerable by the
                    # context-chain read that already exists.
                    cites=f"{_connector_of(records, external_id)}:{external_id}",
                )
                attempts.append(
                    {
                        "step": EXTRACT_PAGE,
                        "url": fetched.data["url"],
                        "ok": page.ok,
                        "error": page.error,
                        "digest": page.digest,
                    }
                )
                if page.ok:
                    candidates.append(_as_web_candidate(page))
    finally:
        _close(fetch)
        _close(extract)

    return {"candidates": candidates, "attempts": attempts}


def _connector_of(records: list[dict], external_id: str) -> str:
    return next(
        (r["connector"] for r in records if r["external_id"] == external_id),
        "text",
    )


def _as_web_candidate(page: ToolResult) -> Candidate:
    """Forces every object from a page onto the `web` source at public sensitivity.

    Done here rather than trusted from the extractor: the extractor is handed a record
    and will faithfully carry whatever source that record claimed, so the place to be
    certain is the one point where tool output becomes a candidate. Rule 2, enforced
    once.
    """
    from ..enums import Sensitivity

    candidate: Candidate = page.data["candidate"]
    record: RawRecord = page.data["record"]
    assert record.connector == WEB, "a page record must declare the web source"

    for obj in (*candidate.entities, *candidate.events, *candidate.claims):
        obj.acl.sources = [WEB]
        obj.acl.sensitivity = Sensitivity.PUBLIC
        # Rule 3: the tool is part of how this came to exist, not just the model.
        obj.provenance.derived_by = f"{FETCH_URL}+{obj.provenance.derived_by}"
    return candidate


def _close(tool: object) -> None:
    closer = getattr(tool, "close", None)
    if callable(closer):
        closer()
