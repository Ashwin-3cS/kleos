"""The `web` source: material read off a page the person referred to.

Registered as a source for the same reason `text` and `voice` are — everything
downstream is written against a source id. Pushed rather than pulled: pages arrive
because a tool fetched one, never because something polled the web.

**Why it is its own source and not a flag on the referring utterance.** A grant over
the person's own material must not implicitly cover the open web. If a fetched page's
claims carried `sources=["text"]`, then "read my notes" would silently include
everything any page those notes linked to happened to assert — and `permits()` would
be right to allow it, because the object would be claiming to be a note. A distinct
id is what makes "my notes, but not the internet" expressible, and it costs nothing
because the permission check already requires *every* source on an object to be in
scope.

Sensitivity is `PUBLIC`, which makes this the first genuinely public content in the
system. That is not a weakening: it is accurate, and accuracy is what lets a scope
with `max_sensitivity: public` exist at all — an agent that may read reference
material and nothing personal.
"""

from __future__ import annotations

from .base import ConnectorSpec, pack_paragraphs
from .direct import PushOnlyConnector

#: Must match `tools.extract_page.WEB_SOURCE`; a test holds them together.
WEB = "web"

SPEC = ConnectorSpec(
    source_id=WEB,
    display_name="Pages you referred to",
    factory=lambda settings: PushOnlyConnector(WEB),
    # Larger than an utterance's budget: a reference page is long, and a chunk that
    # spans a whole section retrieves better than one that stops mid-explanation.
    chunker=pack_paragraphs(1200),
    # No fixture, for the same reason the push sources have none: inventing content
    # for a source that represents "what a page actually said" would be a lie that
    # looks like a feature.
)
