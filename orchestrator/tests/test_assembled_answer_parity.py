"""The Python half of the assembled-line format, and of the content registry.

ADR 0024 moved the assembler into the enclave. The lines and citations an agent
reads are produced in Rust now, and in ``graphs/query.py`` until A1 reaches
every read path -- so for as long as that overlap lasts there are two
implementations of one format, and a disagreement between them is silent.
Nothing errors; the citations just stop lining up with the lines.

Two things are held here, and neither is owned by this file:

- **the wording**, by ``shared/fixtures/assembled_lines.json``, which the Rust
  test ``enclave/tests/assembled_line_parity.rs`` reads as well. Changing a
  string means changing the fixture, which fails both suites until both follow.
- **which fields count as content**, by parsing ``shared/src/content.rs``. A
  field sealed by this side and unknown to that one is handed to the device
  still sealed: not an error anywhere, just unreadable text in an agent's
  context.

Parses the Rust rather than importing anything, for the reason
``test_schema_parity.py`` gives -- the whole point is that the two definitions
are maintained separately and must still agree.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

import pytest

from orchestrator.enums import ClaimStatus, EntityKind, Sensitivity
from orchestrator.graphs.query import _citation_of, _decline_text, _line_of
from orchestrator.permissions import ObjectAcl
from orchestrator.schema import Claim, Entity, Event, Provenance, SourceRef
from orchestrator.storage import content as content_module

REPO = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((REPO / "shared" / "fixtures" / "assembled_lines.json").read_text())
RUST_CONTENT = (REPO / "shared" / "src" / "content.rs").read_text()


def _acl() -> ObjectAcl:
    return ObjectAcl(
        owner_id="owner-1",
        sources=["text"],
        sensitivity=Sensitivity.PERSONAL,
        entity_kinds=[EntityKind.PROJECT],
        occurred_at_ms=1_000,
    )


def _provenance() -> Provenance:
    return Provenance(derived_by="parity", confidence=1.0, created_at_ms=1_000)


def _node_of(case: dict):
    """Builds the node one fixture case describes.

    The Rust side builds the same node from the same descriptor. A shared
    serialised *node* would have been less work and would only have proved the
    two agree about serde.
    """
    if case["kind"] == "claim":
        return Claim(
            id=case["id"],
            owner_id="owner-1",
            statement=case["text"],
            status=ClaimStatus(case["status"]),
            asserted_at_ms=1_000,
            provenance=_provenance(),
            acl=_acl(),
        )
    if case["kind"] == "event":
        return Event(
            id=case["id"],
            owner_id="owner-1",
            summary=case["text"],
            # Set on purpose and expected in no line: an event's body is
            # content the formatter must not reach for.
            body="a body no line may ever contain",
            source=SourceRef(
                connector="text",
                external_id="x1",
                occurred_at_ms=1_000,
                ingested_at_ms=2_000,
            ),
            provenance=_provenance(),
            acl=_acl(),
        )
    if case["kind"] == "entity":
        return Entity(
            id=case["id"],
            owner_id="owner-1",
            kind=EntityKind(case["entity_kind"]),
            name=case["text"],
            first_seen_at_ms=1_000,
            last_seen_at_ms=1_000,
            provenance=_provenance(),
            acl=_acl(),
        )
    raise AssertionError(f"the fixture names an unknown node kind {case['kind']!r}")


@pytest.mark.parametrize("case", FIXTURE["lines"], ids=lambda c: c["id"])
def test_every_line_matches_the_fixture(case: dict) -> None:
    assert _line_of(_node_of(case)) == case["expected"], case["case"]


@pytest.mark.parametrize(
    "case", FIXTURE["declines"], ids=lambda c: str(c["considered"]) + "-" + "-".join(c["reasons"])
)
def test_every_decline_matches_the_fixture(case: dict) -> None:
    # `_decline_text` takes the reasons already deduplicated and sorted, which
    # the Rust side does for itself -- so the fixture carries them raw and each
    # side normalises the way its own caller does. A fixture of pre-sorted
    # reasons would have hidden the dedup on both sides.
    reasons = sorted({r.replace("_", " ") for r in case["reasons"]})
    assert _decline_text(case["considered"], reasons) == case["expected"], case["case"]


@pytest.mark.parametrize("case", FIXTURE["lines"], ids=lambda c: c["id"])
def test_a_citation_names_the_object_and_never_quotes_it(case: dict) -> None:
    """What a citation carries is identity and provenance.

    What it must not carry is the statement: that is already in the line, and a
    second copy is a second thing to keep in step.
    """
    label = {"claim": "Claim", "event": "Event", "entity": "Entity"}[case["kind"]]
    citation = _citation_of(label=label, node=_node_of(case))
    assert citation.object_id == case["id"]
    assert citation.source == "text"
    assert case["text"] not in json.dumps(asdict(citation), default=str)


# -- which fields count as content ---------------------------------------


def _rust_content_fields() -> dict[str, set[str]]:
    """The field names `content_fields` reaches, per node type.

    Parsed rather than imported, and matched on the `entity.`/`event.`/`claim.`
    binding each arm uses -- so an arm that stopped touching a field would drop
    out of this set even though the function still compiles.
    """
    body = RUST_CONTENT.split("pub fn content_fields")[1].split("\n}")[0]
    found: dict[str, set[str]] = {"Entity": set(), "Event": set(), "Claim": set()}
    for binding, label in (("entity", "Entity"), ("event", "Event"), ("claim", "Claim")):
        for match in re.finditer(rf"\b{binding}\.(\w+)", body):
            name = match.group(1)
            if name != "provenance":  # handled by the citation helper, below
                found[label].add(name)
    return found


def test_the_two_content_registries_name_the_same_fields() -> None:
    python: dict[str, set[str]] = {}
    for model, fields in content_module.CONTENT_FIELDS.items():
        python.setdefault(model.__name__, set()).update(fields)
    for model, fields in content_module.CONTENT_LIST_FIELDS.items():
        python.setdefault(model.__name__, set()).update(fields)

    assert _rust_content_fields() == python, (
        "shared/src/content.rs and storage/content.py disagree about which "
        "fields carry content. A field sealed on one side and unknown to the "
        "other is handed to the device still sealed -- no error, just "
        "unreadable text in an agent's context."
    )


def test_both_sides_agree_a_citation_quote_is_content() -> None:
    # Nested rather than top-level, so it is the one entry neither registry can
    # express as a field name and both have to special-case.
    assert "citation.quote" in RUST_CONTENT or "citation_quotes" in RUST_CONTENT
    assert "citation.quote" in Path(content_module.__file__).read_text()


def test_the_marker_is_the_same_string_on_both_sides() -> None:
    """``KSEAL1:`` is what makes a sealed field recognisable as one. A
    disagreement here means the enclave reads every stored field as plaintext
    and formats ciphertext into an answer."""
    match = re.search(r'pub const MARKER: &str = "([^"]+)"', RUST_CONTENT)
    assert match, "shared/src/content.rs no longer declares MARKER"
    assert match.group(1) == content_module.MARKER
