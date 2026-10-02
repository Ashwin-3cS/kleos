"""Every query in the store names an owner, and a test says so.

Tenancy here is logical: one Neo4j database holds every owner's graph, and
isolation is whatever each Cypher statement remembers to say. Community Edition
supports exactly one database, so database-per-owner is not available without a
licence change -- which means this invariant is the isolation boundary, not a
defence in depth behind one.

"Every query must remember" is the weakest form of any boundary, and this
codebase has already proved it: ``link()`` matched both endpoints by id alone
until it was found by reading, not by failing. Writing the rule down as a test is
what turns it from discipline into a property. The test reads the module's own
source, so a new method that forgets the predicate fails here the moment it is
written rather than whenever somebody next audits the file.

The allow-list is deliberately small and every entry carries its reason. An entry
is a decision, not a suppression; adding one should feel like it needs an
argument, because it does.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

STORE_SRC = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "orchestrator"
    / "storage"
    / "neo4j_store.py"
)

#: Statements that read or traverse. A statement containing one of these has to
#: constrain the owner, because it can otherwise reach another owner's subgraph.
#: ``CREATE`` is absent on purpose: it cannot match anything that already exists,
#: so it has nothing to escape into.
_READING = re.compile(r"\b(MATCH|MERGE|CALL)\b")

#: Methods whose Cypher legitimately names no owner. Each needs a reason, and
#: the reason is part of the test: if it stops being true, this is where someone
#: will read it.
ALLOWED_UNSCOPED = {
    "get": (
        "A global lookup by id, used by the resolver to answer 'have I stored this "
        "already?'. Ids are content-addressed over the owner, so a hit from another "
        "owner would be a hash collision -- and the method hands its result to a "
        "writer, never to a reader. Anything handing ids to a *reader* uses get_many, "
        "which is owner-scoped."
    ),
    "_vector_query": (
        "A Neo4j vector index is global and cannot pre-filter on a property, so the "
        "owner filter cannot be in the Cypher: queryNodes returns the nearest k "
        "across every owner and `vector_search` keeps only this owner's rows "
        "immediately, escalating k until it has enough. This is the weakest "
        "owner-scoping in the store and the only query that relies on a Python "
        "filter rather than the database -- which is exactly why `vector_search` is "
        "its only caller and why it returns `owner_id` so the filter cannot be "
        "forgotten."
    ),
    "append_read": (
        "CREATE with no MATCH. The owner_id arrives inside the row being written, so "
        "there is no pattern that could match another owner's node."
    ),
}


def _cypher_by_method() -> dict[str, str]:
    """Every string literal in each method of ``Neo4jStore``, joined.

    Joined rather than examined one at a time because the statements are written
    as adjacent literals and f-strings across several lines; a per-literal check
    would see ``"MATCH (a:Memory {id: $from_id, "`` and miss the owner predicate
    two lines down.
    """
    tree = ast.parse(STORE_SRC.read_text())
    store = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "Neo4jStore"
    )
    out: dict[str, str] = {}
    for member in store.body:
        if not isinstance(member, ast.FunctionDef):
            continue
        parts: list[str] = []
        for node in ast.walk(member):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                parts.append(node.value)
        out[member.name] = " ".join(parts)
    return out


def _reading_methods() -> dict[str, str]:
    return {
        name: cypher
        for name, cypher in _cypher_by_method().items()
        if _READING.search(cypher)
    }


def test_the_store_was_found_and_parsed() -> None:
    """Guards the test itself. A rename that broke the parse would otherwise make
    this file pass by examining nothing, which is the worst way for a boundary
    check to fail."""
    methods = _cypher_by_method()
    assert len(methods) > 15, f"only parsed {len(methods)} methods; did the class move?"
    assert _reading_methods(), "parsed no Cypher at all"


@pytest.mark.parametrize("name", sorted(_reading_methods()))
def test_every_reading_statement_names_the_owner(name: str) -> None:
    cypher = _reading_methods()[name]
    if name in ALLOWED_UNSCOPED:
        pytest.skip(f"allow-listed: {ALLOWED_UNSCOPED[name]}")
    assert "$owner_id" in cypher, (
        f"Neo4jStore.{name} runs a MATCH/MERGE/CALL without $owner_id. One Neo4j "
        f"database holds every owner's graph, so an unscoped pattern can reach "
        f"another owner's subgraph. Add the predicate, or add {name} to "
        f"ALLOWED_UNSCOPED with a reason that will still be true next year."
    )


def test_the_allow_list_has_no_stale_entries() -> None:
    """An allow-list entry for a method that no longer exists, or that no longer
    runs Cypher, is a suppression nobody will notice has expired."""
    methods = _cypher_by_method()
    for name in ALLOWED_UNSCOPED:
        assert name in methods, f"ALLOWED_UNSCOPED names {name!r}, which is gone"


def test_every_allow_list_entry_explains_itself() -> None:
    for name, reason in ALLOWED_UNSCOPED.items():
        assert len(reason) > 40, f"{name} needs a real reason, not a label"


def test_traversals_constrain_every_node_on_the_path() -> None:
    """Scoping the endpoints is not enough for a variable-length match.

    ``(seed)-[*1..3]-(other {owner_id: $owner_id})`` constrains where the walk
    *ends*, not where it goes. An intermediate hop through another owner's node
    would pull their subgraph into the result even though both visible ends look
    correct. The traversals that do this say so with ALL(n IN nodes(path) ...).
    """
    for name, cypher in _reading_methods().items():
        if "*1.." not in cypher and "*1.." not in cypher.replace(" ", ""):
            continue
        normalised = " ".join(cypher.split())
        assert (
            "ALL(n IN nodes(path)" in normalised
            or "owner_id: $owner_id}" in normalised
        ), (
            f"Neo4jStore.{name} walks a variable-length path. Constrain every node "
            f"on it, not only the endpoints."
        )
