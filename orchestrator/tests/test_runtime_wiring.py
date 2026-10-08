"""What the `Runtime` dataclass is, held by a test rather than by review.

`Runtime` is hand-assembled: every new subsystem adds a field here and a line in
`build()`. `tools: ToolRegistry` was once declared twice, with the same comment block
copied, and nothing failed -- `@dataclass(slots=True)` lets the second declaration win
and carries on. A duplicate is harmless until two of them disagree about a type or a
default, at which point the one that lost is invisible in review and load-bearing at
runtime.
"""

from __future__ import annotations

import dataclasses
import inspect

from orchestrator.graphs.runtime import Runtime


def test_runtime_has_no_duplicate_fields() -> None:
    names = [f.name for f in dataclasses.fields(Runtime)]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, f"declared more than once: {duplicates}"


def test_build_passes_every_field() -> None:
    """`build()` is the only constructor, and it passes every field by keyword, so a
    field it forgets is a `TypeError` at import of the first caller rather than here.
    Asserted over the source text because that is where the omission is visible: a
    field added to the dataclass and not to `build()` fails this immediately, with the
    name, instead of at whatever call site happens to run first.
    """
    source = inspect.getsource(Runtime.build)
    missing = [f.name for f in dataclasses.fields(Runtime) if f"{f.name}=" not in source]
    assert not missing, f"never passed by Runtime.build: {missing}"
