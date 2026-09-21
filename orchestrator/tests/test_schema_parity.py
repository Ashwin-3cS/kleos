"""Guards the Python schema against drifting from ``shared/src/memory.rs``.

Parses the Rust sources rather than importing anything: the whole point is
that the two definitions are maintained separately and must still agree on
the wire.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import BaseModel

from orchestrator import permissions, schema

RUST_SRC = Path(__file__).resolve().parents[2] / "shared" / "src"

_STRUCT_RE = re.compile(r"pub struct (\w+) \{(.*?)\n\}", re.S)
_FIELD_RE = re.compile(r"^\s*pub (\w+):", re.M)
_ENUM_RE = re.compile(r"pub enum (\w+) \{(.*?)\n\}", re.S)
_VARIANT_RE = re.compile(r"^\s{4}(\w+)", re.M)


def _rust_text() -> str:
    return (RUST_SRC / "memory.rs").read_text() + (RUST_SRC / "permissions.rs").read_text()


def _rust_structs() -> dict[str, list[str]]:
    text = _rust_text()
    # Strip the Rust test module so its fixtures are not mistaken for schema.
    text = text.split("#[cfg(test)]")[0]
    return {
        name: _FIELD_RE.findall(body) for name, body in _STRUCT_RE.findall(text)
    }


def _rust_enums() -> dict[str, list[str]]:
    text = _rust_text().split("#[cfg(test)]")[0]
    out = {}
    for name, body in _ENUM_RE.findall(text):
        variants = [v for v in _VARIANT_RE.findall(body) if v[0].isupper()]
        out[name] = variants
    return out


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


PY_MODELS = {
    name: obj
    for module in (schema, permissions)
    for name, obj in vars(module).items()
    if isinstance(obj, type) and issubclass(obj, BaseModel) and obj is not BaseModel
}


@pytest.mark.parametrize(
    "name",
    [
        "SourceRef",
        "Citation",
        "Provenance",
        "EncryptedContentRef",
        "Entity",
        "Event",
        "Commitment",
        "Claim",
        "ObjectAcl",
        "Scope",
    ],
)
def test_struct_fields_match(name: str):
    rust_fields = _rust_structs()[name]
    py_fields = list(PY_MODELS[name].model_fields)
    assert py_fields == rust_fields, f"{name} field mismatch"


@pytest.mark.parametrize(
    "rust_name,py_enum",
    [
        ("EntityKind", schema.EntityKind),
        ("ClaimStatus", schema.ClaimStatus),
        ("FulfillmentStatus", schema.FulfillmentStatus),
        ("Sensitivity", permissions.Sensitivity),
        ("DenyReason", permissions.DenyReason),
    ],
)
def test_enum_values_match(rust_name, py_enum):
    rust_variants = [_snake(v) for v in _rust_enums()[rust_name]]
    assert [m.value for m in py_enum] == rust_variants
