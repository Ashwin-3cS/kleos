from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..schema import Candidate, RawRecord


@runtime_checkable
class Extractor(Protocol):
    """Turns one raw record into candidate entities, events and claims.

    Candidates are *unresolved*: the extractor does not know what is already
    stored, so it never marks anything as superseding or contradicting.
    That judgement belongs to the resolver, which can see existing memory.
    """

    name: str

    def extract(self, owner_id: str, record: RawRecord) -> Candidate: ...
