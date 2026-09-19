"""Deterministic fixture connector.

Stands in for a real source in mock mode and in tests. The fixtures are
shaped to exercise the parts of the pipeline that matter: several sources
of entity overlap, one record that supersedes an earlier decision, one that
contradicts it, and one flagged sensitive so the enclave seal round trip is
actually taken.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..schema import RawRecord

DAY_MS = 86_400_000
BASE_MS = 1_735_689_600_000  # 2025-01-01T00:00:00Z


_FIXTURES: list[RawRecord] = [
    RawRecord(
        external_id="mock-001",
        connector="mock",
        occurred_at_ms=BASE_MS,
        title="Kickoff for project Atlas",
        body=(
            "Alice and Bob agreed that project Atlas will use Postgres for the "
            "primary datastore. Decision recorded at kickoff."
        ),
        url="https://mock.local/records/mock-001",
        participants=["Alice", "Bob"],
    ),
    RawRecord(
        external_id="mock-002",
        connector="mock",
        occurred_at_ms=BASE_MS + 3 * DAY_MS,
        title="Atlas storage revisited",
        body=(
            "Bob decided that project Atlas will use Neo4j for the primary "
            "datastore, replacing the earlier Postgres decision."
        ),
        url="https://mock.local/records/mock-002",
        participants=["Bob"],
    ),
    RawRecord(
        external_id="mock-003",
        connector="mock",
        occurred_at_ms=BASE_MS + 5 * DAY_MS,
        title="Atlas compensation note",
        body=(
            "Carol noted that project Atlas will use Postgres for the primary "
            "datastore after all, pending review."
        ),
        url="https://mock.local/records/mock-003",
        sensitive=True,
        participants=["Carol"],
    ),
    RawRecord(
        external_id="mock-004",
        connector="mock",
        occurred_at_ms=BASE_MS + 9 * DAY_MS,
        title="Beacon rollout owner",
        body="Alice decided that project Beacon will ship behind a feature flag.",
        url="https://mock.local/records/mock-004",
        participants=["Alice"],
    ),
]


class MockConnector:
    name = "mock"

    def fetch(self, since_ms: int) -> Iterable[RawRecord]:
        return [r for r in _FIXTURES if r.occurred_at_ms >= since_ms]
