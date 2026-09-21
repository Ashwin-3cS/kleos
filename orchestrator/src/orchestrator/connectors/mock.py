"""Deterministic fixture connector.

Stands in for a real source in mock mode and in tests. The fixtures are
shaped to exercise the parts of the pipeline that matter: several sources
of entity overlap, one record that supersedes an earlier decision, one that
contradicts it, one flagged sensitive so the enclave seal round trip is
actually taken, and three commitments: one that is later reassigned to
someone else with a moved deadline, its replacement, and one that goes past
due without ever being fulfilled.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..schema import RawRecord
from .base import ConnectorSpec, pack_paragraphs

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
    RawRecord(
        external_id="mock-005",
        connector="mock",
        occurred_at_ms=BASE_MS + 12 * DAY_MS,
        title="Atlas migration owner",
        body=(
            "Alice committed to Bob that project Atlas will ship the storage "
            "migration by 2025-02-14."
        ),
        url="https://mock.local/records/mock-005",
        participants=["Alice", "Bob"],
    ),
    RawRecord(
        external_id="mock-006",
        connector="mock",
        occurred_at_ms=BASE_MS + 15 * DAY_MS,
        title="Atlas migration reassigned",
        body=(
            "Bob committed to Alice that project Atlas will ship the storage "
            "migration by 2025-03-07."
        ),
        url="https://mock.local/records/mock-006",
        participants=["Alice", "Bob"],
    ),
    RawRecord(
        external_id="mock-007",
        connector="mock",
        occurred_at_ms=BASE_MS + 16 * DAY_MS,
        title="Beacon rollout plan",
        body="Carol committed that project Beacon will publish the rollout plan by 2025-01-24.",
        url="https://mock.local/records/mock-007",
        participants=["Carol"],
    ),
]


class MockConnector:
    name = "mock"

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        return [r for r in _FIXTURES if r.occurred_at_ms >= since_ms]


def _build(settings) -> MockConnector:
    return MockConnector()


SPEC = ConnectorSpec(
    source_id="mock",
    display_name="Mock fixtures",
    factory=_build,
    chunker=pack_paragraphs(800),
    mock_factory=_build,
)
