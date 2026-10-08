from __future__ import annotations

import os

import pytest
from neo4j.exceptions import Neo4jError

os.environ.setdefault("ORCHESTRATOR_MODE", "mock")

from orchestrator.config import Settings  # noqa: E402
from orchestrator.storage.migrations import apply_migrations  # noqa: E402
from orchestrator.storage.neo4j_store import Neo4jStore  # noqa: E402


@pytest.fixture(scope="session")
def settings(tmp_path_factory) -> Settings:
    # Sealed ciphertext now goes somewhere real (ADR 0002), so the suite needs
    # a blob directory of its own: the default is `.local/blobs` under the
    # working directory, and a test run must not write into a dev store or
    # leave blobs behind.
    return Settings(blob_store_dir=str(tmp_path_factory.mktemp("blobs")))


@pytest.fixture
def store(settings: Settings):
    store = Neo4jStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
        settings.neo4j_database,
        embedding_dim=settings.embedding_dim,
    )
    try:
        store.verify()
    except Neo4jError as exc:
        if not str(getattr(exc, "code", "") or "").startswith("Neo.ClientError.Security."):
            raise
        # **Fails rather than skips.** Skipping on "not reachable" is correct --
        # a developer without the containers up should not see a wall of red --
        # but an authentication failure is not unreachability. It means the
        # database is answering and the credentials are wrong, and skipping
        # there turns the entire suite into a silent no-op: the run that found
        # this reported 248 passed and 128 skipped, which reads like a partial
        # environment rather than like every database-backed test having been
        # quietly dropped.
        #
        # Matched on the `Neo.ClientError.Security.*` code rather than on an
        # exception class, because the two cases that matter are different
        # classes: a wrong password is `AuthError`, while the lockout Neo4j
        # applies after a few failed attempts is `AuthenticationRateLimit` -- an
        # ordinary `ClientError`. Catching only the first left the second
        # skipping, which is how this was found twice.
        #
        # The lockout matters because it outlives the mistake: after a password
        # change, attempts with the old one leave a window that looks exactly
        # like a wrong password and lasts long enough to span a whole run.
        # `docker restart` clears it; see `scripts/services.sh`.
        store.close()
        pytest.fail(
            f"neo4j rejected the configured credentials at {settings.neo4j_uri} "
            f"(user={settings.neo4j_user!r}): {exc}\n"
            "This is a wrong password or a lockout window, not an absent "
            "database -- skipping here would hide every database-backed test."
        )
    except Exception as exc:  # noqa: BLE001
        store.close()
        pytest.skip(f"neo4j not reachable at {settings.neo4j_uri}: {exc}")
    apply_migrations(store.driver, settings.neo4j_database, settings.embedding_dim)
    yield store
    store.close()


@pytest.fixture
def vector(settings: Settings):
    """A usable embedding of the configured width.

    Not all zeros: Neo4j's cosine index rejects a zero vector, and the tests that
    used `[0.0] * 256` only worked because nothing ever queried them. A fixture so
    a dimension change does not mean editing every call site.
    """

    def make(seed: float = 1.0) -> list[float]:
        values = [0.0] * settings.embedding_dim
        values[0] = seed
        return values

    return make
