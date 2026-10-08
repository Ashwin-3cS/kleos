"""Agent sessions: short-term memory that is stored and deliberately not searchable.

The three states this is built around -- stored, searchable, loaded -- are only
real if the first two are enforced by something rather than observed by someone.
What enforces them is one fact: `:AgentSession` and `:SessionBlock` carry no
`:Memory` label, and the vector index and every traversal key on that label.

So the tests here are mostly about what a session is *not*: not retrievable, not
able to outlive its grant, not something an agent can name itself, and not
silently truncated when it overruns. See ADR 0016.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings
from orchestrator.graphs.runtime import Runtime
from orchestrator.storage.sessions import SessionError, SessionStore

OWNER = "owner-session"
AGENT = "claude-code"
DEVICE = "device-1a2b3c"
GRANT_FP = "fp-deadbeef"


@pytest.fixture
def runtime(settings: Settings, store) -> Runtime:
    rt = Runtime.build(settings=settings, migrate=False)
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_sessions(OWNER)
    yield rt
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_sessions(OWNER)
    rt.close()


def _open(runtime: Runtime, **overrides):
    kwargs = dict(
        owner_id=OWNER,
        agent_id=AGENT,
        device_id=DEVICE,
        grant_fp=GRANT_FP,
        ttl_secs=runtime.settings.agent_session_ttl_secs,
    )
    kwargs.update(overrides)
    return runtime.sessions.open_session(**kwargs)


def _append(runtime: Runtime, session_id: str, block: str, **overrides):
    kwargs = dict(
        owner_id=OWNER,
        session_id=session_id,
        block=block,
        max_blocks=runtime.settings.agent_session_max_blocks,
        max_bytes=runtime.settings.agent_session_max_bytes,
    )
    kwargs.update(overrides)
    return runtime.sessions.append_block(**kwargs)


# -- stored -------------------------------------------------------------


def test_a_block_is_stored_in_the_blob_store_and_the_node_holds_no_content(
    runtime: Runtime,
) -> None:
    session = _open(runtime)
    stored = [
        _append(runtime, session.id, "opened migrations.py"),
        _append(runtime, session.id, "ran the suite: 318 passed"),
        _append(runtime, session.id, "the proximity weight is the suspect"),
    ]

    # The bytes are where bytes go.
    from orchestrator.storage.blobs import BlobRef

    for block in stored:
        ref = BlobRef(
            blob_id=block.blob_id,
            patch_id=block.patch_id,
            byte_len=block.byte_len,
            backend=block.backend,
        )
        assert runtime.blobs.get(OWNER, ref) is not None, "the patch should be on disk"

    # The node is an index into them and nothing more.
    rows = runtime.store._run(
        "MATCH (s:AgentSession {owner_id: $o, id: $id}) RETURN properties(s) AS props",
        o=OWNER,
        id=session.id,
    )
    props = rows[0]["props"]
    assert props["block_count"] == 3
    assert props["byte_len"] > 0
    serialised = repr(props)
    for text in ("migrations.py", "318 passed", "proximity"):
        assert text not in serialised, "a session node must hold no block content"


def test_the_blocks_come_back_in_order(runtime: Runtime) -> None:
    session = _open(runtime)
    for i in range(5):
        _append(runtime, session.id, f"block {i}")

    assert [b.index for b in runtime.sessions.blocks(OWNER, session.id)] == [0, 1, 2, 3, 4]


# -- not searchable -----------------------------------------------------


def test_a_session_is_invisible_to_retrieval(runtime: Runtime) -> None:
    """The property the whole three-state split rests on. A scratchpad that could
    be retrieved as memory would surface one agent's working context inside
    another agent's answer, through the very check meant to separate them."""
    session = _open(runtime)
    _append(runtime, session.id, "the quick brown fox decided on Postgres")

    # Unpacked, because `vector_search` returns (node, score) pairs -- and with
    # nothing indexed for this owner the result is empty, so an assertion that
    # only inspects the hits proves nothing on its own. The two reads below are
    # what actually hold the property.
    hits = runtime.store.vector_search(OWNER, runtime.embedder.embed("Postgres"), top_k=20)
    assert session.id not in {node.id for node, _score in hits}

    assert not runtime.store.get_many(OWNER, [session.id])
    assert not runtime.store.neighbour_ids(OWNER, [session.id], hops=2)


def test_wiping_memory_leaves_the_sessions(runtime: Runtime) -> None:
    """Same rule as the read log: re-ingesting does not un-happen what an agent
    was working from when it decided something."""
    session = _open(runtime)
    _append(runtime, session.id, "something")

    runtime.store.wipe_owner(OWNER)

    assert runtime.sessions.get(OWNER, session.id) is not None
    assert len(runtime.sessions.blocks(OWNER, session.id)) == 1


# -- identity and bounds ------------------------------------------------


def test_the_session_id_is_minted_not_supplied(runtime: Runtime) -> None:
    """An agent-chosen id is an unauthenticated string two agents could collide
    on, and attribution is the whole point."""
    first = _open(runtime)
    second = _open(runtime, now_ms=first.opened_at_ms + 1)

    assert first.id.startswith("ses_")
    assert first.id != second.id
    assert DEVICE not in first.id, "the id is derived from the device, not a label for it"


def test_a_session_records_the_device_not_only_the_label(runtime: Runtime) -> None:
    session = _open(runtime)
    stored = runtime.sessions.get(OWNER, session.id)

    assert stored.device_id == DEVICE
    assert stored.agent_id == AGENT


def test_a_session_cannot_outlive_its_grant(runtime: Runtime) -> None:
    """Clamped, not refused: a grant with ten minutes left should still be usable
    for ten minutes. What it must not produce is a session that survives it."""
    now = 1_000_000
    grant_expiry = now + 60_000  # one minute left on the grant
    session = _open(
        runtime, ttl_secs=3600, grant_expires_at_ms=grant_expiry, now_ms=now
    )

    assert session.expires_at_ms == grant_expiry

    with pytest.raises(SessionError, match="expired"):
        _append(runtime, session.id, "after the grant lapsed", now_ms=grant_expiry + 1)


def test_an_over_cap_block_is_refused_not_truncated(runtime: Runtime) -> None:
    session = _open(runtime)
    with pytest.raises(SessionError, match="over the"):
        _append(runtime, session.id, "x" * 50, max_bytes=10)

    assert runtime.sessions.get(OWNER, session.id).block_count == 0
    assert runtime.sessions.blocks(OWNER, session.id) == []


def test_the_block_cap_is_a_cap(runtime: Runtime) -> None:
    session = _open(runtime)
    _append(runtime, session.id, "one", max_blocks=2)
    _append(runtime, session.id, "two", max_blocks=2)

    with pytest.raises(SessionError, match="the cap is 2"):
        _append(runtime, session.id, "three", max_blocks=2)


def test_an_empty_block_is_not_a_block(runtime: Runtime) -> None:
    session = _open(runtime)
    with pytest.raises(SessionError):
        _append(runtime, session.id, "")


def test_a_closed_session_takes_no_more_blocks(runtime: Runtime) -> None:
    session = _open(runtime)
    _append(runtime, session.id, "before")
    runtime.sessions.close(OWNER, session.id)

    with pytest.raises(SessionError, match="closed"):
        _append(runtime, session.id, "after")

    assert runtime.sessions.get(OWNER, session.id).open is False


def test_another_owners_session_is_not_an_existence_oracle(runtime: Runtime) -> None:
    """Same refusal whether the id exists under another owner or not at all."""
    session = _open(runtime)

    assert runtime.sessions.get("someone-else", session.id) is None
    with pytest.raises(SessionError, match="no open session"):
        runtime.sessions.append_block(
            owner_id="someone-else",
            session_id=session.id,
            block="theirs",
            max_blocks=10,
            max_bytes=1000,
        )
    with pytest.raises(SessionError, match="no open session"):
        runtime.sessions.append_block(
            owner_id="someone-else",
            session_id="ses_doesnotexist",
            block="theirs",
            max_blocks=10,
            max_bytes=1000,
        )


def test_a_block_is_sealed_when_there_is_a_gateway_to_seal_with(
    runtime: Runtime, settings: Settings
) -> None:
    """A session block is working material -- file contents, tool output, what
    the person said -- so it is treated like a sensitive body, not like a
    resolved statement."""

    class _SealingGateway:
        def __init__(self) -> None:
            self.seals = 0

        def seal_encrypt(self, plaintext: bytes):
            from orchestrator.gateway_client import SealedContent
            from orchestrator.schema import EncryptedContentRef

            self.seals += 1
            return SealedContent(
                ciphertext=bytes(b ^ 0x5A for b in plaintext),
                ref=EncryptedContentRef(
                    key_id="k", scheme="XOR_TEST", blob_id=None, byte_len=len(plaintext)
                ),
                attestation="TEST",
            )

    gateway = _SealingGateway()
    sessions = SessionStore(runtime.store, runtime.blobs, gateway=gateway)
    session = sessions.open_session(
        owner_id=OWNER,
        agent_id=AGENT,
        device_id=DEVICE,
        grant_fp=GRANT_FP,
        ttl_secs=600,
    )
    block = sessions.append_block(
        owner_id=OWNER,
        session_id=session.id,
        block="a plaintext scratchpad line",
        max_blocks=10,
        max_bytes=10_000,
    )

    assert gateway.seals == 1
    from orchestrator.storage.blobs import BlobRef

    on_disk = runtime.blobs.get(
        OWNER,
        BlobRef(
            blob_id=block.blob_id,
            patch_id=block.patch_id,
            byte_len=block.byte_len,
            backend=block.backend,
        ),
    )
    assert b"plaintext scratchpad" not in on_disk
