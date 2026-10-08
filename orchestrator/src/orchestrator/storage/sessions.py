"""Agent sessions: the short-term half of the memory, and the state manager.

Every source before this one was a *pull* or a *push* of something that had
already happened. A session is neither: it is the working context of an agent
that is still thinking -- the turns so far, what a tool returned, a scratchpad,
the contents of a file it opened. Nothing in this service had anywhere to put
that, and "session" throughout the codebase meant an auth session.

It exists because several agents now share one memory. Claude Code on one device
and ChatGPT on another each hold their own context window, and the harness can
only tell the second what the first decided -- and *why* -- if the first's
working material was kept somewhere addressable at the moment it decided.

**The three states, which are the whole design.** The reference architecture puts
it as: stored, searchable and loaded are different states.

- **Stored.** A block is sealed and written as a Quilt patch. No embedding is
  computed, and nothing is labelled ``:Memory``.
- **Searchable.** Only consolidated claims reach the vector index, by going
  through the ordinary ingestion graph. A session's raw blocks never do.
- **Loaded.** What one inference actually sees, assembled per call by the
  briefing and never stored as an object. Its only durable trace is the read
  log -- deliberately, because a stored copy of every context window is a second
  uncontrolled copy of the memory.

The mechanism that enforces the first two is the one already used twice in this
codebase: ``:AgentSession`` carries **no ``:Memory`` label**. The vector index
and every traversal in `neo4j_store` key on that label, so staying off it is
what makes "a scratchpad is stored and not retrievable" a property rather than a
convention. ``:AgentRead`` is off it for the same reason, and the test that
holds this covers both.

**A session is a node and a set of blobs**, mirroring the split `Event` and
`EncryptedContentRef` already use: the node is identity and bounds and is
queryable, the blocks are bytes and are not. The node is therefore small and
the scratchpad can be large.

**The session id is minted here, never supplied by the agent.** An agent-chosen
id is an unauthenticated string two agents could collide on, by accident or on
purpose, and attribution is the entire point of the feature.

**A session cannot outlive the grant that opened it.** Mirrors how
`verify_grant` clamps a grant's own expiry: a session that survived its grant
would be a way to keep using a capability after it lapsed.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from ..extraction.ids import stable_id

log = logging.getLogger(__name__)


class SessionError(RuntimeError):
    """A session was asked to do something its bounds or its grant forbid."""


@dataclass(slots=True)
class AgentSession:
    """One agent's working context: who, under what, for how long, how much.

    Deliberately holds no content. The blocks are in the blob store; what is
    here is what has to be queryable without unsealing anything.
    """

    owner_id: str
    #: The label the owner put in the scope they signed. Not authenticated.
    agent_id: str
    #: The registered device key the gateway verified. Authenticated, and what
    #: makes "device 1" answerable. See ADR 0016.
    device_id: str
    #: Keyed hash of the grant this session was opened under. The token itself is
    #: never stored, like everywhere else (ADR 0005).
    grant_fp: str
    opened_at_ms: int = 0
    #: Never later than the grant's own expiry.
    expires_at_ms: int = 0
    closed_at_ms: int | None = None
    #: How many blocks have been appended, and their total size. Counters rather
    #: than a list: the bounds are checked on every append and a list would grow
    #: the node in step with the thing it is supposed to bound.
    block_count: int = 0
    byte_len: int = 0
    #: Ids of the claims consolidation produced from this session, so "what did
    #: this session actually commit to memory" is one property read. Empty until
    #: it is consolidated, and empty forever for a session that decided nothing.
    consolidated_into: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.opened_at_ms:
            self.opened_at_ms = int(time.time() * 1000)
        if not self.id:
            # Minted from the authenticated device and the time, never from
            # anything the agent sent. Two agents cannot collide on it and one
            # agent cannot choose it.
            self.id = stable_id(
                "ses",
                self.owner_id,
                self.device_id,
                self.agent_id,
                self.grant_fp,
                str(self.opened_at_ms),
            )

    @property
    def open(self) -> bool:
        return self.closed_at_ms is None

    def expired(self, now_ms: int | None = None) -> bool:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        return bool(self.expires_at_ms) and now >= self.expires_at_ms

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class StoredBlock:
    """Where one appended block went, and nothing about what it said."""

    session_id: str
    index: int
    blob_id: str
    patch_id: str | None
    byte_len: int
    backend: str
    at_ms: int


class SessionStore:
    """Append-only sessions in Neo4j, with their blocks in the blob store.

    Append-only in the sense that matters: a block is never rewritten and never
    removed, and closing a session sets a timestamp rather than deleting it.
    What an agent was working from when it decided something is part of the
    record of that decision.

    Like the read log, this lives in Neo4j while Neo4j is explicitly not the
    system of record -- and for the same reason. That property is scoped to the
    ``:Memory`` graph, which is rebuildable from source material. A session is
    not: it is the only trace of a context window that no longer exists.
    """

    def __init__(self, store, blobs, gateway=None) -> None:
        self._store = store
        self._blobs = blobs
        self._gateway = gateway

    # -- opening and closing ------------------------------------------

    def open_session(
        self,
        *,
        owner_id: str,
        agent_id: str,
        device_id: str,
        grant_fp: str,
        ttl_secs: int,
        grant_expires_at_ms: int | None = None,
        now_ms: int | None = None,
    ) -> AgentSession:
        """Opens a session, clamped by the grant that authorised it."""
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        expires = now + ttl_secs * 1000
        if grant_expires_at_ms:
            # The clamp, not a validation error: a grant with ten minutes left
            # should still be usable for ten minutes, not refused for asking for
            # an hour. What it must not do is produce a session outliving it.
            expires = min(expires, grant_expires_at_ms)
        session = AgentSession(
            owner_id=owner_id,
            agent_id=agent_id,
            device_id=device_id,
            grant_fp=grant_fp,
            opened_at_ms=now,
            expires_at_ms=expires,
        )
        self._store.append_session(session)
        log.info(
            "session.open id=%s agent=%s device=%s ttl_ms=%d",
            session.id,
            agent_id,
            device_id,
            expires - now,
        )
        return session

    def get(self, owner_id: str, session_id: str) -> AgentSession | None:
        return self._store.get_session(owner_id, session_id)

    def close(
        self, owner_id: str, session_id: str, now_ms: int | None = None
    ) -> AgentSession:
        session = self._require_live(owner_id, session_id, now_ms=now_ms, for_append=False)
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        session.closed_at_ms = now
        self._store.close_session(owner_id, session_id, now)
        return session

    def recent(self, owner_id: str, limit: int = 50) -> list[AgentSession]:
        return self._store.recent_sessions(owner_id, limit)

    # -- the blocks ----------------------------------------------------

    def append_block(
        self,
        *,
        owner_id: str,
        session_id: str,
        block: str,
        max_blocks: int,
        max_bytes: int,
        now_ms: int | None = None,
    ) -> StoredBlock:
        """Seals one block and stores it, or refuses.

        Refuses rather than truncates. A truncated scratchpad is a scratchpad
        that silently lost the part the decision turned on, and the agent has no
        way to tell -- the same asymmetry that makes a sealed record's absence
        better than a half-stored one.
        """
        session = self._require_live(owner_id, session_id, now_ms=now_ms, for_append=True)
        raw = block.encode()
        if not raw:
            raise SessionError("an empty block is not a block")
        if len(raw) > max_bytes:
            raise SessionError(
                f"block is {len(raw)} bytes, over the {max_bytes}-byte cap; "
                "split it rather than letting it be truncated"
            )
        if session.block_count >= max_blocks:
            raise SessionError(
                f"session {session_id} already holds {session.block_count} blocks, "
                f"the cap is {max_blocks}; close it and open another"
            )

        sealed = self._seal(raw)
        ref = self._blobs.put(owner_id, sealed)
        index = session.block_count
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        stored = StoredBlock(
            session_id=session_id,
            index=index,
            blob_id=ref.blob_id,
            patch_id=ref.patch_id,
            byte_len=ref.byte_len,
            backend=ref.backend,
            at_ms=now,
        )
        self._store.append_session_block(owner_id, stored)
        self._store.bump_session_counters(owner_id, session_id, blocks=1, bytes_=ref.byte_len)
        return stored

    def blocks(self, owner_id: str, session_id: str) -> list[StoredBlock]:
        """Where this session's blocks are, in order. Not what they say."""
        return self._store.session_blocks(owner_id, session_id)

    # -- internals -----------------------------------------------------

    def _seal(self, raw: bytes) -> bytes:
        """Seals a block in the enclave when there is one to seal with.

        A session block is working material -- file contents, tool output, what
        the person said -- so it is treated like a sensitive record body rather
        than like a resolved statement. With no gateway configured the bytes are
        stored as they are, which is the same bargain `ENCRYPT_CONTENT_AT_REST`
        already strikes and is why that setting defaults off: the smoke script
        and the eval run without a gateway.
        """
        if self._gateway is None:
            return raw
        return self._gateway.seal_encrypt(raw).ciphertext

    def _require_live(
        self,
        owner_id: str,
        session_id: str,
        *,
        now_ms: int | None,
        for_append: bool,
    ) -> AgentSession:
        session = self._store.get_session(owner_id, session_id)
        if session is None:
            # Says nothing about whether the id exists under another owner. A
            # session id from another owner must not be an existence oracle, the
            # same rule every traversal in this codebase follows.
            raise SessionError(f"no open session {session_id} for this owner")
        if for_append and not session.open:
            raise SessionError(f"session {session_id} is closed")
        if session.expired(now_ms):
            raise SessionError(
                f"session {session_id} expired at {session.expires_at_ms}; "
                "its grant may have too"
            )
        return session
