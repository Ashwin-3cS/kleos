"""A ceiling on the owner-driven write routes (ADR 0027).

`POST /remember` is synchronous, writes into memory, and spends an extraction
call per record. Unmetered, it is a way to fill somebody's memory and a way to
spend their budget, and the caller does not have to be hostile to do it -- a
client with a retry loop will manage it by accident.

**In Redis, not in the process.** Two API processes sharing nothing would each
enforce the limit and together enforce neither. Redis is already here for the
queue, so this adds a dependency on nothing new.

**A fixed window, not a token bucket.** A window is approximate: a caller can
get 2N across two adjacent windows. That does not matter for a ceiling meant to
stop loops rather than shape traffic, and the burst behaviour a bucket would
model is behaviour nobody has measured. When there is a measurement there is a
reason to pay for the state.

**Per owner, not per IP.** On an authenticated route the credential is what
identifies the writer. An IP ceiling is evadable by anyone who wants to evade it
and unfair to everyone behind one NAT.

**It fails open, and says so.** If Redis is unreachable the limiter allows the
call and logs. The alternative is a memory layer that stops accepting what the
person says because a counter is down, which trades a bounded abuse problem for
an unbounded availability one. Ingestion already refuses loudly when the
*gateway* is down, because that one cannot be degraded safely -- it would mean
writing plaintext. A missing rate limit means writing a record that was going to
be written anyway.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from redis import Redis
from redis.exceptions import RedisError

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Verdict:
    """Whether the call may proceed, and what to tell the caller if not."""

    allowed: bool
    limit: int
    window_secs: int
    #: Seconds until the current window ends. What goes in `Retry-After`.
    retry_after_secs: int = 0
    used: int = 0

    @property
    def detail(self) -> str:
        return (
            f"rate limit reached: {self.limit} per {self.window_secs}s for this owner. "
            f"Retry in {self.retry_after_secs}s."
        )


def check(
    redis: Redis,
    *,
    route: str,
    owner_id: str,
    limit: int,
    window_secs: int,
    now: float | None = None,
) -> Verdict:
    """Counts this call against ``owner_id``'s window for ``route``.

    ``now`` is injectable so the window boundary is testable; a limiter whose
    clock cannot be moved can only be tested by sleeping.

    ``limit <= 0`` disables the check, which is how a deployment turns it off
    without a second setting to keep in step with the first.
    """
    if limit <= 0:
        return Verdict(allowed=True, limit=limit, window_secs=window_secs)

    now = time.time() if now is None else now
    window = int(now // window_secs)
    # The window index is in the key, so an expired window is a key that no
    # longer exists rather than a counter something has to reset.
    key = f"kleos:ratelimit:{route}:{owner_id}:{window}"
    retry_after = max(1, int((window + 1) * window_secs - now))

    try:
        pipe = redis.pipeline()
        pipe.incr(key)
        # Set on every call rather than only the first: a key that lost its TTL
        # to a crash between INCR and EXPIRE would otherwise count forever.
        pipe.expire(key, window_secs + 1)
        used = int(pipe.execute()[0])
    except RedisError as exc:
        # See the module docstring: open, and loudly.
        log.warning(
            "rate limit check failed for route=%s owner=%s, allowing: %s", route, owner_id, exc
        )
        return Verdict(allowed=True, limit=limit, window_secs=window_secs)

    return Verdict(
        allowed=used <= limit,
        limit=limit,
        window_secs=window_secs,
        retry_after_secs=retry_after,
        used=used,
    )
