"""The two routes that used to write to memory with no credential (ADR 0027).

`POST /ingest` and `POST /remember` took `owner_id` from the request body and
authenticated nothing, so on any reachable address naming somebody was enough
to write into their memory -- into the record the briefing quotes and the
resolver reasons over, with the owner's own provenance on it.

The tests here are the ones that would catch that coming back. Three shapes:

- **the credential is required**, and a grant is not one;
- **the owner is derived**, and `owner_id` is not a field to send;
- **the ceiling exists**, per owner, and a refusal says what the limit was.

`test_a_grant_token_is_refused_where_an_owner_session_is_required` in
`test_dashboard_routes.py` is the same test for the four read routes. These are
the write ones, which is the half that was missing.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from orchestrator import api as api_module
from orchestrator.config import Settings
from orchestrator.graphs.runtime import Runtime
from orchestrator.jobs import limits

OWNER = "owner-write-door"
OTHER_OWNER = "owner-somebody-else"
SESSION_TOKEN = "owner-session-for-the-write-door"
GRANT_TOKEN = "a-grant-not-a-session"

WRITE_ROUTES = ["/ingest", "/remember"]


class _Gateway:
    """Resolves the one session token and refuses everything else.

    Standing in for an HTTP round trip to the gateway, which is where session
    verification belongs because the orchestrator holds no signing key.
    """

    def introspect_session(self, session_token: str) -> str:
        if session_token != SESSION_TOKEN:
            raise RuntimeError("session is not active")
        return OWNER

    def close(self) -> None:
        pass


class _Job:
    def __init__(self, job_id: str, owner_id: str) -> None:
        self.id = job_id
        self.kwargs = {"owner_id": owner_id}

    def get_status(self, refresh: bool = False) -> str:
        return "finished"

    def return_value(self, refresh: bool = False) -> dict:
        return {"records": 1}

    exc_info = None


class _Queue:
    """Enqueues nothing and remembers what it was asked to enqueue."""

    def __init__(self) -> None:
        self.enqueued: list[dict] = []
        self.jobs: dict[str, _Job] = {}

    def enqueue(self, _fn, **kwargs):
        self.enqueued.append(kwargs)
        job = _Job(f"job-{len(self.enqueued)}", kwargs["owner_id"])
        self.jobs[job.id] = job
        return job

    def fetch_job(self, job_id: str):
        return self.jobs.get(job_id)


@pytest.fixture
def queue(monkeypatch) -> _Queue:
    q = _Queue()
    monkeypatch.setattr(api_module, "get_queue", lambda *a, **k: q)
    return q


@pytest.fixture
def client(settings: Settings, store, monkeypatch, queue):
    rt = Runtime.build(settings=settings, migrate=False)
    rt.gateway = _Gateway()
    rt.store.wipe_owner(OWNER)
    monkeypatch.setattr(api_module, "_runtime", rt)
    # The real limiter against a counter in memory, rather than a stub of the
    # limiter: that way the route's own call is exercised and a test can lower
    # the ceiling to see a 429. The default ceiling is far above what any test
    # here sends.
    counter = _Redis()
    monkeypatch.setattr(api_module, "get_redis", lambda *a, **k: counter)
    with TestClient(api_module.app) as c:
        monkeypatch.setattr(api_module, "_runtime", rt)
        yield c
    rt.store.wipe_owner(OWNER)
    rt.close()


# -- the credential is required -----------------------------------------


#: The smallest valid body for each route, minus the credential. `/ingest`
#: forbids unknown fields and `/remember` needs `text`, so one shared body
#: would fail for the wrong reason on one of them.
BODIES = {"/ingest": {"source": "mock"}, "/remember": {"text": "something"}}


@pytest.mark.parametrize("route", WRITE_ROUTES)
def test_a_write_route_refuses_a_request_with_no_session(client: TestClient, route: str) -> None:
    response = client.post(route, json=BODIES[route])
    assert response.status_code == 422, response.text
    assert "session_token" in response.text


@pytest.mark.parametrize("route", WRITE_ROUTES)
def test_a_grant_token_is_refused_where_an_owner_session_is_required(
    client: TestClient, route: str
) -> None:
    """A grant must fail here, not degrade into a narrower write.

    `/remember` attributes the record to the *owner*, so a grant authorising it
    would hand any write-capable agent the ability to write as the person --
    which is the precedence boundary ADR 0017's authority classes exist to
    defend. An agent with something to record has `record_decision`.
    """
    response = client.post(route, json={**BODIES[route], "session_token": GRANT_TOKEN})
    assert response.status_code == 401
    assert "owner session" in response.json()["detail"]


# -- the owner is derived -----------------------------------------------


@pytest.mark.parametrize("route", WRITE_ROUTES)
def test_a_write_route_will_not_take_an_owner_id(client: TestClient, route: str) -> None:
    """The defect itself, as a test.

    Forbidden rather than ignored: silently dropping it would answer 201 to a
    caller who believes they chose whose memory they wrote into.
    """
    response = client.post(
        route,
        json={**BODIES[route], "session_token": SESSION_TOKEN, "owner_id": OTHER_OWNER},
    )
    assert response.status_code == 422
    assert "owner_id" in response.text


def test_ingest_enqueues_under_the_session_owner(client: TestClient, queue: _Queue) -> None:
    response = client.post("/ingest", json={"session_token": SESSION_TOKEN, "source": "mock"})
    assert response.status_code == 202, response.text
    assert queue.enqueued == [
        {"owner_id": OWNER, "source": "mock", "since_ms": 0, "session_token": SESSION_TOKEN}
    ]


def test_remember_writes_under_the_session_owner(client: TestClient) -> None:
    response = client.post(
        "/remember",
        json={"session_token": SESSION_TOKEN, "text": "The window seat is the one I want."},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["external_id"]
    rt = api_module.runtime()
    # Written under the session's owner, and nowhere else.
    assert rt.store.recent_entities(OWNER) is not None
    assert rt.store.recent_entities(OTHER_OWNER) == []


# -- job status is owner-scoped -----------------------------------------


def test_job_status_needs_a_bearer_session(client: TestClient, queue: _Queue) -> None:
    client.post("/ingest", json={"session_token": SESSION_TOKEN, "source": "mock"})
    assert client.get("/ingest/job-1").status_code == 401
    assert client.get("/ingest/job-1", headers={"Authorization": "Basic x"}).status_code == 401
    ok = client.get("/ingest/job-1", headers={"Authorization": f"Bearer {SESSION_TOKEN}"})
    assert ok.status_code == 200
    assert ok.json()["status"] == "finished"


def test_another_owners_job_is_404_and_not_403(client: TestClient, queue: _Queue) -> None:
    """403 would confirm the job exists.

    A sequence of job ids would then be an oracle for who else uses this
    deployment and how often -- which is a different and worse leak than the
    job's contents.
    """
    queue.jobs["job-theirs"] = _Job("job-theirs", OTHER_OWNER)
    response = client.get(
        "/ingest/job-theirs", headers={"Authorization": f"Bearer {SESSION_TOKEN}"}
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "no such job job-theirs"


# -- the ceiling --------------------------------------------------------


class _Redis:
    """Counts, and nothing else. Enough for a fixed-window limiter."""

    def __init__(self, fail: bool = False) -> None:
        self.counts: dict[str, int] = {}
        self.fail = fail
        self.expires: list[tuple[str, int]] = []

    def pipeline(self):
        return _Pipeline(self)


class _Pipeline:
    def __init__(self, redis: _Redis) -> None:
        self.redis = redis
        self.ops: list = []

    def incr(self, key: str) -> None:
        self.ops.append(("incr", key))

    def expire(self, key: str, ttl: int) -> None:
        self.ops.append(("expire", key, ttl))

    def execute(self) -> list:
        if self.redis.fail:
            from redis.exceptions import RedisError

            raise RedisError("down")
        out = []
        for op in self.ops:
            if op[0] == "incr":
                self.redis.counts[op[1]] = self.redis.counts.get(op[1], 0) + 1
                out.append(self.redis.counts[op[1]])
            else:
                self.redis.expires.append((op[1], op[2]))
                out.append(True)
        return out


def _check(redis, owner=OWNER, limit=3, now=1000.0, route="remember"):
    return limits.check(
        redis, route=route, owner_id=owner, limit=limit, window_secs=60, now=now
    )


def test_the_limit_allows_up_to_n_then_refuses():
    redis = _Redis()
    assert [_check(redis).allowed for _ in range(3)] == [True, True, True]
    refused = _check(redis)
    assert not refused.allowed
    assert refused.retry_after_secs > 0
    assert "3 per 60s" in refused.detail


def test_the_limit_is_per_owner():
    redis = _Redis()
    for _ in range(3):
        _check(redis)
    assert not _check(redis).allowed
    # Somebody else's window is untouched: one owner cannot exhaust another's.
    assert _check(redis, owner=OTHER_OWNER).allowed


def test_the_limit_is_per_route():
    redis = _Redis()
    for _ in range(3):
        _check(redis, route="remember")
    assert not _check(redis, route="remember").allowed
    assert _check(redis, route="ingest").allowed


def test_a_new_window_starts_fresh():
    redis = _Redis()
    for _ in range(3):
        _check(redis, now=1000.0)
    assert not _check(redis, now=1000.0).allowed
    # 1000 // 60 == 16; 1080 // 60 == 18. A different window, a different key.
    assert _check(redis, now=1080.0).allowed


def test_the_ttl_is_set_on_every_call_not_only_the_first():
    """A key that lost its TTL between INCR and EXPIRE would count forever."""
    redis = _Redis()
    for _ in range(3):
        _check(redis)
    assert len(redis.expires) == 3
    assert {ttl for _, ttl in redis.expires} == {61}


def test_a_limit_of_zero_disables_the_check():
    redis = _Redis()
    for _ in range(10):
        assert _check(redis, limit=0).allowed
    # Nothing was counted, so turning it off costs no round trip either.
    assert redis.counts == {}


def test_it_fails_open_when_redis_is_down():
    """Deliberate, and argued in `jobs/limits.py`.

    Refusing writes because a counter is unreachable trades a bounded abuse
    problem for an unbounded availability one. Contrast ingestion with the
    gateway down, which refuses *because* the alternative is writing plaintext.
    """
    assert _check(_Redis(fail=True)).allowed


def test_the_route_returns_429_with_retry_after(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_module.get_settings(), "remember_rate_limit", 1, raising=False)

    body = {"session_token": SESSION_TOKEN, "text": "one thing"}
    assert client.post("/remember", json=body).status_code == 201
    refused = client.post("/remember", json={**body, "text": "another thing"})
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) > 0
    assert "rate limit reached" in refused.json()["detail"]
