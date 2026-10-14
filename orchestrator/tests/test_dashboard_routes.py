"""The routes the owner's dashboard needs, and the one confusion that must not happen.

Three of these are listings the harness itself never asks for -- sessions,
actions -- because an agent addresses the session it already holds and has no
business enumerating what every *other* agent has been doing. That is why they
are owner-authenticated, and the first test here is the one that matters: the two
auth modes take a string that looks identical and mean entirely different things.
A grant says "this agent may read these objects"; a session says "this is the
person". Confusing them in this direction hands an agent the owner's own view of
every other agent's activity.

The fourth, `/memory/consolidate`, is a *write* and is grant-authenticated even
though the owner presses the button -- the dashboard signs a short-lived grant
with the owner's own device key instead of reaching for an owner-authority path,
so one gate still decides every claim-producing write. See ADR 0023.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from orchestrator import api as api_module
from orchestrator.config import Settings
from orchestrator.graphs.decide import WriteRefused
from orchestrator.graphs.runtime import Runtime
from orchestrator.storage.actions import ActionEntry
from orchestrator.storage.sessions import SessionError

OWNER = "owner-dashboard-routes"
SESSION_TOKEN = "owner-session-for-the-dashboard"
GRANT_TOKEN = "a-grant-not-a-session"
DEVICE_1 = "device-1a2b3c"
DEVICE_2 = "device-9z8y7x"


class _Gateway:
    """Resolves the owner session and nothing else.

    `introspect_session` is the gateway's job because the orchestrator holds no
    signing key, so a stub here is standing in for an HTTP round trip. It refuses
    anything that is not the one session token, which is what lets the grant-token
    test below be a real test rather than a tautology.
    """

    def __init__(self) -> None:
        self.calls = 0

    def introspect_session(self, session_token: str) -> str:
        self.calls += 1
        if session_token != SESSION_TOKEN:
            raise RuntimeError("session is not active")
        return OWNER

    def close(self) -> None:
        pass


@pytest.fixture
def client(settings: Settings, store, monkeypatch):
    rt = Runtime.build(settings=settings, migrate=False)
    rt.gateway = _Gateway()
    _wipe(rt)
    monkeypatch.setattr(api_module, "_runtime", rt)
    with TestClient(api_module.app) as c:
        # The app's own lifespan would build a second runtime and overwrite the
        # one wired above, so it is re-pinned after startup rather than before.
        monkeypatch.setattr(api_module, "_runtime", rt)
        yield c
    _wipe(rt)
    rt.close()


def _wipe(rt: Runtime) -> None:
    rt.store.wipe_owner(OWNER)
    rt.store.wipe_sessions(OWNER)
    rt.store.wipe_actions(OWNER)
    rt.store.wipe_read_log(OWNER)


def _open(rt: Runtime, device_id: str):
    return rt.sessions.open_session(
        owner_id=OWNER,
        agent_id="claude-code",
        device_id=device_id,
        grant_fp="fp-dashboard",
        ttl_secs=600,
    )


# -- the confusion that must not happen ---------------------------------

OWNER_ROUTES = ["/memory/sessions", "/memory/actions", "/memory/reads", "/memory/mutations"]


@pytest.mark.parametrize("route", OWNER_ROUTES)
def test_a_grant_token_is_refused_where_an_owner_session_is_required(
    client: TestClient, route: str
) -> None:
    """The whole reason `require_owner` was extracted into one function.

    Four copies of this check drift, and the copy that drifts is the one nobody
    reads. A grant presented here must fail, not degrade into a narrower answer:
    these routes have no object-level filtering to fall back on, so "partly
    authorised" is not a state they can be in.
    """
    response = client.post(route, json={"session_token": GRANT_TOKEN})
    assert response.status_code == 401
    assert "owner session" in response.json()["detail"]


@pytest.mark.parametrize("route", OWNER_ROUTES)
def test_an_owner_route_never_takes_a_grant_token_field(
    client: TestClient, route: str
) -> None:
    """From the other direction: there must be no `grant_token` argument to reach
    for. A route accepting both is one refactor away from accepting either."""
    response = client.post(route, json={"grant_token": GRANT_TOKEN})
    assert response.status_code == 422


# -- sessions -----------------------------------------------------------


def test_sessions_are_listed_per_device(client: TestClient) -> None:
    rt = api_module.runtime()
    _open(rt, DEVICE_1)
    _open(rt, DEVICE_2)

    body = client.post(
        "/memory/sessions", json={"session_token": SESSION_TOKEN}
    ).json()
    assert body["sessions"] == 2
    assert {e["device_id"] for e in body["entries"]} == {DEVICE_1, DEVICE_2}

    only_1 = client.post(
        "/memory/sessions",
        json={"session_token": SESSION_TOKEN, "device_id": DEVICE_1},
    ).json()
    assert only_1["sessions"] == 1
    assert only_1["entries"][0]["device_id"] == DEVICE_1


def test_a_session_listing_carries_no_block_content(client: TestClient) -> None:
    """A session node is an index into the blob store. Listing is the owner's
    "how much, from whom, distilled or not" question, and answering it must not
    unseal anything -- the answer to "what did it say" is consolidation, which is
    a write and is gated as one."""
    rt = api_module.runtime()
    session = _open(rt, DEVICE_1)
    secret = "the thing the agent was actually working on"
    rt.sessions.append_block(
        owner_id=OWNER,
        session_id=session.id,
        block=secret,
        max_blocks=10,
        max_bytes=10_000,
    )

    body = client.post("/memory/sessions", json={"session_token": SESSION_TOKEN}).json()
    assert secret not in repr(body)
    assert body["entries"][0]["block_count"] == 1


def test_undistilled_counts_sessions_that_have_never_been_consolidated(
    client: TestClient,
) -> None:
    """The freshness signal, and the reason `consolidated_at_ms` had to exist.

    An empty `consolidated_into` cannot answer this: it means *either* "not yet"
    *or* "ran and concluded nothing", and the second is the common outcome. So a
    client inferring freshness from the claim list would tell the owner to keep
    pressing a button that has already done its work.
    """
    rt = api_module.runtime()
    fresh = _open(rt, DEVICE_1)
    rt.sessions.append_block(
        owner_id=OWNER, session_id=fresh.id, block="not yet distilled",
        max_blocks=10, max_bytes=10_000,
    )
    ran = _open(rt, DEVICE_2)
    rt.sessions.append_block(
        owner_id=OWNER, session_id=ran.id, block="distilled, concluded nothing",
        max_blocks=10, max_bytes=10_000,
    )
    # Consolidation ran and wrote nothing, which is the ambiguous case.
    rt.store.mark_session_consolidated(OWNER, ran.id, 1_700_000_000_000)

    body = client.post("/memory/sessions", json={"session_token": SESSION_TOKEN}).json()
    assert body["undistilled"] == 1

    by_id = {e["id"]: e for e in body["entries"]}
    assert by_id[fresh.id]["consolidated_at_ms"] is None
    assert by_id[ran.id]["consolidated_at_ms"] == 1_700_000_000_000
    assert by_id[ran.id]["consolidated_into"] == [], (
        "the claim list is empty in both cases -- that is the point"
    )


def test_an_empty_session_is_not_counted_as_undistilled(client: TestClient) -> None:
    """A session that was opened and never used has nothing to distil, so
    reporting it as work pending would be a permanent false positive."""
    rt = api_module.runtime()
    _open(rt, DEVICE_1)
    body = client.post("/memory/sessions", json={"session_token": SESSION_TOKEN}).json()
    assert body["sessions"] == 1
    assert body["undistilled"] == 0


def test_the_session_listing_never_crosses_owners(client: TestClient) -> None:
    rt = api_module.runtime()
    _open(rt, DEVICE_1)
    assert rt.sessions.recent("someone-else") == []


# -- actions ------------------------------------------------------------


def test_actions_are_listed_with_their_outcome_and_without_arguments(
    client: TestClient,
) -> None:
    """A failed action is in here too: "tried and failed" is a different fact
    from "never tried", and only the first is something an owner needs to know.
    The arguments are not, because an action's arguments are the content it acted
    on."""
    rt = api_module.runtime()
    for ok, digest in ((True, "3f9adead"), (False, "")):
        rt.store.append_action(
            ActionEntry(
                owner_id=OWNER,
                action_id="attest.digest",
                agent_id="claude-code",
                device_id=DEVICE_1,
                ok=ok,
                digest=digest,
                summary="attested a digest",
                args_fp="deadbeef",
                error=None if ok else "action is declared and not wired",
            )
        )

    body = client.post("/memory/actions", json={"session_token": SESSION_TOKEN}).json()
    assert body["actions"] == 2
    assert {e["ok"] for e in body["entries"]} == {True, False}
    assert all("args" not in e or e.get("args") is None for e in body["entries"])
    assert all(e["args_fp"] == "deadbeef" for e in body["entries"])


# -- consolidate --------------------------------------------------------


def test_a_refused_consolidation_is_an_answer_not_an_error(
    client: TestClient, monkeypatch
) -> None:
    """`201` with `refused: true`, as `/memory/decide` does. A status code alone
    cannot say "your grant may write, but not as that source"."""
    def _refuse(*_args, **_kwargs):
        raise WriteRefused("write_not_permitted")

    monkeypatch.setattr(api_module, "consolidate_session", _refuse)
    response = client.post(
        "/memory/consolidate",
        json={"grant_token": GRANT_TOKEN, "session_id": "ses_whatever"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["refused"] is True
    assert body["reason"] == "write_not_permitted"


def test_an_unknown_session_is_a_404(client: TestClient, monkeypatch) -> None:
    def _missing(*_args, **_kwargs):
        raise SessionError("no session ses_nope for this owner")

    monkeypatch.setattr(api_module, "consolidate_session", _missing)
    response = client.post(
        "/memory/consolidate",
        json={"grant_token": GRANT_TOKEN, "session_id": "ses_nope"},
    )
    assert response.status_code == 404


def test_consolidation_reports_what_it_refused_alongside_what_it_wrote(
    client: TestClient, monkeypatch
) -> None:
    """The partial result the dashboard must not render as a clean run.

    `consolidate_session` catches a refusal *per conclusion* so that a grant
    covering episodes but not procedures keeps the episodes. That is the right
    behaviour and it means a narrow grant produces a success with an `errors`
    list, which is indistinguishable from a clean run unless the caller looks.
    """
    from orchestrator.graphs.decide import Consolidated

    monkeypatch.setattr(
        api_module,
        "consolidate_session",
        lambda *_a, **_k: Consolidated(
            owner_id=OWNER,
            session_id="ses_partial",
            blocks=9,
            claims=["clm_kept"],
            conclusions=[{"kind": "episodic", "statement": "kept"}],
            errors=["procedural: memory_kind_not_in_scope"],
        ),
    )
    body = client.post(
        "/memory/consolidate",
        json={"grant_token": GRANT_TOKEN, "session_id": "ses_partial"},
    ).json()
    assert body["refused"] is False
    assert body["claims"] == ["clm_kept"]
    assert body["errors"] == ["procedural: memory_kind_not_in_scope"]


def test_consolidate_takes_a_grant_and_not_an_owner_session(client: TestClient) -> None:
    """The deliberate asymmetry: this is the one dashboard route that is *not*
    owner-authenticated, because it is a write. See ADR 0023."""
    response = client.post(
        "/memory/consolidate", json={"session_token": SESSION_TOKEN, "session_id": "x"}
    )
    assert response.status_code == 422


# -- the page itself ----------------------------------------------------


def test_the_dashboard_says_so_when_it_has_not_been_built(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    """A dashboard that 404s when the assets are missing reads as a wrong URL.
    This is a checkout that has not run the build, which is a different thing and
    has a different fix."""
    monkeypatch.setattr(api_module, "_UI", tmp_path / "nothing-here")
    response = client.get("/ui")
    assert response.status_code == 503
    assert "npm run build" in response.json()["detail"]


def test_every_dashboard_path_serves_the_same_page(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    """Client-side routing, and specifically what makes `/ui/oauth/land` work: it
    is the provider's redirect target, so it has to be served by this origin
    rather than by the gateway's -- that is the whole reason the browser can read
    the session token at all."""
    built = tmp_path / "ui"
    built.mkdir()
    (built / "index.html").write_text("<!doctype html><title>Kleos</title>")
    monkeypatch.setattr(api_module, "_UI", built)

    for path in ("/ui", "/ui/access", "/ui/oauth/land?code=abc&state=def"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "Kleos" in response.text
