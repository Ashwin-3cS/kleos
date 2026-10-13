#!/usr/bin/env python3
"""Drives the MCP server from a real client, which nothing had ever done.

`test_mcp_server.py` asserts the tool surface by importing the module and
calling `list_tools()` in-process. That catches a tool registered twice or a
signature changed, and it caught the server being unimportable at all -- but a
transport nothing has spoken to is a transport nothing has tested. Everything
between `mcp.run()` and a tool body was unexercised: the stdio framing, the JSON
schema the SDK generates from each signature, how an exception becomes a protocol
error, whether a `dict` argument survives the round trip.

So this is a client. No model in the loop: it calls tools in a fixed order and
asserts what came back, which makes it a regression test rather than a demo.

**The fifth step is the whole product.** Device 1 records a decision; device 2
reconnects under its own grant, asks nothing about device 1, and is told what it
decided and why. If that assertion fails, the harness does not work, whatever
the unit tests say.

    ./scripts/services.sh up
    python3 scripts/mcp_smoke.py

Needs Neo4j and the orchestrator's venv. Needs no gateway: grants are resolved
through a local stand-in, for the reason the eval harness uses one -- standing up
the Rust stack to prove the *transport* would make this harder to run than it has
to be, and `scripts/orchestrator_smoke.sh` already proves the gateway round trip.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORCHESTRATOR = ROOT / "orchestrator"
VENV_PYTHON = ORCHESTRATOR / ".venv" / "bin" / "python"

OWNER = "owner-mcp-smoke"
DEVICE_1 = "device-1a2b3c"
DEVICE_2 = "device-9z8y7x"

DECIDED = "project Lantern will use Neo4j for durable storage."
BECAUSE = "graph proximity is a hard requirement and Postgres cannot do it"
INTENT = "about to pick a database for project Lantern"

#: The grants, as the stand-in gateway will read them. Device 1 may write and may
#: replace the owner's own decisions; device 2 only reads. Two devices under one
#: owner is the shape the whole feature is about, so the smoke test has to have
#: two rather than simulate one.
GRANTS = {
    "device-1-writer": {
        "device_id": DEVICE_1,
        "scope": {
            "agent_id": "claude-code",
            "owner_id": OWNER,
            "sources": ["agent", "text"],
            "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
            "max_sensitivity": "confidential",
            "may_write": True,
            "write_sources": ["agent"],
            "may_supersede_owner": True,
            "memory_kinds": ["episodic", "procedural", "tacit"],
        },
    },
    "device-2-reader": {
        "device_id": DEVICE_2,
        "scope": {
            "agent_id": "chatgpt",
            "owner_id": OWNER,
            "sources": ["agent", "text"],
            "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
            "max_sensitivity": "confidential",
            "memory_kinds": ["episodic", "procedural", "tacit"],
        },
    },
}

#: Injected into the server process, which reads it to build the stand-in. Passed
#: through the environment rather than written to disk, so a stray file cannot
#: become a grant somebody later trusts.
GRANTS_ENV = "KLEOS_MCP_SMOKE_GRANTS"

EXPECTED_TOOLS = {
    "query_memory",
    "why_this_shifted",
    "memory_context_chain",
    "open_session",
    "append_context",
    "close_session",
    "brief_before_acting",
    "record_decision",
    "request_action",
}


def fail(message: str) -> None:
    print(f"\n  FAILED: {message}\n", file=sys.stderr)
    raise SystemExit(1)


def check(condition: object, message: str) -> None:
    if not condition:
        fail(message)


async def main() -> None:
    try:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
    except ImportError as exc:  # pragma: no cover - environment problem
        fail(f"the MCP client SDK is not importable: {exc}")

    if not VENV_PYTHON.exists():
        fail(f"no venv at {VENV_PYTHON}; see orchestrator/README.md")

    env = dict(os.environ)
    env.update(
        {
            "ORCHESTRATOR_MODE": "mock",
            GRANTS_ENV: json.dumps(GRANTS),
            # `scripts/sitecustomize.py` is imported automatically by the
            # child interpreter and installs a local grant resolver, so proving
            # the transport does not need the Rust stack up. It no-ops unless
            # KLEOS_MCP_SMOKE is set, below.
            "PYTHONPATH": str(ROOT / "scripts"),
            "KLEOS_MCP_SMOKE": "1",
        }
    )

    params = StdioServerParameters(
        command=str(VENV_PYTHON),
        args=["-m", "orchestrator.mcp_server"],
        env=env,
        cwd=str(ORCHESTRATOR),
    )

    _wipe()

    print("connecting to the MCP server over stdio...")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. The surface, from the outside. The first thing that would catch
            #    a tool whose generated schema does not match its signature.
            listed = await session.list_tools()
            names = {tool.name for tool in listed.tools}
            check(
                names == EXPECTED_TOOLS,
                f"tool surface differs: missing {EXPECTED_TOOLS - names}, "
                f"unexpected {names - EXPECTED_TOOLS}",
            )
            print(f"  list_tools: {len(names)} tools, as expected")

            # 2. Device 1 opens a session. The device id must be the one the
            #    grant was signed by, not the agent label.
            opened = await call(session, "open_session", {"grant_token": "device-1-writer"})
            check(
                opened.get("device_id") == DEVICE_1,
                f"open_session named {opened.get('device_id')!r}, expected {DEVICE_1!r}",
            )
            check(
                opened.get("identity_basis") == "device_key",
                "a grant resolved to a device must report device_key, not label",
            )
            session_id = opened["session_id"]
            print(f"  open_session: {session_id} on {opened['device_id']}")

            # 3. Working context goes in, and must not be searchable.
            appended = await call(
                session,
                "append_context",
                {
                    "session_id": session_id,
                    "grant_token": "device-1-writer",
                    "block": "benchmarked both options; the traversal queries settle it",
                },
            )
            check(
                appended.get("searchable") is False,
                "a session block must report itself as not searchable",
            )
            print("  append_context: stored, not searchable")

            # 4. Device 2 briefs first, before anything has been decided.
            before = await call(
                session,
                "brief_before_acting",
                {"intent": INTENT, "grant_token": "device-2-reader"},
            )
            print(f"  brief (device 2, before): answered={before.get('answered')}")

            # 5. Device 1 records a decision.
            recorded = await call(
                session,
                "record_decision",
                {
                    "grant_token": "device-1-writer",
                    "statement": DECIDED,
                    "reason": BECAUSE,
                    "session_id": session_id,
                },
            )
            check(
                recorded.get("device_id") == DEVICE_1,
                "the decision must be attributed to the signing device",
            )
            check(
                recorded.get("claims", 0) >= 1,
                f"no claim was written: {recorded}",
            )
            print(
                f"  record_decision: {recorded['claims']} claim(s), "
                f"authority={recorded['authority']}"
            )

            # 6. **The whole product.** Device 2 asks nothing about device 1 and
            #    is told what it decided, which device decided it, and why.
            after = await call(
                session,
                "brief_before_acting",
                {"intent": INTENT, "grant_token": "device-2-reader"},
            )
            advisories = " ".join(after.get("advisories", []))
            check(after.get("answered"), f"the briefing found nothing: {after}")
            check(
                DEVICE_1[:12] in advisories,
                f"the briefing did not name device 1:\n    {advisories}",
            )
            check(
                BECAUSE in advisories,
                f"the briefing did not carry device 1's reason:\n    {advisories}",
            )
            check(
                "device-authenticated" in advisories,
                "the briefing must say whether the identity is authenticated",
            )
            print("  brief (device 2, after): names device 1 and carries its reason")
            for line in after["advisories"]:
                print(f"      {line}")

            # 7. A refusal is a real answer, and has to survive the transport
            #    *as* an answer. It did not: raising reached the client as
            #    "Error executing tool record_decision" with the reason stripped,
            #    which is indistinguishable from a bug. Found here, fixed by
            #    returning the refusal.
            refused = await call(
                session,
                "record_decision",
                {
                    "grant_token": "device-2-reader",
                    "statement": "project Lantern will use Redis.",
                    "reason": "no reason at all",
                },
            )
            check(
                refused.get("refused") is True,
                f"a read-only grant should be refused, got: {refused}",
            )
            check(
                refused.get("reason") == "write_not_permitted",
                f"a refusal has to name its reason, got: {refused}",
            )
            print(f"  record_decision (device 2): refused -- {refused['reason']}")

            # 8. The action broker, as far as it can be driven from here. There
            #    is no gateway in this run, so what this exercises is the tool,
            #    the transport and the error path -- not the broker's own
            #    refusals, which are covered in `gateway/tests` (two capability
            #    checks) and `enclave/tests` (an ack that carries no credential).
            #    Asserted anyway, because a tool that cannot even fail cleanly
            #    over MCP is a tool nobody can use.
            acked = await call(
                session,
                "request_action",
                {
                    "action_id": "attest.digest",
                    "grant_token": "device-1-writer",
                    "args": {"digest": "deadbeef"},
                },
                expect_error=True,
            )
            check(bool(acked), "request_action failed without saying anything")
            print("  request_action: fails cleanly with no gateway reachable")

            # 9. Close without consolidating, which is the common outcome.
            closed = await call(
                session,
                "close_session",
                {"session_id": session_id, "grant_token": "device-1-writer"},
            )
            check(closed.get("closed_at_ms"), "close_session did not close anything")
            print("  close_session: closed, nothing consolidated")

    print("\nmcp_smoke: ok -- the harness works over a real client\n")


def _wipe() -> None:
    """Clears this owner before running, which the first version did not.

    Without it the script accumulates: a second run sees the claims the first
    wrote, two claims state the same decision for different reasons, and the
    briefing correctly renders both -- correctly, and confusingly, because the
    older one was written before a defect this very script found was fixed. A
    smoke test whose output depends on how many times it has been run is not one.

    Done from here rather than inside the server, because the script already
    needs the venv and this keeps the server free of a test-only branch.
    """
    sys.path.insert(0, str(ORCHESTRATOR / "src"))
    from orchestrator.config import Settings
    from orchestrator.storage.neo4j_store import Neo4jStore

    settings = Settings()
    store = Neo4jStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
        settings.neo4j_database,
        embedding_dim=settings.embedding_dim,
    )
    try:
        store.verify()
    except Exception as exc:  # noqa: BLE001
        fail(f"neo4j is not reachable at {settings.neo4j_uri}: {exc}")
    for wipe in (
        store.wipe_owner,
        store.wipe_read_log,
        store.wipe_sessions,
        store.wipe_mutations,
        store.wipe_actions,
    ):
        wipe(OWNER)
    store.close()
    print(f"cleared {OWNER}")


async def call(
    session, tool: str, arguments: dict, *, expect_error: bool = False
) -> dict | str:
    """Calls one tool and unwraps the result.

    An MCP tool result is content blocks, so a caller has to parse what the
    server serialised -- which is exactly the layer an in-process test skips and
    the thing most likely to differ between SDK versions.
    """
    result = await session.call_tool(tool, arguments)
    # `is_error`, not `isError`: the SDK's 2.0 renamed it, and an in-process test
    # that calls the tool function directly never touches either. This line is
    # most of why the file exists.
    text = "\n".join(
        getattr(block, "text", "") for block in result.content
    ).strip()
    if result.is_error:
        if expect_error:
            return text
        fail(f"{tool} failed: {text}")
    if expect_error:
        fail(f"{tool} was expected to fail and did not: {text}")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"text": text}


if __name__ == "__main__":
    asyncio.run(main())
