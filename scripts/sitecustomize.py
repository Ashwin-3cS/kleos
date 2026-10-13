"""Installs a local grant resolver into the MCP server, for `mcp_smoke.py` only.

The server resolves a grant by asking the gateway. Proving the *transport* should
not require the Rust stack to be up -- the same reasoning the eval harness uses
for its own stand-in, and `scripts/orchestrator_smoke.sh` already proves the
gateway round trip.

Python imports `sitecustomize` automatically at interpreter start if it is
importable, so putting this directory on the child's `PYTHONPATH` patches the
client before `orchestrator.mcp_server` builds anything. That is the only hook
that runs early enough without editing the server, and not editing the server is
the point: a smoke test that needs a test-only branch inside the thing it tests
is not testing it.

**It no-ops unless `KLEOS_MCP_SMOKE` is set.** A file named `sitecustomize.py`
on `PYTHONPATH` affects every interpreter started with that path, so it has to
refuse to do anything by default.
"""

from __future__ import annotations

import json
import os

if os.environ.get("KLEOS_MCP_SMOKE") == "1":  # pragma: no branch - a guard
    _GRANTS = json.loads(os.environ.get("KLEOS_MCP_SMOKE_GRANTS", "{}"))

    def _install() -> None:
        from orchestrator.gateway_client import GatewayClient, ResolvedGrant
        from orchestrator.permissions import Scope
        from orchestrator.storage.reads import grant_fingerprint

        def introspect_grant(self, grant_token: str) -> ResolvedGrant:
            entry = _GRANTS.get(grant_token)
            if entry is None:
                raise ValueError(f"unknown grant {grant_token!r}")
            return ResolvedGrant(
                scope=Scope.model_validate(entry["scope"]),
                # The device the grant would have been signed by. Fixed per
                # grant, because the whole point of the smoke test is that two
                # devices stay distinguishable.
                device_id=entry["device_id"],
                grant_fp=grant_fingerprint(grant_token),
            )

        def introspect_scope(self, grant_token: str) -> Scope:
            return self.introspect_grant(grant_token).scope

        def seal_encrypt(self, plaintext: bytes):
            # Nothing in the smoke path is sensitive, and a stand-in that
            # pretended to seal would be the one thing this file must not do.
            raise NotImplementedError("mcp_smoke runs without an enclave")

        GatewayClient.introspect_grant = introspect_grant
        GatewayClient.introspect_scope = introspect_scope
        GatewayClient.seal_encrypt = seal_encrypt

    try:
        _install()
    except Exception as exc:  # pragma: no cover - surfaced by the smoke test
        import sys

        print(f"mcp_smoke: could not install the grant resolver: {exc}", file=sys.stderr)
