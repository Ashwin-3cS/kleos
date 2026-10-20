#!/usr/bin/env bash
# Phase 2 end-to-end proof, mock mode throughout.
#
#   identity -> owner session -> ingestion job on RQ -> worker runs the
#   ingestion graph (fetch/extract/resolve/encrypt-in-enclave/write) ->
#   Neo4j -> scoped grant -> query graph -> answer with citations, then the
#   same query under a narrower scope, which declines.
#
# Prereqs: ./scripts/run_local.sh (enclave + gateway), and
# `docker compose up -d` in orchestrator/ (neo4j + redis).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORCH_DIR="$ROOT_DIR/orchestrator"
PY="${PY:-$ORCH_DIR/.venv/bin/python}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"
ORCH_URL="${ORCH_URL:-http://127.0.0.1:8090}"
OWNER_TOKEN="${OWNER_TOKEN:-mock_google_alice}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[ -x "$PY" ] || { echo "no venv at $PY; see orchestrator/README.md" >&2; exit 1; }

mkdir -p "$ROOT_DIR/.local"

cleanup() {
  for pidfile in "$ROOT_DIR/.local/orchestrator.pid" "$ROOT_DIR/.local/worker.pid"; do
    [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
  done
}
trap cleanup EXIT

echo "== 0. gateway reachable =="
curl -sf "$GATEWAY_URL/health" | jq -c '{status, enclave: .enclave.reachable}'

echo
echo "== 1. starting orchestrator API + RQ worker (mock mode) =="
cd "$ORCH_DIR"
ORCHESTRATOR_MODE=mock "$PY" -m orchestrator.api > "$ROOT_DIR/.local/orchestrator.log" 2>&1 &
echo $! > "$ROOT_DIR/.local/orchestrator.pid"
ORCHESTRATOR_MODE=mock "$PY" -m orchestrator.jobs.worker > "$ROOT_DIR/.local/worker.log" 2>&1 &
echo $! > "$ROOT_DIR/.local/worker.pid"

for _ in $(seq 1 40); do
  curl -sf "$ORCH_URL/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "$ORCH_URL/health" | jq -c '{status, mode, neo4j, redis}'

echo
echo "== 2. owner session from the enclave-verified identity =="
SESSION_JSON=$(curl -sf -X POST "$GATEWAY_URL/auth/session" \
  -H 'content-type: application/json' \
  -d "{\"google_token\": \"$OWNER_TOKEN\"}")
SESSION_TOKEN=$(echo "$SESSION_JSON" | jq -r .session_token)
OWNER_ID=$(echo "$SESSION_JSON" | jq -r .identity.owner_id)
echo "$SESSION_JSON" | jq -c '{owner_id: .identity.owner_id, trust_tier: .identity.trust_tier, attestation: (.attestation[0:24] + "...")}'

# Ingestion is idempotent, so a second run legitimately writes nothing new.
# Wipe first so the printed counts are always the first-ingest numbers.
if [ "${KEEP_MEMORY:-0}" != "1" ]; then
  echo
  echo "== 2b. clearing existing memory for this owner (KEEP_MEMORY=1 to skip) =="
  (cd "$ORCH_DIR" && ORCHESTRATOR_MODE=mock "$PY" - "$OWNER_ID" <<'PYEOF'
import sys
from orchestrator.config import get_settings
from orchestrator.storage.neo4j_store import Neo4jStore

settings = get_settings()
store = Neo4jStore(
    settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password, settings.neo4j_database
)
store.wipe_owner(sys.argv[1])
store.close()
print(f"wiped {sys.argv[1]}")
PYEOF
  )
fi

echo
echo "== 3. enqueue an ingestion job for the mock connector =="
JOB_ID=$(curl -sf -X POST "$ORCH_URL/ingest" \
  -H 'content-type: application/json' \
  -d "{\"owner_id\": \"$OWNER_ID\", \"source\": \"mock\", \"session_token\": \"$SESSION_TOKEN\"}" \
  | jq -r .job_id)
echo "job_id: $JOB_ID"

for _ in $(seq 1 60); do
  STATUS=$(curl -sf "$ORCH_URL/ingest/$JOB_ID" | jq -r .status)
  [ "$STATUS" = "finished" ] || [ "$STATUS" = "failed" ] && break
  sleep 1
done
curl -sf "$ORCH_URL/ingest/$JOB_ID" | jq '{status, result}'

# The owner signs grants with a key only they hold, so the script has to behave
# like a client: generate a device key once, register the public half, and sign
# each scope locally. The gateway has no route that mints one (ADR 0011).
DEVICE_KEY="$ROOT_DIR/.local/device.key"
SIGNER="$ROOT_DIR/target/debug/kleos-device"
[ -x "$SIGNER" ] || cargo build -q -p device --bin kleos-device
[ -f "$DEVICE_KEY" ] || "$SIGNER" keygen --key "$DEVICE_KEY" >/dev/null

echo
echo "== 4. register the owner's device key, then sign grants locally =="
PUBKEY=$("$SIGNER" pubkey --key "$DEVICE_KEY")
curl -sf -X POST "$GATEWAY_URL/auth/device/register" \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d "{\"public_key_b64\": \"$PUBKEY\",
       \"encryption_key_b64\": \"$("$SIGNER" pubkey --key "$DEVICE_KEY" --encryption)\",
       \"label\": \"smoke-test\"}" \
  | jq -c '{key_id, label, registered_at_ms}'

# Signs a scope read from stdin. The private key never leaves this machine.
sign_grant() { "$SIGNER" sign --key "$DEVICE_KEY" --scope - --ttl-secs 3600; }

echo
echo "== 4b. owner signs a scoped capability for agent-demo =="
GRANT=$(sign_grant <<JSON
{"agent_id": "agent-demo",
 "owner_id": "$OWNER_ID",
 "sources": ["mock"],
 "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "confidential", "expires_at_ms": null}
JSON
)
echo "grant signed by the owner's device key (${#GRANT} chars)"

echo
echo "== 5. query through the query graph (in scope) =="
curl -sf -X POST "$ORCH_URL/query" -H 'content-type: application/json' \
  -d "{\"question\": \"What datastore will project Atlas use?\", \"grant_token\": \"$GRANT\"}" \
  | jq '{answered, considered, text, citations: [.citations[] | {object_id, source, url}]}'

echo
echo "== 6. same query under a scope that permits nothing (expect a decline) =="
NARROW=$(sign_grant <<JSON
{"agent_id": "agent-narrow",
 "owner_id": "$OWNER_ID",
 "sources": ["github"],
 "entity_kinds": ["organization"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "personal", "expires_at_ms": null}
JSON
)
curl -sf -X POST "$ORCH_URL/query" -H 'content-type: application/json' \
  -d "{\"question\": \"What datastore will project Atlas use?\", \"grant_token\": \"$NARROW\"}" \
  | jq '{answered, considered, text, denied: [.denied[] | .reason] | unique}'

echo
echo "== 7. why did this decision shift, and what is it hanging off =="
CLAIM_ID=$(curl -sf -X POST "$ORCH_URL/query" -H 'content-type: application/json' \
  -d "{\"question\": \"What datastore will project Atlas use?\", \"grant_token\": \"$GRANT\"}" \
  | jq -r '[.citations[] | select(.object_id | startswith("clm_")) | .object_id][0]')
echo "seed claim: $CLAIM_ID"

curl -sf -X POST "$ORCH_URL/memory/shift" -H 'content-type: application/json' \
  -d "{\"claim_id\": \"$CLAIM_ID\", \"grant_token\": \"$GRANT\"}" \
  | jq '{answered, considered, text,
         steps: [.steps[] | {elapsed_ms, new_evidence: [.new_citations[] | "\(.connector)/\(.external_id)"]}]}'

curl -sf -X POST "$ORCH_URL/memory/context" -H 'content-type: application/json' \
  -d "{\"object_id\": \"$CLAIM_ID\", \"grant_token\": \"$GRANT\", \"hops\": 3}" \
  | jq '{answered, sources, considered, nodes: [.nodes[] | {id, hops, withheld}]}'

echo
echo "== 8. the same shift read under the narrow scope (expect a decline) =="
curl -sf -X POST "$ORCH_URL/memory/shift" -H 'content-type: application/json' \
  -d "{\"claim_id\": \"$CLAIM_ID\", \"grant_token\": \"$NARROW\"}" \
  | jq '{answered, considered, text, denied: [.denied[] | .reason] | unique}'

echo
echo "== 9. the graph neighbourhood around that claim (nodes + typed edges) =="
curl -sf -X POST "$ORCH_URL/memory/neighbourhood" -H 'content-type: application/json' \
  -d "{\"seed_ids\": [\"$CLAIM_ID\"], \"grant_token\": \"$GRANT\", \"hops\": 2}" \
  | jq '{answered, considered, withheld, withheld_edges, sources,
         labels: [.nodes[] | .label] | group_by(.) | map({(.[0]): length}) | add,
         edge_types: [.edges[] | .type] | group_by(.) | map({(.[0]): length}) | add}'

echo
echo "== 9b. the same neighbourhood under a grant that cannot read confidential =="
echo "       (denied nodes are dropped, not blanked -- only the count comes back)"
SHALLOW=$(sign_grant <<JSON
{"agent_id": "agent-shallow",
 "owner_id": "$OWNER_ID",
 "sources": ["mock"],
 "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "personal", "expires_at_ms": null}
JSON
)
curl -sf -X POST "$ORCH_URL/memory/neighbourhood" -H 'content-type: application/json' \
  -d "{\"seed_ids\": [\"$CLAIM_ID\"], \"grant_token\": \"$SHALLOW\", \"hops\": 2}" \
  | jq '{answered, considered, shown: (.nodes | length), withheld, withheld_edges,
         withheld_reasons, text}'

echo
echo "== 10. revoking a device key invalidates every grant it signed =="
echo "       (the first lever this system has for withdrawing a live capability)"
# A throwaway key, because revocation is deliberately terminal: re-registering a
# revoked key does NOT un-revoke it, or revocation would mean nothing. So the
# owner's main key stays usable and this demonstrates the lever on a spare.
SPARE_KEY="$ROOT_DIR/.local/device-spare.key"
rm -f "$SPARE_KEY"
"$SIGNER" keygen --key "$SPARE_KEY" >/dev/null
SPARE_PUB=$("$SIGNER" pubkey --key "$SPARE_KEY")
curl -sf -X POST "$GATEWAY_URL/auth/device/register" \
  -H 'content-type: application/json' -H "Authorization: Bearer $SESSION_TOKEN" \
  -d "{\"public_key_b64\": \"$SPARE_PUB\", \"label\": \"spare\"}" | jq -c '{key_id}'

SPARE_GRANT=$("$SIGNER" sign --key "$SPARE_KEY" --scope - --ttl-secs 3600 <<JSON
{"agent_id": "agent-spare",
 "owner_id": "$OWNER_ID",
 "sources": ["mock"],
 "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "confidential", "expires_at_ms": null}
JSON
)
echo -n "before revoking -> "
curl -sf -X POST "$GATEWAY_URL/memory/scope/introspect" -H 'content-type: application/json' \
  -d "{\"grant_token\": \"$SPARE_GRANT\"}" | jq -c '{active, agent: .scope.agent_id}'

SPARE_ID=$("$SIGNER" key-id --key "$SPARE_KEY")
curl -sf -X POST "$GATEWAY_URL/auth/device/revoke" \
  -H 'content-type: application/json' -H "Authorization: Bearer $SESSION_TOKEN" \
  -d "{\"key_id\": \"$SPARE_ID\"}" | jq -c .
echo -n "after revoking  -> "
curl -s -o /dev/null -w "HTTP %{http_code} (expect 401)\n" \
  -X POST "$GATEWAY_URL/memory/scope/introspect" -H 'content-type: application/json' \
  -d "{\"grant_token\": \"$SPARE_GRANT\"}"
rm -f "$SPARE_KEY"

# -- the harness, against the real stack -------------------------------------
#
# Everything above is one agent reading. What follows is the part several agents
# need, and it is deliberately run against the Rust gateway rather than against a
# stand-in: `scripts/mcp_smoke.py` already proves the same flow over MCP with a
# local grant resolver, so what this adds is the half that resolver stands in for
# -- a second registered device, real signature verification, and a capability
# the gateway actually enforces.

echo
echo "== 11. a second device, so \"which agent decided this\" is a real question =="
DEVICE_2_KEY="$ROOT_DIR/.local/device2.key"
[ -f "$DEVICE_2_KEY" ] || "$SIGNER" keygen --key "$DEVICE_2_KEY" >/dev/null
PUBKEY_2=$("$SIGNER" pubkey --key "$DEVICE_2_KEY")
curl -sf -X POST "$GATEWAY_URL/auth/device/register" \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d "{\"public_key_b64\": \"$PUBKEY_2\",
       \"encryption_key_b64\": \"$("$SIGNER" pubkey --key "$DEVICE_2_KEY" --encryption)\",
       \"label\": \"smoke-device-2\"}" \
  | jq -c '{key_id, label}'

DEVICE_1_ID=$("$SIGNER" key-id --key "$DEVICE_KEY")
DEVICE_2_ID=$("$SIGNER" key-id --key "$DEVICE_2_KEY")
echo "device 1: $DEVICE_1_ID"
echo "device 2: $DEVICE_2_ID"

# Device 1 may write and may replace the owner's own decisions. Device 2 only
# reads. Both are capabilities the owner signed; neither is anything the gateway
# could have granted itself.
WRITER_GRANT=$("$SIGNER" sign --key "$DEVICE_KEY" --scope - --ttl-secs 3600 <<JSON
{"agent_id": "claude-code",
 "owner_id": "$OWNER_ID",
 "sources": ["mock", "agent"],
 "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "confidential", "expires_at_ms": null,
 "may_write": true, "write_sources": ["agent"], "may_supersede_owner": true,
 "memory_kinds": ["episodic", "procedural", "tacit"]}
JSON
)
READER_GRANT=$("$SIGNER" sign --key "$DEVICE_2_KEY" --scope - --ttl-secs 3600 <<JSON
{"agent_id": "chatgpt",
 "owner_id": "$OWNER_ID",
 "sources": ["mock", "agent"],
 "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "confidential", "expires_at_ms": null,
 "memory_kinds": ["episodic", "procedural", "tacit"]}
JSON
)
echo -n "introspecting device 2's grant -> "
curl -sf -X POST "$GATEWAY_URL/memory/scope/introspect" -H 'content-type: application/json' \
  -d "{\"grant_token\": \"$READER_GRANT\"}" | jq -c '{agent: .scope.agent_id, key_id}'

echo
echo "== 12. device 2 briefs before acting -- only the corpus to go on =="
#      The mock corpus already supersedes its own storage decision, so there is
#      something to warn about before any agent writes. What is missing at this
#      point is an *agent* in the picture: every advisory names the owner's own
#      ingestion.
curl -sf -X POST "$ORCH_URL/memory/brief" -H 'content-type: application/json' \
  -d "{\"intent\": \"about to pick a datastore for project Atlas\", \"grant_token\": \"$READER_GRANT\"}" \
  | jq -c '{answered, advisories}'

echo
echo "== 13. device 1 records a decision that contradicts the corpus =="
# Through the orchestrator, which checks `may_write` against the scope the
# gateway verified. A grant without it is refused by name rather than ignored.
curl -sf -X POST "$ORCH_URL/memory/brief" -H 'content-type: application/json' \
  -d "{\"intent\": \"recording the datastore decision\", \"grant_token\": \"$WRITER_GRANT\"}" \
  > /dev/null
python3 - "$ORCH_URL" "$WRITER_GRANT" <<'PY'
import json, sys, urllib.request

orch, grant = sys.argv[1], sys.argv[2]
body = json.dumps(
    {
        "grant_token": grant,
        "statement": "project Atlas will use Neo4j for durable storage.",
        "reason": "graph proximity is a hard requirement and the relational option cannot do it",
        "memory_kind": "episodic",
    }
).encode()
req = urllib.request.Request(
    f"{orch}/memory/decide", data=body, headers={"content-type": "application/json"}
)
try:
    with urllib.request.urlopen(req) as response:
        print(json.dumps(json.load(response), indent=2)[:400])
except urllib.error.HTTPError as exc:
    print(f"HTTP {exc.code}: {exc.read().decode()[:200]}")
PY

echo
echo "== 14. device 2 briefs again, and is told what device 1 decided =="
curl -sf -X POST "$ORCH_URL/memory/brief" -H 'content-type: application/json' \
  -d "{\"intent\": \"about to pick a datastore for project Atlas\", \"grant_token\": \"$READER_GRANT\"}" \
  | jq -r '.advisories[]? // "(nothing to warn about)"'

echo
echo "== 15. the owner reads both logs: what was seen, and what was changed =="
echo -n "reads by device    -> "
curl -sf -X POST "$ORCH_URL/memory/reads" -H 'content-type: application/json' \
  -d "{\"session_token\": \"$SESSION_TOKEN\", \"limit\": 50}" \
  | jq -c '[.grants[] | {agent_id, device_id, reads}]'
echo -n "changes with rules -> "
curl -sf -X POST "$ORCH_URL/memory/mutations" -H 'content-type: application/json' \
  -d "{\"session_token\": \"$SESSION_TOKEN\", \"limit\": 10}" \
  | jq -c '[.entries[] | select(.rule != null) | {kind, rule, device: .actor_device_id}] | unique'

echo
echo "== 16. an action the grant does not name (expect a refusal) =="
# The broker's own refusals are covered by gateway/ and enclave/ tests; what this
# proves is that the capability is enforced where the grant is verified.
curl -s -o /dev/null -w "POST /memory/act -> HTTP %{http_code} (expect 401)\n" \
  -X POST "$GATEWAY_URL/memory/act" -H 'content-type: application/json' \
  -d "{\"grant_token\": \"$READER_GRANT\", \"action_id\": \"attest.digest\", \"args\": {\"digest\": \"abc\"}}"

echo
echo "== 17. the owner's view of what the agents have been working on =="
# Owner-authenticated, like the two logs above: a listing across sessions tells
# whoever asks what every *other* agent has been doing. `undistilled` is the
# freshness signal, and it needs `consolidated_at_ms` -- an empty claim list
# cannot separate "not distilled yet" from "distilled, concluded nothing", and
# the second is the common case.
curl -sf -X POST "$ORCH_URL/memory/sessions" -H 'content-type: application/json' \
  -d "{\"session_token\": \"$SESSION_TOKEN\", \"limit\": 20}" \
  | jq -c '{sessions, undistilled, devices: [.entries[].device_id] | unique}'

# Expect zeroes here, and that is not the step passing vacuously by accident:
# a session is opened by an agent over MCP and there is no HTTP route that opens
# one, so this walkthrough has none to list. What this proves is the route, its
# shape and its auth. That it reports *correctly* with data in it is
# `scripts/mcp_smoke.py` and `tests/test_dashboard_routes.py`, which open real
# sessions and assert the freshness count.
echo -n "actions taken      -> "
curl -sf -X POST "$ORCH_URL/memory/actions" -H 'content-type: application/json' \
  -d "{\"session_token\": \"$SESSION_TOKEN\", \"limit\": 20}" \
  | jq -c '{actions, entries: [.entries[] | {action_id, ok}]}'

echo
echo "== 18. an owner session is not a grant, and the routes say so =="
# The two auth modes take a string that looks identical and mean entirely
# different things. A grant presented to an owner route must fail rather than
# degrade into a narrower answer: these routes have no object-level filtering to
# fall back on, so "partly authorised" is not a state they can be in.
for route in sessions actions reads mutations; do
  curl -s -o /dev/null -w "  grant -> /memory/$route -> HTTP %{http_code} (expect 401)\n" \
    -X POST "$ORCH_URL/memory/$route" -H 'content-type: application/json' \
    -d "{\"session_token\": \"$READER_GRANT\"}"
done

echo
echo "== 19. the explorer and the dashboard are served =="
curl -sf -o /dev/null -w "GET /explorer -> %{http_code} (%{size_download} bytes)\n" "$ORCH_URL/explorer"
curl -s -o /dev/null -w "GET /ui       -> %{http_code} (%{size_download} bytes)\n" "$ORCH_URL/ui"
# The provider's redirect target. It has to be served by *this* origin rather
# than the gateway's, which is the whole reason the browser can read the session
# token: the gateway's /auth/callback returns JSON and runs no script.
curl -s -o /dev/null -w "GET /ui/oauth/land -> %{http_code} (expect 200)\n" \
  "$ORCH_URL/ui/oauth/land?code=x&state=y"

echo
echo "Open $ORCH_URL/ui to issue a grant without writing one by hand, or"
echo "$ORCH_URL/explorer to paste a grant token and browse what it can see."
echo
echo "Done. Logs: .local/orchestrator.log, .local/worker.log"
