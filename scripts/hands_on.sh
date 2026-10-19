#!/usr/bin/env bash
# Two devices, one graph, driven by hand instead of by a script.
#
# `orchestrator_smoke.sh` and `mcp_smoke.py` both prove the cross-device flow
# with no model in the loop, which is what makes them regression tests. This
# proves nothing: it sets the same thing up and then gets out of the way, so the
# agents on either end can be real ones. What it leaves behind is an orchestrator
# serving the MCP tools over HTTP and two grants signed by two different device
# keys -- one that may write, one that may only read.
#
#   ./scripts/run_local.sh          # gateway + enclave, first
#   ./scripts/hands_on.sh           # then this
#   ./scripts/hands_on.sh grants    # re-mint when the 8h TTL runs out
#   ./scripts/hands_on.sh stop
#
# Extraction is the mock one by default, so this needs no model and no key. To
# put a real model behind `record_decision` and `close_session(consolidate=true)`
# -- a local llama.cpp, say -- set EXTRACTOR=llm and point LLM_BASE_URL at it:
#
#   GATEWAY_PORT=8081 ./scripts/run_local.sh     # llama.cpp wants 8080
#   GATEWAY_URL=http://127.0.0.1:8081 \
#   EXTRACTOR=llm LLM_BASE_URL=http://127.0.0.1:8080/v1 \
#   EXTRACTION_MODEL=gemma-4-26b-a4b LLM_API_KEY=local LLM_TIMEOUT_SECS=300 \
#     ./scripts/hands_on.sh
#
# A key is still *required* even where it is ignored: the extractor refuses to
# construct without one rather than sending an unauthenticated request to
# whatever `LLM_BASE_URL` turns out to point at. Any string does for a local
# server. Raise the timeout: 60s is sized for a hosted provider and one record
# through a partly-offloaded 26B takes about a minute.
#
# Memory is deliberately *not* wiped: the whole point is that it outlives the
# session that wrote it.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORCH_DIR="$ROOT_DIR/orchestrator"
PY="${PY:-$ORCH_DIR/.venv/bin/python}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"
ORCH_URL="${ORCH_URL:-http://127.0.0.1:8090}"
OWNER_TOKEN="${OWNER_TOKEN:-mock_google_alice}"
TTL_SECS="${TTL_SECS:-28800}"
#: `auto` follows ORCHESTRATOR_MODE, which is mock here. `llm` opts in to a
#: real model for extraction and consolidation; see the header.
EXTRACTOR="${EXTRACTOR:-auto}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[ -x "$PY" ] || { echo "no venv at $PY; see orchestrator/README.md" >&2; exit 1; }
mkdir -p "$ROOT_DIR/.local"

stop() {
  for pidfile in "$ROOT_DIR/.local/orchestrator.pid" "$ROOT_DIR/.local/worker.pid"; do
    if [ -f "$pidfile" ]; then
      kill "$(cat "$pidfile")" 2>/dev/null && echo "stopped $(basename "$pidfile" .pid)" || true
      rm -f "$pidfile"
    fi
  done
}

[ "${1:-}" = "stop" ] && { stop; exit 0; }

SIGNER="$ROOT_DIR/target/debug/kleos-device"
[ -x "$SIGNER" ] || cargo build -q -p gateway --bin kleos-device

# The owner signs grants with a key only they hold; the gateway has no route
# that mints one (ADR 0011). So this behaves like a client: keygen once, register
# the public half, sign each scope locally.
mint_grants() {
  SESSION_JSON=$(curl -sf -X POST "$GATEWAY_URL/auth/session" \
    -H 'content-type: application/json' -d "{\"google_token\": \"$OWNER_TOKEN\"}")
  SESSION_TOKEN=$(echo "$SESSION_JSON" | jq -r .session_token)
  OWNER_ID=$(echo "$SESSION_JSON" | jq -r .identity.owner_id)

  for n in 1 2; do
    key="$ROOT_DIR/.local/hands-on-device$n.key"
    [ -f "$key" ] || "$SIGNER" keygen --key "$key" >/dev/null
    # Registration is idempotent by design: the binding between a signing key
    # and its X25519 half is the row, and re-registering must not move it.
    curl -s -X POST "$GATEWAY_URL/auth/device/register" \
      -H 'content-type: application/json' -H "Authorization: Bearer $SESSION_TOKEN" \
      -d "{\"public_key_b64\": \"$("$SIGNER" pubkey --key "$key")\", \"label\": \"hands-on-$n\"}" \
      >/dev/null
  done

  WRITER_GRANT=$("$SIGNER" sign --key "$ROOT_DIR/.local/hands-on-device1.key" \
    --scope - --ttl-secs "$TTL_SECS" <<JSON
{"agent_id": "claude-code-writer",
 "owner_id": "$OWNER_ID",
 "sources": ["mock", "agent", "text"],
 "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "confidential", "expires_at_ms": null,
 "may_write": true, "write_sources": ["agent"], "may_supersede_owner": true,
 "memory_kinds": ["episodic", "procedural", "tacit"]}
JSON
)
  READER_GRANT=$("$SIGNER" sign --key "$ROOT_DIR/.local/hands-on-device2.key" \
    --scope - --ttl-secs "$TTL_SECS" <<JSON
{"agent_id": "claude-code-reader",
 "owner_id": "$OWNER_ID",
 "sources": ["mock", "agent", "text"],
 "entity_kinds": ["person", "project", "artifact", "organization", "topic"],
 "not_before_ms": null, "not_after_ms": null,
 "max_sensitivity": "confidential", "expires_at_ms": null,
 "memory_kinds": ["episodic", "procedural", "tacit"]}
JSON
)
}

if [ "${1:-}" != "grants" ]; then
  echo "== gateway =="
  curl -sf "$GATEWAY_URL/health" | jq -c '{status, enclave: .enclave.reachable}'

  echo
  echo "== orchestrator + worker, MCP tools at $ORCH_URL/mcp (extractor: $EXTRACTOR) =="
  stop
  cd "$ORCH_DIR"
  export ORCHESTRATOR_MODE=mock EXTRACTOR GATEWAY_URL
  MCP_HTTP_ENABLED=1 "$PY" -m orchestrator.api \
    > "$ROOT_DIR/.local/orchestrator.log" 2>&1 &
  echo $! > "$ROOT_DIR/.local/orchestrator.pid"
  "$PY" -m orchestrator.jobs.worker \
    > "$ROOT_DIR/.local/worker.log" 2>&1 &
  echo $! > "$ROOT_DIR/.local/worker.pid"

  for _ in $(seq 1 40); do
    curl -sf "$ORCH_URL/health" >/dev/null 2>&1 && break
    sleep 0.5
  done
  curl -sf "$ORCH_URL/health" | jq -c '{status, mode, neo4j, redis}'
fi

mint_grants

cat <<TXT

== register the tools with Claude Code, once ==

  claude mcp add --transport http kleos $ORCH_URL/mcp/

The trailing slash matters: the app is mounted at /mcp and the endpoint inside
it is "/", so /mcp redirects and some clients drop the session header.

== the writing chat ==

Paste this, then talk normally:

  You have the kleos MCP tools. My grant token is:
  $WRITER_GRANT
  Pass it as grant_token on every kleos call. Open a session with open_session,
  and when I decide something, record it with record_decision.

== the reading chat (a different chat, or a different machine) ==

  You have the kleos MCP tools. My grant token is:
  $READER_GRANT
  Pass it as grant_token on every kleos call. Before you advise me on anything,
  call brief_before_acting with what I am about to do, and query_memory for
  anything you need. You cannot write.

Owner: $OWNER_ID. Grants expire in ${TTL_SECS}s; re-mint with
\`./scripts/hands_on.sh grants\`. Stop with \`./scripts/hands_on.sh stop\`.
Logs: .local/orchestrator.log, .local/worker.log
TXT
