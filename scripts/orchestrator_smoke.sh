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

echo
echo "== 4. owner grants a scoped capability to agent-demo =="
GRANT=$(curl -sf -X POST "$GATEWAY_URL/memory/scope/grant" \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d "{\"ttl_secs\": 3600, \"scope\": {
        \"agent_id\": \"agent-demo\",
        \"owner_id\": \"$OWNER_ID\",
        \"sources\": [\"mock\"],
        \"entity_kinds\": [\"person\", \"project\", \"artifact\", \"organization\", \"topic\"],
        \"not_before_ms\": null, \"not_after_ms\": null,
        \"max_sensitivity\": \"confidential\", \"expires_at_ms\": null}}" | jq -r .grant_token)
echo "grant minted (${#GRANT} chars)"

echo
echo "== 5. query through the query graph (in scope) =="
curl -sf -X POST "$ORCH_URL/query" -H 'content-type: application/json' \
  -d "{\"question\": \"What datastore will project Atlas use?\", \"grant_token\": \"$GRANT\"}" \
  | jq '{answered, considered, text, citations: [.citations[] | {object_id, source, url}]}'

echo
echo "== 6. same query under a scope that permits nothing (expect a decline) =="
NARROW=$(curl -sf -X POST "$GATEWAY_URL/memory/scope/grant" \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d "{\"ttl_secs\": 3600, \"scope\": {
        \"agent_id\": \"agent-narrow\",
        \"owner_id\": \"$OWNER_ID\",
        \"sources\": [\"github\"],
        \"entity_kinds\": [\"organization\"],
        \"not_before_ms\": null, \"not_after_ms\": null,
        \"max_sensitivity\": \"public\", \"expires_at_ms\": null}}" | jq -r .grant_token)
curl -sf -X POST "$ORCH_URL/query" -H 'content-type: application/json' \
  -d "{\"question\": \"What datastore will project Atlas use?\", \"grant_token\": \"$NARROW\"}" \
  | jq '{answered, considered, text, denied: [.denied[] | .reason] | unique}'

echo
echo "Done. Logs: .local/orchestrator.log, .local/worker.log"
