#!/usr/bin/env bash
# Runs gateway + enclave locally in mock mode (no Nitro, no VSOCK, no
# socat): the enclave binds 127.0.0.1:4000 directly and the gateway dials
# it as a normal TCP loopback connection. Exercises the full request path
# end to end via CLI without EC2.
#
# With --with-orchestrator it also brings up the Phase 2 backing services
# (Neo4j + Redis via orchestrator/docker-compose.yml). The orchestrator's
# own API and RQ worker are started by scripts/orchestrator_smoke.sh, which
# owns their lifetime.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export ENCLAVE_MODE=mock
export ENCLAVE_PORT="${ENCLAVE_PORT:-4000}"
export GATEWAY_PORT="${GATEWAY_PORT:-8080}"
export ENCLAVE_HOST="${ENCLAVE_HOST:-127.0.0.1}"
export SESSION_JWT_SECRET="${SESSION_JWT_SECRET:-dev-insecure-secret-change-me}"
export OAUTH_STATE_SECRET="${OAUTH_STATE_SECRET:-dev-insecure-oauth-state-secret}"
# Placeholder client ids so /auth/authorize is exercisable with no real OAuth
# app. The matching *secrets* would go in the enclave's environment, not here,
# and mock-mode code exchange never uses either.
export GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-mock-google-client-id}"
export GITHUB_CLIENT_ID="${GITHUB_CLIENT_ID:-mock-github-client-id}"
export GOOGLE_REDIRECT_URI="${GOOGLE_REDIRECT_URI:-http://127.0.0.1:$GATEWAY_PORT/auth/callback}"
export GITHUB_REDIRECT_URI="${GITHUB_REDIRECT_URI:-http://127.0.0.1:$GATEWAY_PORT/auth/callback}"
# Unset by default: the gateway then uses its in-memory sealed-token store.
# Point this at the compose Postgres to persist across restarts.
export SEALED_TOKEN_STORE_URL="${SEALED_TOKEN_STORE_URL:-}"

WITH_ORCHESTRATOR=0
for arg in "$@"; do
  case "$arg" in
    --with-orchestrator) WITH_ORCHESTRATOR=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

mkdir -p "$ROOT_DIR/.local"

if [ "$WITH_ORCHESTRATOR" = "1" ]; then
  echo "Starting Neo4j + Redis for the orchestrator..."
  docker compose -f "$ROOT_DIR/orchestrator/docker-compose.yml" up -d
fi

echo "Building enclave (mock feature, default)..."
cargo build -p enclave

echo "Building gateway..."
cargo build -p gateway

echo "Starting enclave on :$ENCLAVE_PORT..."
RUST_LOG=info "$ROOT_DIR/target/debug/enclave" > "$ROOT_DIR/.local/enclave.log" 2>&1 &
echo $! > "$ROOT_DIR/.local/enclave.pid"

echo "Starting gateway on :$GATEWAY_PORT..."
RUST_LOG=info "$ROOT_DIR/target/debug/gateway" > "$ROOT_DIR/.local/gateway.log" 2>&1 &
echo $! > "$ROOT_DIR/.local/gateway.pid"

echo "Enclave PID: $(cat "$ROOT_DIR/.local/enclave.pid")   log: .local/enclave.log"
echo "Gateway PID: $(cat "$ROOT_DIR/.local/gateway.pid")   log: .local/gateway.log"
echo "Run scripts/smoke_test.sh for the Phase 1 identity path, and scripts/view_logs.sh to tail logs."
if [ "$WITH_ORCHESTRATOR" = "1" ]; then
  echo "Run scripts/orchestrator_smoke.sh for the Phase 2 ingest -> query path."
fi
echo "Kill both with: kill \$(cat .local/enclave.pid) \$(cat .local/gateway.pid)"
