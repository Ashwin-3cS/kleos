#!/usr/bin/env bash
# Runs gateway + enclave locally in mock mode (no Nitro, no VSOCK, no
# socat): the enclave binds 127.0.0.1:4000 directly and the gateway dials
# it as a normal TCP loopback connection. Exercises the full request path
# end to end via CLI without EC2.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export ENCLAVE_MODE=mock
export ENCLAVE_PORT="${ENCLAVE_PORT:-4000}"
export GATEWAY_PORT="${GATEWAY_PORT:-8080}"
export ENCLAVE_HOST="${ENCLAVE_HOST:-127.0.0.1}"
export SESSION_JWT_SECRET="${SESSION_JWT_SECRET:-dev-insecure-secret-change-me}"

mkdir -p "$ROOT_DIR/.local"

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
echo "Run scripts/smoke_test.sh to exercise the full path, and scripts/view_logs.sh to tail logs."
echo "Kill both with: kill \$(cat .local/enclave.pid) \$(cat .local/gateway.pid)"
