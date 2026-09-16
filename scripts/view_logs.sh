#!/usr/bin/env bash
# Tails logs. Locally (mock mode) that's the run_local.sh output files;
# on the parent EC2 instance it's the enclave.log written by
# parent_forwarder.sh's VSOCK log listener (port 5000).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -f "$ROOT_DIR/.local/enclave.log" ] || [ -f "$ROOT_DIR/.local/gateway.log" ]; then
  echo "Tailing local mock-mode logs (Ctrl-C to stop)..."
  tail -f "$ROOT_DIR/.local/enclave.log" "$ROOT_DIR/.local/gateway.log"
elif [ -f "$ROOT_DIR/scripts/enclave.log" ]; then
  echo "Tailing parent-forwarded enclave.log (Ctrl-C to stop)..."
  tail -f "$ROOT_DIR/scripts/enclave.log"
else
  echo "No logs found yet. Run scripts/run_local.sh (local) or scripts/parent_forwarder.sh (EC2) first." >&2
  exit 1
fi
