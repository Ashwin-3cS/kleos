#!/usr/bin/env bash
# Host-side VSOCK forwarders, adapted from
# suiverify/nautilus-attestation-backend/parent_forwarder.sh. Run this on
# the EC2 parent instance alongside a running enclave. Redis/Government-API/
# Sui-specific forwarders from the original are dropped; replaced with the
# new port plan (see README.md's VSOCK ports table).
set -uo pipefail

for port in 8002 8003 8004 8005 8006 8007 5000; do
    pkill -f "VSOCK-LISTEN:$port" || true
done
sudo pkill -f "socat.*VSOCK:.*:4000" || true
sleep 1

echo "Starting parent forwarder..."

# These carry TLS streams the enclave established and this host cannot read;
# each one must land on the exact host the enclave's certificate check
# expects. See enclave/src/services/http.rs for the authoritative table.
echo "Forwarding VSOCK 8002 -> www.googleapis.com (Google tokeninfo)..."
socat VSOCK-LISTEN:8002,fork,reuseaddr TCP:www.googleapis.com:443 &

echo "Forwarding VSOCK 8003 -> api.github.com (GitHub user API)..."
socat VSOCK-LISTEN:8003,fork,reuseaddr TCP:api.github.com:443 &

echo "Forwarding VSOCK 8006 -> oauth2.googleapis.com (Google token endpoint)..."
socat VSOCK-LISTEN:8006,fork,reuseaddr TCP:oauth2.googleapis.com:443 &

echo "Forwarding VSOCK 8007 -> github.com (GitHub token endpoint)..."
socat VSOCK-LISTEN:8007,fork,reuseaddr TCP:github.com:443 &

echo "Forwarding VSOCK 8004 -> Walrus publisher/aggregator..."
socat VSOCK-LISTEN:8004,fork,reuseaddr TCP:"${WALRUS_PUBLISHER_HOST:-publisher.walrus-testnet.walrus.space}":443 &

echo "Forwarding VSOCK 8005 -> Walrus Memory relayer..."
socat VSOCK-LISTEN:8005,fork,reuseaddr TCP:"${WALRUS_MEMORY_RELAYER_HOST:-127.0.0.1}":"${WALRUS_MEMORY_RELAYER_PORT:-9000}" &

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/enclave.log"
touch "$LOG_FILE"
echo "Starting enclave log listener on VSOCK port 5000 -> $LOG_FILE"
socat VSOCK-LISTEN:5000,fork,reuseaddr OPEN:"$LOG_FILE",creat,append,wronly &

(
  echo "[port4000-bridge] Waiting for enclave to start..."
  for i in $(seq 1 24); do
    sleep 5
    NEW_CID=$(sudo nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].EnclaveCID // empty')
    if [ -n "$NEW_CID" ]; then
      sudo pkill -f "socat.*VSOCK:$NEW_CID:4000" 2>/dev/null || true
      sleep 1
      sudo socat TCP-LISTEN:4000,reuseaddr,fork VSOCK:$NEW_CID:4000 &
      echo "[port4000-bridge] Connected port 4000 -> enclave CID $NEW_CID"
      break
    fi
    echo "[port4000-bridge] Attempt $i: no enclave yet, retrying..."
  done
) &

echo "Parent forwarders running. Ctrl-C to stop."
wait
