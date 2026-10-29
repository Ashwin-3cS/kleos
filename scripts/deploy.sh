#!/usr/bin/env bash
# EC2 deploy path: build the EIF, ship it + parent_forwarder.sh to the
# parent instance, register and run the enclave, and start the gateway +
# forwarders. This is intentionally a documented skeleton -- Phase 1 does
# not include actual infra provisioning (Terraform/CDK/etc).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${DEPLOY_HOST:?set DEPLOY_HOST to the parent EC2 instance (user@host)}"

echo "1/4: Building EIF locally..."
"$ROOT_DIR/scripts/build_enclave.sh"

echo "2/4: Building gateway release binary..."
cargo build --release -p gateway

echo "3/4: Shipping artifacts to $DEPLOY_HOST..."
scp "$ROOT_DIR/enclave/out/kleos-enclave.eif" "$DEPLOY_HOST:~/kleos-enclave.eif"
scp "$ROOT_DIR/target/release/gateway" "$DEPLOY_HOST:~/kleos-gateway"
scp "$ROOT_DIR/scripts/parent_forwarder.sh" "$DEPLOY_HOST:~/parent_forwarder.sh"
scp "$ROOT_DIR/.env.example" "$DEPLOY_HOST:~/.env"

echo "4/4: On $DEPLOY_HOST, run:"
cat <<'EOF'
  nitro-cli run-enclave --cpu-count 2 --memory 4096 \
    --eif-path ~/kleos-enclave.eif --enclave-cid 16
  ./parent_forwarder.sh &
  # GATEWAY_BIND is loopback by default so a laptop does not serve the local
  # network. A parent instance has to be reachable, so it says so here --
  # behind TLS, because a grant token travels in a request body.
  ENCLAVE_MODE=nitro GATEWAY_BIND=0.0.0.0 ./kleos-gateway
EOF
