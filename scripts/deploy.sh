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
scp "$ROOT_DIR/enclave/out/memorai-enclave.eif" "$DEPLOY_HOST:~/memorai-enclave.eif"
scp "$ROOT_DIR/target/release/gateway" "$DEPLOY_HOST:~/memorai-gateway"
scp "$ROOT_DIR/scripts/parent_forwarder.sh" "$DEPLOY_HOST:~/parent_forwarder.sh"
scp "$ROOT_DIR/.env.example" "$DEPLOY_HOST:~/.env"

echo "4/4: On $DEPLOY_HOST, run:"
cat <<'EOF'
  nitro-cli run-enclave --cpu-count 2 --memory 4096 \
    --eif-path ~/memorai-enclave.eif --enclave-cid 16
  ./parent_forwarder.sh &
  ENCLAVE_MODE=nitro ./memorai-gateway
EOF
