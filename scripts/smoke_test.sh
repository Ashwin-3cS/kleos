#!/usr/bin/env bash
# Posts a mock Google token through the gateway to the enclave and prints
# back identity + trust_tier + attestation. Run scripts/run_local.sh first.
set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"

echo "== gateway /health =="
curl -sf "$GATEWAY_URL/health" | jq .
echo

echo "== POST /identity/verify (mock Google token) =="
curl -sf -X POST "$GATEWAY_URL/identity/verify" \
  -H "content-type: application/json" \
  -d '{"google_token": "mock_google_alice"}' | jq .
echo

echo "== POST /identity/verify (mock Google + GitHub, trust tier 2) =="
curl -sf -X POST "$GATEWAY_URL/identity/verify" \
  -H "content-type: application/json" \
  -d '{"google_token": "mock_google_alice", "github_token": "mock_github_alice"}' | jq .
