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
echo

# The connect flow: authorize -> callback. The code exchange happens inside
# the enclave and the refresh token is sealed before it comes back, so
# nothing printed below is token material.
echo "== GET /auth/authorize?provider=google =="
AUTHORIZE=$(curl -sf "$GATEWAY_URL/auth/authorize?provider=google")
echo "$AUTHORIZE" | jq '{scopes, authorize_url: (.authorize_url[0:96] + "...")}'
STATE=$(echo "$AUTHORIZE" | jq -r .state)
echo

echo "== GET /auth/callback (mock code -> sealed refresh token) =="
curl -sf "$GATEWAY_URL/auth/callback?code=mock_code_google_alice&state=$STATE" \
  | jq '{provider, owner_id: .identity.owner_id, scopes, seal_scheme, sealed_key_id, sealed_token_bytes}'
echo

echo "== replaying the same state is rejected (single-use PKCE verifier) =="
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  "$GATEWAY_URL/auth/callback?code=mock_code_google_alice&state=$STATE"
