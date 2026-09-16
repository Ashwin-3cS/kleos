#!/usr/bin/env bash
# Builds the enclave's .eif image via the stagex-based Dockerfile, adapted
# from suiverify/nautilus-attestation-backend's Containerfile/Makefile.
# Requires docker (or podman) with the stagex registry reachable; not
# runnable in a sandboxed dev environment. Run from the repo root.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/enclave/out"
mkdir -p "$OUT_DIR"

echo "Building enclave EIF image (stagex/docker)..."
docker build -f "$ROOT_DIR/enclave/Dockerfile" -t memorai-enclave:latest --target package "$ROOT_DIR"

CONTAINER_ID=$(docker create memorai-enclave:latest)
docker cp "$CONTAINER_ID:/memorai.eif" "$OUT_DIR/memorai-enclave.eif"
docker cp "$CONTAINER_ID:/memorai.pcrs" "$OUT_DIR/memorai-enclave.pcrs"
docker rm "$CONTAINER_ID" > /dev/null

echo "Built $OUT_DIR/memorai-enclave.eif"
echo "PCRs: $OUT_DIR/memorai-enclave.pcrs"
echo "Register/run with: nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path $OUT_DIR/memorai-enclave.eif --enclave-cid 16"
