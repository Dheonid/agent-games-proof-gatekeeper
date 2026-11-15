#!/usr/bin/env bash
# Fetch the official Gatekeeper circuit artifacts (wasm + zkey) when missing.
# Source of truth: https://agentgames.zkverify.io/circuits (public, from /api/circuit-info).
# Idempotent: skips files that already exist and are non-empty.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p circuits
BASE="https://agentgames.zkverify.io/circuits"
if [ ! -s circuits/gatekeeper.wasm ]; then
  echo "[fetch-circuits] downloading gatekeeper.wasm ..."
  curl -fsSL --max-time 120 -o circuits/gatekeeper.wasm "$BASE/gatekeeper.wasm"
fi
if [ ! -s circuits/gatekeeper_final.zkey ]; then
  echo "[fetch-circuits] downloading gatekeeper_final.zkey ..."
  curl -fsSL --max-time 120 -o circuits/gatekeeper_final.zkey "$BASE/gatekeeper_final.zkey"
fi
ls -la circuits/
