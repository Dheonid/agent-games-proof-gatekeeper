#!/usr/bin/env bash
# Start (or revive) the Proof Gatekeeper agent, detached so it survives
# the end of this shell session (VM restarts still wipe processes —
# re-run this script after a restart to revive the agent).
#
# Usage: ./start.sh [port]     (default port 8787)
# Stop:  kill "$(cat logs/server.pid)"
# Logs:  logs/server.log
#
# Loads .env if present (AGENT_GAMES_HMAC_SECRET etc.).
# Without AGENT_GAMES_HMAC_SECRET the server still starts, but POST
# /agent returns 500 until the real secret is set (dashboard -> Rotate
# Secret) and the server is restarted.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p logs data
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi
export PORT="${1:-${PORT:-8787}}"
if [ -f logs/server.pid ] && kill -0 "$(cat logs/server.pid)" 2>/dev/null; then
  echo "[start] already running (pid $(cat logs/server.pid), port $PORT). Stop it first: kill \"\$(cat logs/server.pid)\""
  exit 1
fi
if [ -z "${AGENT_GAMES_HMAC_SECRET:-}" ]; then
  echo "[start] WARNING: AGENT_GAMES_HMAC_SECRET is not set — POST /agent will return 500." >&2
  echo "[start] Set it in .env (dashboard -> Rotate Secret) and restart." >&2
fi
setsid nohup node server.js > logs/server.log 2>&1 < /dev/null &
echo $! > logs/server.pid
sleep 1
if curl -s -m 5 "http://127.0.0.1:${PORT}/health" >/dev/null; then
  echo "[start] Proof Gatekeeper running: pid $(cat logs/server.pid), http://127.0.0.1:${PORT}/agent"
  echo "[start] log: logs/server.log"
else
  echo "[start] FAILED to start — see logs/server.log" >&2
  cat logs/server.log >&2
  exit 1
fi
