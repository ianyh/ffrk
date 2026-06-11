#!/usr/bin/env bash
# Run ffrk.xyz locally exactly as it behaves in production: a static server for
# the GitHub Pages content, with the Cloudflare Worker (wrangler dev) in front
# so pretty permalinks (/20210006, /m/?ids=…) and embed tags work.
#
# Then open http://localhost:8787/  (NOT :8000 — that's the bare static origin).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATIC_PORT=8000
WORKER_PORT=8787

echo "Static origin → http://localhost:$STATIC_PORT"
python3 -m http.server "$STATIC_PORT" --directory "$ROOT" >/tmp/ffrk-static.log 2>&1 &
STATIC_PID=$!
trap 'kill "$STATIC_PID" 2>/dev/null || true' EXIT

echo "Worker        → http://localhost:$WORKER_PORT"
cd "$ROOT/worker"
exec npx wrangler dev --env dev --port "$WORKER_PORT"
