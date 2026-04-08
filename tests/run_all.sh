#!/usr/bin/env bash
# Usage: ./run_all.sh [host] [port]
set -u
HOST="${1:-127.0.0.1}"
PORT="${2:-8080}"
DIR="$(dirname "$0")"
echo "=== Target: http://$HOST:$PORT ==="
for f in detect_timing.py smuggle_clte.py smuggle_tecl.py smuggle_tete.py; do
  echo
  echo "### $f"
  python "$DIR/$f" "$HOST" "$PORT" || true
done
