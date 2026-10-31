#!/usr/bin/env bash
# macOS/Linux twin of scripts/start.ps1: build the frontend, then serve API + dashboard offline on loopback.
#   ./scripts/start.sh [--skip-build] [--port 8001]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT=8000
SKIP_BUILD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1 ;;
    --port) PORT="${2:?--port needs a value}"; shift ;;
    --port=*) PORT="${1#--port=}" ;;
    -h|--help) sed -n 2,3p "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
PY=""
for p in "$ROOT/backend/.venv/bin/python" "$ROOT/.venv/bin/python"; do
  if [ -x "$p" ] && "$p" -c "import fastapi, uvicorn" 2>/dev/null; then PY="$p"; break; fi
done
[ -n "$PY" ] || { echo "Create backend/.venv (or .venv) and install backend/requirements.txt first. See README.md." >&2; exit 1; }
if [ "$SKIP_BUILD" -eq 0 ]; then
  "$PY" -X utf8 "$ROOT/scripts/export_scoring_config.py" || { echo "Could not export the central scoring configuration." >&2; exit 1; }
  (cd "$ROOT/frontend" && npm run build) || { echo "Frontend build failed." >&2; exit 1; }
fi
export DEMO_MODE=true PYTHONUTF8=1
echo "Vectra demo: http://127.0.0.1:$PORT/app"
echo "Offline cache mode. Press Ctrl+C to stop."
exec "$PY" -X utf8 -m uvicorn app.main:app --app-dir "$ROOT/backend" --host 127.0.0.1 --port "$PORT"
