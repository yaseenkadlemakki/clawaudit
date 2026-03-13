#!/usr/bin/env bash
# ClawAudit local start script
# Always starts on fixed ports: frontend :3000, backend :18790
# Kills any existing processes on those ports first.
set -euo pipefail

FRONTEND_PORT=3000
BACKEND_PORT=18790
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$REPO_DIR/.logs"

mkdir -p "$LOG_DIR"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[clawaudit]${NC} $*"; }
success() { echo -e "${GREEN}[clawaudit]${NC} $*"; }
warn()    { echo -e "${YELLOW}[clawaudit]${NC} $*"; }
err()     { echo -e "${RED}[clawaudit]${NC} $*"; }

# ── Kill whatever is on a port ────────────────────────────────────────────────
kill_port() {
  local port=$1
  local pids
  # macOS: lsof; Linux fallback: fuser
  if command -v lsof &>/dev/null; then
    pids=$(lsof -ti :"$port" 2>/dev/null || true)
  elif command -v fuser &>/dev/null; then
    pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\n' || true)
  fi
  if [[ -n "${pids:-}" ]]; then
    warn "Port $port in use (PIDs: $pids) — killing..."
    # Graceful SIGTERM first, then SIGKILL if needed
    echo "$pids" | xargs kill 2>/dev/null || true
    local attempt=0
    while [[ $attempt -lt 5 ]]; do
      sleep 1
      local remaining=""
      if command -v lsof &>/dev/null; then
        remaining=$(lsof -ti :"$port" 2>/dev/null || true)
      elif command -v fuser &>/dev/null; then
        remaining=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\n' || true)
      fi
      [[ -z "${remaining:-}" ]] && break
      attempt=$((attempt + 1))
      if [[ $attempt -ge 3 ]]; then
        echo "$remaining" | xargs kill -9 2>/dev/null || true
      fi
    done
    success "Port $port cleared"
  fi
}

# ── Wait for a port to be ready ───────────────────────────────────────────────
wait_for_port() {
  local port=$1 name=$2 timeout=${3:-30} health_path=${4:-/} i=0
  info "Waiting for $name on :$port..."
  until curl -sf "http://localhost:$port$health_path" &>/dev/null; do
    sleep 1
    i=$((i+1))
    if [[ $i -ge $timeout ]]; then
      err "$name did not start in ${timeout}s — check $LOG_DIR"
      return 1
    fi
  done
  success "$name ready on :$port"
}

# ── Python interpreter ────────────────────────────────────────────────────────
PYTHON=""
for py in python3.11 python3 python; do
  if command -v "$py" &>/dev/null; then PYTHON="$py"; break; fi
done
[[ -z "$PYTHON" ]] && { err "Python not found"; exit 1; }

# ── Node ─────────────────────────────────────────────────────────────────────
command -v node &>/dev/null || { err "Node.js not found"; exit 1; }

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  ClawAudit — Local Deploy${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Clear ports ───────────────────────────────────────────────────────────────
kill_port "$BACKEND_PORT"
kill_port "$FRONTEND_PORT"

# ── Install dependencies ──────────────────────────────────────────────────────
info "Installing Python deps..."
"$PYTHON" -m pip install -e ".[backend,dev]" -q 2>&1 | grep -v "^$" | grep -v "already satisfied" || true

info "Installing Node deps..."
(cd "$REPO_DIR/frontend" && npm install --silent 2>/dev/null) || true

# ── Start backend ─────────────────────────────────────────────────────────────
info "Starting backend on :$BACKEND_PORT..."
"$PYTHON" -m uvicorn backend.main:app \
  --host 127.0.0.1 \
  --port "$BACKEND_PORT" \
  --reload \
  > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$LOG_DIR/backend.pid"

# ── Start frontend (PORT env forces Next.js to use exactly this port) ─────────
info "Starting frontend on :$FRONTEND_PORT..."
cd "$REPO_DIR/frontend"
PORT=$FRONTEND_PORT npm run dev \
  > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "$FRONTEND_PID" > "$LOG_DIR/frontend.pid"
cd "$REPO_DIR"

# ── Wait for both to be ready ─────────────────────────────────────────────────
sleep 3
wait_for_port "$BACKEND_PORT"  "Backend"  20 "/api/v1/status"
wait_for_port "$FRONTEND_PORT" "Frontend" 30 "/"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓ ClawAudit is running${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Dashboard  →  ${CYAN}http://localhost:$FRONTEND_PORT/dashboard${NC}"
echo -e "  API        →  ${CYAN}http://localhost:$BACKEND_PORT/api/v1${NC}"
echo -e "  API Docs   →  ${CYAN}http://localhost:$BACKEND_PORT/docs${NC}"
echo -e "  Logs       →  ${CYAN}$LOG_DIR/${NC}"
echo ""
echo -e "  Stop with: ${YELLOW}./stop.sh${NC}  or  Ctrl+C"
echo ""

# ── Keep alive (trap Ctrl+C to stop both) ─────────────────────────────────────
cleanup() {
  info "Stopping..."
  # Kill process groups to catch child workers (uvicorn --reload, next dev)
  kill -- -$BACKEND_PID 2>/dev/null || kill $BACKEND_PID 2>/dev/null || true
  kill -- -$FRONTEND_PID 2>/dev/null || kill $FRONTEND_PID 2>/dev/null || true
  rm -f "$LOG_DIR/backend.pid" "$LOG_DIR/frontend.pid"
  exit 0
}
trap cleanup INT TERM
wait
