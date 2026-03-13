#!/usr/bin/env bash
# ClawAudit stop script — kills backend and frontend by PID file or port scan
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$REPO_DIR/.logs"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
info()    { echo -e "${CYAN}[clawaudit]${NC} $*"; }
success() { echo -e "${GREEN}[clawaudit]${NC} $*"; }

NEED_PORT_FALLBACK=0

kill_pid_file() {
  local file=$1 name=$2
  if [[ -f "$file" ]]; then
    local pid
    pid=$(cat "$file")
    if kill -0 "$pid" 2>/dev/null; then
      # Graceful SIGTERM first
      kill "$pid" 2>/dev/null || true
      # Wait briefly for process to exit
      local i=0
      while kill -0 "$pid" 2>/dev/null && [[ $i -lt 5 ]]; do
        sleep 1
        i=$((i+1))
      done
      # SIGKILL if still alive
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
      fi
      info "Stopped $name (PID $pid)"
    fi
    rm -f "$file"
  else
    NEED_PORT_FALLBACK=1
  fi
}

kill_port() {
  local port=$1 pids=""
  if command -v lsof &>/dev/null; then
    pids=$(lsof -ti :"$port" 2>/dev/null || true)
  elif command -v fuser &>/dev/null; then
    pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\n' || true)
  fi
  if [[ -n "$pids" ]]; then
    echo "$pids" | xargs kill 2>/dev/null || true
    sleep 1
    # Force-kill stragglers
    if command -v lsof &>/dev/null; then
      pids=$(lsof -ti :"$port" 2>/dev/null || true)
    fi
    [[ -n "${pids:-}" ]] && echo "$pids" | xargs kill -9 2>/dev/null || true
  fi
}

info "Stopping ClawAudit..."
kill_pid_file "$LOG_DIR/backend.pid"  "backend"
kill_pid_file "$LOG_DIR/frontend.pid" "frontend"

# Fallback: port-based kill only when PID files were missing
if [[ $NEED_PORT_FALLBACK -eq 1 ]]; then
  kill_port 18790
  kill_port 3000
fi

success "ClawAudit stopped."
