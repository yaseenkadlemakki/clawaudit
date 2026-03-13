#!/usr/bin/env bash
# ClawAudit stop script — kills backend and frontend by PID file or port scan
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$REPO_DIR/.logs"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
info()    { echo -e "${CYAN}[clawaudit]${NC} $*"; }
success() { echo -e "${GREEN}[clawaudit]${NC} $*"; }

kill_pid_file() {
  local file=$1 name=$2
  if [[ -f "$file" ]]; then
    local pid
    pid=$(cat "$file")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && info "Stopped $name (PID $pid)"
    fi
    rm -f "$file"
  fi
}

kill_port() {
  local port=$1 pids=""
  if command -v lsof &>/dev/null; then
    pids=$(lsof -ti :"$port" 2>/dev/null || true)
  elif command -v fuser &>/dev/null; then
    pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\n' || true)
  fi
  [[ -n "$pids" ]] && echo "$pids" | xargs kill -9 2>/dev/null || true
}

info "Stopping ClawAudit..."
kill_pid_file "$LOG_DIR/backend.pid"  "backend"
kill_pid_file "$LOG_DIR/frontend.pid" "frontend"

# Fallback: nuke by port in case PIDs drifted
kill_port 18790
kill_port 3000

success "ClawAudit stopped."
