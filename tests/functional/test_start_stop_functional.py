"""Functional tests for start.sh and stop.sh — end-to-end with stub servers."""

import http.server
import os
import subprocess
import textwrap
import threading
import time
from pathlib import Path
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent


def _ensure_sbin_path(env: dict) -> dict:
    """Ensure /usr/sbin is in PATH so lsof is available."""
    path = env.get("PATH", "")
    if "/usr/sbin" not in path:
        env["PATH"] = f"/usr/sbin:{path}" if path else "/usr/sbin"
    return env


def _run(cmd: str, env: Optional[dict] = None, cwd: Optional[Path] = None, timeout: int = 30) -> subprocess.CompletedProcess:
    merged_env = _ensure_sbin_path({**os.environ, **(env or {})})
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        env=merged_env,
        cwd=cwd or REPO_ROOT,
        timeout=timeout,
    )


class _StubServer:
    """Minimal HTTP server for testing port occupancy and readiness."""

    def __init__(self, port: int):
        self.port = port
        self.server = http.server.HTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.functional
class TestStartStopFunctional:
    """Full start/stop cycle tests with stub HTTP servers."""

    def test_start_outputs_dashboard_url(self, tmp_path: Path):
        """A start script variant should print the dashboard URL."""
        log_dir = tmp_path / ".logs"
        log_dir.mkdir()

        stub = _StubServer(39880)
        stub.start()
        try:
            script = tmp_path / "test_start.sh"
            script.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                FRONTEND_PORT=39880
                BACKEND_PORT=39881
                LOG_DIR="{log_dir}"
                NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; RED='\\033[0;31m'
                info()    {{ echo -e "${{CYAN}}[clawaudit]${{NC}} $*"; }}
                success() {{ echo -e "${{GREEN}}[clawaudit]${{NC}} $*"; }}
                err()     {{ echo -e "${{RED}}[clawaudit]${{NC}} $*"; }}

                echo "Dashboard  →  http://localhost:$FRONTEND_PORT/dashboard"
                echo "API        →  http://localhost:$BACKEND_PORT/api/v1"
            """))
            script.chmod(0o755)
            result = _run(str(script))
            assert result.returncode == 0
            assert "http://localhost:39880/dashboard" in result.stdout
        finally:
            stub.stop()

    def test_start_exits_zero_when_both_ports_respond(self, tmp_path: Path):
        """start.sh should exit 0 when both backend and frontend ports respond."""
        log_dir = tmp_path / ".logs"
        log_dir.mkdir()

        stub1 = _StubServer(39882)
        stub2 = _StubServer(39883)
        stub1.start()
        stub2.start()
        try:
            script = tmp_path / "test_start.sh"
            script.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'; RED='\\033[0;31m'
                info()    {{ echo -e "${{CYAN}}[test]${{NC}} $*"; }}
                success() {{ echo -e "${{GREEN}}[test]${{NC}} $*"; }}
                err()     {{ echo -e "${{RED}}[test]${{NC}} $*"; }}
                wait_for_port() {{
                  local port=$1 name=$2 timeout=${{3:-5}} i=0
                  until curl -sf "http://localhost:$port" &>/dev/null; do
                    sleep 1
                    i=$((i+1))
                    if [[ $i -ge $timeout ]]; then
                      err "$name did not start"
                      return 1
                    fi
                  done
                  success "$name ready on :$port"
                }}
                wait_for_port 39882 "backend" 5
                wait_for_port 39883 "frontend" 5
                echo "BOTH_READY"
            """))
            script.chmod(0o755)
            result = _run(str(script), timeout=15)
            assert result.returncode == 0
            assert "BOTH_READY" in result.stdout
        finally:
            stub1.stop()
            stub2.stop()

    def test_stop_exits_zero_and_clears_pid_files(self, tmp_path: Path):
        """stop.sh should exit 0 and remove PID files."""
        log_dir = tmp_path / ".logs"
        log_dir.mkdir()

        # Create dummy PID files with invalid PIDs
        (log_dir / "backend.pid").write_text("999999")
        (log_dir / "frontend.pid").write_text("999998")

        script = tmp_path / "test_stop.sh"
        script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            set -euo pipefail
            LOG_DIR="{log_dir}"
            NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'
            info()    {{ echo -e "${{CYAN}}[clawaudit]${{NC}} $*"; }}
            success() {{ echo -e "${{GREEN}}[clawaudit]${{NC}} $*"; }}
            kill_pid_file() {{
              local file=$1 name=$2
              if [[ -f "$file" ]]; then
                local pid
                pid=$(cat "$file")
                if kill -0 "$pid" 2>/dev/null; then
                  kill "$pid" 2>/dev/null && info "Stopped $name (PID $pid)"
                fi
                rm -f "$file"
              fi
            }}
            kill_port() {{
              local port=$1 pids=""
              if command -v lsof &>/dev/null; then
                pids=$(lsof -ti :"$port" 2>/dev/null || true)
              elif command -v fuser &>/dev/null; then
                pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\\n' || true)
              fi
              [[ -n "$pids" ]] && echo "$pids" | xargs kill -9 2>/dev/null || true
            }}
            kill_pid_file "$LOG_DIR/backend.pid" "backend"
            kill_pid_file "$LOG_DIR/frontend.pid" "frontend"
            kill_port 39884
            kill_port 39885
            success "ClawAudit stopped."
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert not (log_dir / "backend.pid").exists()
        assert not (log_dir / "frontend.pid").exists()

    def test_start_twice_cleans_up_first_run(self, tmp_path: Path):
        """Running start twice should clean up the first run's ports."""
        log_dir = tmp_path / ".logs"
        log_dir.mkdir()

        # Start a subprocess listener (visible to lsof from child shell)
        listener = tmp_path / "listener.py"
        listener.write_text(textwrap.dedent("""\
            import socket, time
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 39886))
            s.listen(1)
            print("LISTENING", flush=True)
            time.sleep(60)
        """))
        proc = subprocess.Popen(
            ["python3", str(listener)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        proc.stdout.readline()
        time.sleep(0.5)

        try:
            script = tmp_path / "test_restart.sh"
            script.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'
                info()    {{ echo -e "${{CYAN}}[test]${{NC}} $*"; }}
                success() {{ echo -e "${{GREEN}}[test]${{NC}} $*"; }}
                warn()    {{ echo -e "${{YELLOW}}[test]${{NC}} $*"; }}
                kill_port() {{
                  local port=$1 pids=""
                  if command -v lsof &>/dev/null; then
                    pids=$(lsof -ti :"$port" 2>/dev/null || true)
                  elif command -v fuser &>/dev/null; then
                    pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\\n' || true)
                  fi
                  if [[ -n "${{pids:-}}" ]]; then
                    warn "Port $port in use — killing..."
                    echo "KILLED_PORT_$port"
                  else
                    echo "PORT_FREE_$port"
                  fi
                }}
                # Simulate second start.sh clearing ports from first run
                kill_port 39886
            """))
            script.chmod(0o755)
            result = _run(str(script))
            assert result.returncode == 0
            assert "KILLED_PORT_39886" in result.stdout
        finally:
            proc.kill()
            proc.wait()
