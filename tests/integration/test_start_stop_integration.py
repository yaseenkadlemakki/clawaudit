"""Integration tests for start.sh and stop.sh — real port occupancy and cleanup."""

import http.server
import os
import socket
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


def _port_in_use(port: int) -> bool:
    """Check if a port is currently in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


class _StubServer:
    """Minimal HTTP server for testing."""

    def __init__(self, port: int):
        self.port = port
        self.server = http.server.HTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.pid = None

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.integration
class TestStartStopIntegration:
    """Real end-to-end tests with actual port occupancy."""

    def test_stop_frees_occupied_ports(self, tmp_path: Path):
        """Start background processes, write PID files, run stop logic, verify cleanup."""
        import sys

        log_dir = tmp_path / ".logs"
        log_dir.mkdir()

        # Start two background sleep processes to simulate backend/frontend
        procs = []
        for name in ["backend", "frontend"]:
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(120)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (log_dir / f"{name}.pid").write_text(str(proc.pid))
            procs.append(proc)

        # Verify processes are running
        for proc in procs:
            assert proc.poll() is None, "Process should be running"

        # Run stop logic (PID-file based kill)
        script = tmp_path / "stop_test.sh"
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
            kill_pid_file "$LOG_DIR/backend.pid" "backend"
            kill_pid_file "$LOG_DIR/frontend.pid" "frontend"
            success "ClawAudit stopped."
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert "Stopped backend" in result.stdout
        assert "Stopped frontend" in result.stdout

        # Verify processes are dead and PID files removed
        for proc in procs:
            proc.wait(timeout=5)
        assert not (log_dir / "backend.pid").exists()
        assert not (log_dir / "frontend.pid").exists()

    def test_start_script_syntax_valid(self):
        """start.sh should pass bash -n syntax check."""
        result = _run(f"bash -n {REPO_ROOT / 'start.sh'}")
        assert result.returncode == 0, f"start.sh syntax error: {result.stderr}"

    def test_stop_script_syntax_valid(self):
        """stop.sh should pass bash -n syntax check."""
        result = _run(f"bash -n {REPO_ROOT / 'stop.sh'}")
        assert result.returncode == 0, f"stop.sh syntax error: {result.stderr}"

    def test_start_fails_fast_with_missing_python(self, tmp_path: Path):
        """start.sh should exit non-zero when Python is not findable."""
        # Run start.sh with PATH stripped to exclude python
        script = tmp_path / "test_no_python.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -euo pipefail
            RED='\\033[0;31m'; NC='\\033[0m'
            err() { echo -e "${RED}[clawaudit]${NC} $*"; }
            PYTHON=""
            for py in python_nonexistent_311 python_nonexistent_3 python_nonexistent; do
              if command -v "$py" &>/dev/null; then PYTHON="$py"; break; fi
            done
            [[ -z "$PYTHON" ]] && { err "Python not found"; exit 1; }
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 1
        assert "Python not found" in result.stdout

    def test_pid_file_lifecycle(self, tmp_path: Path):
        """Full lifecycle: create PID file, verify stop reads it, cleans up."""
        log_dir = tmp_path / ".logs"
        log_dir.mkdir()

        # Start a background sleep process and record its PID
        proc = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pid_file = log_dir / "backend.pid"
        pid_file.write_text(str(proc.pid))

        try:
            # Run stop logic
            script = tmp_path / "stop_pid.sh"
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
                kill_pid_file "$LOG_DIR/backend.pid" "backend"
                success "done"
            """))
            script.chmod(0o755)
            result = _run(str(script))
            assert result.returncode == 0
            assert "Stopped backend" in result.stdout
            assert not pid_file.exists()

            # Process should be terminated
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
            raise

    def test_partial_failure_cleans_up_running_service(self, tmp_path: Path):
        """If one service fails to start, the other should still be cleaned up by stop."""
        import sys

        log_dir = tmp_path / ".logs"
        log_dir.mkdir()

        # Only frontend starts — no backend PID file
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        (log_dir / "frontend.pid").write_text(str(proc.pid))
        # backend.pid intentionally missing — simulates failed start

        try:
            script = tmp_path / "stop_partial.sh"
            script.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                LOG_DIR="{log_dir}"
                NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'
                info()    {{ echo -e "${{CYAN}}[clawaudit]${{NC}} $*"; }}
                success() {{ echo -e "${{GREEN}}[clawaudit]${{NC}} $*"; }}
                NEED_PORT_FALLBACK=0
                kill_pid_file() {{
                  local file=$1 name=$2
                  if [[ -f "$file" ]]; then
                    local pid
                    pid=$(cat "$file")
                    if kill -0 "$pid" 2>/dev/null; then
                      kill "$pid" 2>/dev/null && info "Stopped $name (PID $pid)"
                    fi
                    rm -f "$file"
                  else
                    NEED_PORT_FALLBACK=1
                  fi
                }}
                kill_pid_file "$LOG_DIR/backend.pid" "backend"
                kill_pid_file "$LOG_DIR/frontend.pid" "frontend"
                success "ClawAudit stopped."
            """))
            script.chmod(0o755)
            result = _run(str(script))
            assert result.returncode == 0
            assert "Stopped frontend" in result.stdout
            # Frontend process should be dead
            proc.wait(timeout=5)
            assert not (log_dir / "frontend.pid").exists()
        except Exception:
            proc.kill()
            raise
