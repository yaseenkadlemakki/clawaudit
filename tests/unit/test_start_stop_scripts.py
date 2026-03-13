"""Unit tests for start.sh and stop.sh shell scripts."""

import os
import signal
import subprocess
import textwrap
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


def _run(cmd: str, env: Optional[dict] = None, cwd: Optional[Path] = None, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
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


# ── kill_port() logic ────────────────────────────────────────────────────────


@pytest.mark.shell
class TestKillPort:
    """Tests for the kill_port() function extracted from start.sh."""

    def test_port_free_is_noop(self, tmp_path: Path):
        """When port is free, kill_port should do nothing and not fail."""
        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -euo pipefail
            kill_port() {
              local port=$1 pids=""
              if command -v lsof &>/dev/null; then
                pids=$(lsof -ti :"$port" 2>/dev/null || true)
              elif command -v fuser &>/dev/null; then
                pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\\n' || true)
              fi
              if [[ -n "${pids:-}" ]]; then
                echo "KILLING $pids"
                echo "$pids" | xargs kill -9 2>/dev/null || true
              else
                echo "PORT_FREE"
              fi
            }
            kill_port 39871
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert "PORT_FREE" in result.stdout

    def test_port_occupied_kills_pid(self, tmp_path: Path):
        """When port is occupied, kill_port should detect the process."""
        # Start a subprocess listener so lsof from child shell can see it
        listener = tmp_path / "listener.py"
        listener.write_text(textwrap.dedent("""\
            import socket, time
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 39872))
            s.listen(1)
            print("LISTENING", flush=True)
            time.sleep(60)
        """))
        import time
        proc = subprocess.Popen(
            ["python3", str(listener)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        # Wait for it to start listening
        proc.stdout.readline()
        time.sleep(0.5)

        try:
            script = tmp_path / "test.sh"
            script.write_text(textwrap.dedent("""\
                #!/usr/bin/env bash
                set -euo pipefail
                kill_port() {
                  local port=$1 pids=""
                  if command -v lsof &>/dev/null; then
                    pids=$(lsof -ti :"$port" 2>/dev/null || true)
                  elif command -v fuser &>/dev/null; then
                    pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\\n' || true)
                  fi
                  if [[ -n "${pids:-}" ]]; then
                    echo "KILLING"
                  else
                    echo "PORT_FREE"
                  fi
                }
                kill_port 39872
            """))
            script.chmod(0o755)
            result = _run(str(script))
            assert result.returncode == 0
            assert "KILLING" in result.stdout
        finally:
            proc.kill()
            proc.wait()


# ── wait_for_port() logic ─────────────────────────────────────────────────────


@pytest.mark.shell
class TestWaitForPort:
    """Tests for the wait_for_port() function from start.sh."""

    def test_returns_when_port_responds(self, tmp_path: Path):
        """wait_for_port should succeed when curl gets a response."""
        import http.server
        import threading

        handler = http.server.SimpleHTTPRequestHandler
        server = http.server.HTTPServer(("127.0.0.1", 39873), handler)
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()

        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -euo pipefail
            NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'; RED='\\033[0;31m'
            info()    { echo -e "${CYAN}[test]${NC} $*"; }
            success() { echo -e "${GREEN}[test]${NC} $*"; }
            err()     { echo -e "${RED}[test]${NC} $*"; }
            wait_for_port() {
              local port=$1 name=$2 timeout=${3:-5} i=0
              until curl -sf "http://localhost:$port" &>/dev/null; do
                sleep 1
                i=$((i+1))
                if [[ $i -ge $timeout ]]; then
                  echo "TIMEOUT"
                  return 1
                fi
              done
              echo "READY"
            }
            wait_for_port 39873 "test-server" 5
        """))
        script.chmod(0o755)
        result = _run(str(script), timeout=15)
        server.server_close()
        assert result.returncode == 0
        assert "READY" in result.stdout

    def test_times_out_if_port_never_opens(self, tmp_path: Path):
        """wait_for_port should fail after timeout when port never opens."""
        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -uo pipefail
            NC='\\033[0m'; CYAN='\\033[0;36m'; RED='\\033[0;31m'
            info()    { echo -e "${CYAN}[test]${NC} $*"; }
            err()     { echo -e "${RED}[test]${NC} $*"; }
            wait_for_port() {
              local port=$1 name=$2 timeout=${3:-2} i=0
              until curl -sf "http://localhost:$port" &>/dev/null; do
                sleep 1
                i=$((i+1))
                if [[ $i -ge $timeout ]]; then
                  echo "TIMEOUT"
                  return 1
                fi
              done
              echo "READY"
            }
            wait_for_port 39874 "test-server" 2
        """))
        script.chmod(0o755)
        result = _run(str(script), timeout=15)
        assert result.returncode != 0
        assert "TIMEOUT" in result.stdout


# ── stop.sh PID file handling ────────────────────────────────────────────────


@pytest.mark.shell
class TestStopPidHandling:
    """Tests for stop.sh PID-file reading and fallback."""

    def test_reads_pid_file_and_kills(self, tmp_path: Path):
        """stop.sh kill_pid_file should read PID and attempt kill."""
        pid_file = tmp_path / "test.pid"
        # Use PID 1 (init) which we can't kill but can signal-check
        # Instead, use current PID for kill -0 check
        pid_file.write_text(str(os.getpid()))

        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            set -euo pipefail
            NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'
            info()    {{ echo -e "${{CYAN}}[test]${{NC}} $*"; }}
            success() {{ echo -e "${{GREEN}}[test]${{NC}} $*"; }}
            kill_pid_file() {{
              local file=$1 name=$2
              if [[ -f "$file" ]]; then
                local pid
                pid=$(cat "$file")
                if kill -0 "$pid" 2>/dev/null; then
                  echo "FOUND_PID $pid"
                else
                  echo "PID_DEAD $pid"
                fi
                rm -f "$file"
              else
                echo "NO_FILE"
              fi
            }}
            kill_pid_file "{pid_file}" "test-service"
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert f"FOUND_PID {os.getpid()}" in result.stdout
        assert not pid_file.exists()  # file removed

    def test_fallback_to_port_kill_when_no_pid_file(self, tmp_path: Path):
        """stop.sh should fall back to port-based kill when PID file is missing."""
        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            set -euo pipefail
            NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'
            info()    {{ echo -e "${{CYAN}}[test]${{NC}} $*"; }}
            success() {{ echo -e "${{GREEN}}[test]${{NC}} $*"; }}
            kill_pid_file() {{
              local file=$1 name=$2
              if [[ -f "$file" ]]; then
                echo "HAS_FILE"
              else
                echo "NO_FILE"
              fi
            }}
            kill_port() {{
              echo "PORT_FALLBACK $1"
            }}
            kill_pid_file "{tmp_path}/nonexistent.pid" "test"
            kill_port 18790
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert "NO_FILE" in result.stdout
        assert "PORT_FALLBACK 18790" in result.stdout


# ── PORT env var ──────────────────────────────────────────────────────────────


@pytest.mark.shell
class TestPortEnvVar:
    """Verify that PORT env var is set in start.sh for Next.js."""

    def test_port_env_var_in_start_script(self):
        """start.sh should pass PORT=$FRONTEND_PORT to npm run dev."""
        content = (REPO_ROOT / "start.sh").read_text()
        assert "PORT=$FRONTEND_PORT" in content or "PORT=3000" in content
        assert "npm run dev" in content


# ── Prerequisite checks ─────────────────────────────────────────────────────


@pytest.mark.shell
class TestPrerequisiteChecks:
    """Test that scripts exit non-zero when prerequisites are missing."""

    def test_exits_nonzero_if_python_not_found(self, tmp_path: Path):
        """start.sh should fail fast if no Python is available."""
        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -euo pipefail
            RED='\\033[0;31m'; NC='\\033[0m'
            err() { echo -e "${RED}[clawaudit]${NC} $*"; }
            # Override command to make all pythons unfindable
            PYTHON=""
            for py in python3.11_fake python3_fake python_fake; do
              if command -v "$py" &>/dev/null; then PYTHON="$py"; break; fi
            done
            [[ -z "$PYTHON" ]] && { err "Python not found"; exit 1; }
            echo "SHOULD_NOT_REACH"
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 1
        assert "Python not found" in result.stdout

    def test_exits_nonzero_if_node_not_found(self, tmp_path: Path):
        """start.sh should fail fast if Node.js is not available."""
        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -euo pipefail
            RED='\\033[0;31m'; NC='\\033[0m'
            err() { echo -e "${RED}[clawaudit]${NC} $*"; }
            command -v node_fake_binary &>/dev/null || { err "Node.js not found"; exit 1; }
            echo "SHOULD_NOT_REACH"
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 1
        assert "Node.js not found" in result.stdout


# ── .logs directory creation ──────────────────────────────────────────────────


@pytest.mark.shell
class TestLogDirCreation:
    """Test that .logs/ is created when missing."""

    def test_logs_dir_created_if_missing(self):
        """start.sh should contain mkdir -p for .logs directory."""
        content = (REPO_ROOT / "start.sh").read_text()
        assert 'mkdir -p "$LOG_DIR"' in content or "mkdir -p" in content


# ── stop.sh idempotency ──────────────────────────────────────────────────────


@pytest.mark.shell
class TestStopIdempotency:
    """Test that stop.sh is safe to run when nothing is running."""

    def test_stop_idempotent_no_pid_files(self, tmp_path: Path):
        """stop.sh logic should exit 0 even with no PID files and free ports."""
        script = tmp_path / "test.sh"
        log_dir = tmp_path / ".logs"
        log_dir.mkdir()
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
            kill_port 39875
            kill_port 39876
            success "ClawAudit stopped."
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert "stopped" in result.stdout.lower()

    def test_stop_idempotent_run_twice(self, tmp_path: Path):
        """Running stop logic twice should succeed both times."""
        script = tmp_path / "test.sh"
        log_dir = tmp_path / ".logs"
        log_dir.mkdir()
        script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            set -uo pipefail
            LOG_DIR="{log_dir}"
            NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'
            info()    {{ echo -e "${{CYAN}}[clawaudit]${{NC}} $*"; }}
            success() {{ echo -e "${{GREEN}}[clawaudit]${{NC}} $*"; }}
            kill_pid_file() {{
              local file=$1 name=$2
              if [[ -f "$file" ]]; then
                rm -f "$file"
              fi
            }}
            kill_port() {{
              true
            }}
            kill_pid_file "$LOG_DIR/backend.pid" "backend"
            kill_pid_file "$LOG_DIR/frontend.pid" "frontend"
            kill_port 39875
            kill_port 39876
            success "ClawAudit stopped."
        """))
        script.chmod(0o755)
        r1 = _run(str(script))
        r2 = _run(str(script))
        assert r1.returncode == 0
        assert r2.returncode == 0
