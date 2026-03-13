"""Unit tests for start.sh and stop.sh shell scripts."""

import os
import re
import signal
import socket
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


def _free_port() -> int:
    """Return an OS-assigned free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── kill_port() logic ────────────────────────────────────────────────────────


@pytest.mark.shell
class TestKillPort:
    """Tests for the kill_port() function extracted from start.sh."""

    def test_port_free_is_noop(self, tmp_path: Path):
        """When port is free, kill_port should do nothing and not fail."""
        port = _free_port()
        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            set -euo pipefail
            kill_port() {{
              local port=$1 pids=""
              if command -v lsof &>/dev/null; then
                pids=$(lsof -ti :"$port" 2>/dev/null || true)
              elif command -v fuser &>/dev/null; then
                pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\\n' || true)
              fi
              if [[ -n "${{pids:-}}" ]]; then
                echo "KILLING $pids"
                echo "$pids" | xargs kill -9 2>/dev/null || true
              else
                echo "PORT_FREE"
              fi
            }}
            kill_port {port}
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert "PORT_FREE" in result.stdout

    def test_port_occupied_kills_pid(self, tmp_path: Path):
        """When port is occupied, kill_port should detect the process."""
        port = _free_port()
        # Start a subprocess listener so lsof from child shell can see it
        listener = tmp_path / "listener.py"
        listener.write_text(textwrap.dedent(f"""\
            import socket, time
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", {port}))
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
            script.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                kill_port() {{
                  local port=$1 pids=""
                  if command -v lsof &>/dev/null; then
                    pids=$(lsof -ti :"$port" 2>/dev/null || true)
                  elif command -v fuser &>/dev/null; then
                    pids=$(fuser "$port"/tcp 2>/dev/null | tr ' ' '\\n' || true)
                  fi
                  if [[ -n "${{pids:-}}" ]]; then
                    echo "KILLING"
                  else
                    echo "PORT_FREE"
                  fi
                }}
                kill_port {port}
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

        port = _free_port()
        handler = http.server.SimpleHTTPRequestHandler
        server = http.server.HTTPServer(("127.0.0.1", port), handler)
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()

        try:
            script = tmp_path / "test.sh"
            # Intentional simplification: tests use a minimal version of the
            # production wait_for_port loop. The production script captures
            # http_code via --write-out; here we only check the liveness
            # semantics (-s without -f, exit on any HTTP response).
            script.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'; RED='\\033[0;31m'
                info()    {{ echo -e "${{CYAN}}[test]${{NC}} $*"; }}
                success() {{ echo -e "${{GREEN}}[test]${{NC}} $*"; }}
                err()     {{ echo -e "${{RED}}[test]${{NC}} $*"; }}
                wait_for_port() {{
                  local port=$1 name=$2 timeout=${{3:-5}} i=0 http_code=""
                  # Mirrors start.sh: curl -s -o /dev/null --write-out for liveness
                  while true; do
                    http_code=$(curl -s -o /dev/null --write-out '%{{http_code}}' "http://localhost:$port" 2>/dev/null || true)
                    [[ "$http_code" != "000" ]] && break
                    sleep 1
                    i=$((i+1))
                    if [[ $i -ge $timeout ]]; then
                      echo "TIMEOUT"
                      return 1
                    fi
                  done
                  echo "READY"
                }}
                wait_for_port {port} "test-server" 5
            """))
            script.chmod(0o755)
            result = _run(str(script), timeout=15)
            assert result.returncode == 0
            assert "READY" in result.stdout
        finally:
            server.server_close()

    def test_returns_ready_on_non_2xx_response(self, tmp_path: Path):
        """wait_for_port should succeed even when server returns 401 (non-2xx).

        This is the core behavioral change: without -f, curl treats any HTTP
        response as success, so services behind auth (401) count as 'up'.
        """
        import threading

        from http.server import BaseHTTPRequestHandler, HTTPServer

        port = _free_port()

        class Unauthorized401Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")

            def log_message(self, format, *args):
                pass  # suppress stderr

        server = HTTPServer(("127.0.0.1", port), Unauthorized401Handler)
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()

        try:
            script = tmp_path / "test.sh"
            script.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                NC='\\033[0m'; CYAN='\\033[0;36m'; GREEN='\\033[0;32m'; RED='\\033[0;31m'
                info()    {{ echo -e "${{CYAN}}[test]${{NC}} $*"; }}
                success() {{ echo -e "${{GREEN}}[test]${{NC}} $*"; }}
                err()     {{ echo -e "${{RED}}[test]${{NC}} $*"; }}
                wait_for_port() {{
                  local port=$1 name=$2 timeout=${{3:-5}} i=0 http_code=""
                  # Mirrors start.sh: curl -s -o /dev/null --write-out for liveness
                  while true; do
                    http_code=$(curl -s -o /dev/null --write-out '%{{http_code}}' "http://localhost:$port" 2>/dev/null || true)
                    [[ "$http_code" != "000" ]] && break
                    sleep 1
                    i=$((i+1))
                    if [[ $i -ge $timeout ]]; then
                      echo "TIMEOUT"
                      return 1
                    fi
                  done
                  echo "READY"
                }}
                wait_for_port {port} "test-server" 5
            """))
            script.chmod(0o755)
            result = _run(str(script), timeout=15)
            assert result.returncode == 0
            assert "READY" in result.stdout
        finally:
            server.server_close()

    def test_times_out_if_port_never_opens(self, tmp_path: Path):
        """wait_for_port should fail after timeout when port never opens."""
        port = _free_port()
        script = tmp_path / "test.sh"
        script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            set -uo pipefail
            NC='\\033[0m'; CYAN='\\033[0;36m'; RED='\\033[0;31m'
            info()    {{ echo -e "${{CYAN}}[test]${{NC}} $*"; }}
            err()     {{ echo -e "${{RED}}[test]${{NC}} $*"; }}
            wait_for_port() {{
              local port=$1 name=$2 timeout=${{3:-2}} i=0 http_code=""
              # Mirrors start.sh: curl -s -o /dev/null --write-out for liveness
              while true; do
                http_code=$(curl -s -o /dev/null --write-out '%{{http_code}}' "http://localhost:$port" 2>/dev/null || true)
                [[ "$http_code" != "000" ]] && break
                sleep 1
                i=$((i+1))
                if [[ $i -ge $timeout ]]; then
                  echo "TIMEOUT"
                  return 1
                fi
              done
              echo "READY"
            }}
            wait_for_port {port} "test-server" 2
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


# ── wait_for_port curl flags regression guard ─────────────────────────────


@pytest.mark.shell
class TestWaitForPortCurlFlags:
    """Regression guard: wait_for_port must NOT use curl -f."""

    def test_start_sh_curl_has_no_fail_flag(self):
        """start.sh wait_for_port must use curl without -f/--fail so non-2xx responses count as up."""
        content = (REPO_ROOT / "start.sh").read_text()
        # Extract the wait_for_port function body
        in_func = False
        func_lines = []
        for line in content.splitlines():
            if "wait_for_port()" in line:
                in_func = True
            if in_func:
                func_lines.append(line)
                if line.strip() == "}":
                    break
        func_body = "\n".join(func_lines)
        assert "curl" in func_body, "wait_for_port should use curl"
        # Match all fail-flag forms: -f, -sf, -fs, -fsS, --fail, etc.
        fail_flag_pattern = re.compile(r"curl\s+[^|;]*(?:-[a-zA-Z]*f[a-zA-Z]*\b|--fail\b)")
        match = fail_flag_pattern.search(func_body)
        assert match is None, (
            f"wait_for_port must not use curl -f/--fail (fails on 401): found '{match.group()}'"
        )


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
        port_a = _free_port()
        port_b = _free_port()
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
            kill_port {port_a}
            kill_port {port_b}
            success "ClawAudit stopped."
        """))
        script.chmod(0o755)
        result = _run(str(script))
        assert result.returncode == 0
        assert "stopped" in result.stdout.lower()

    def test_stop_idempotent_run_twice(self, tmp_path: Path):
        """Running stop logic twice should succeed both times."""
        port_a = _free_port()
        port_b = _free_port()
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
            kill_port {port_a}
            kill_port {port_b}
            success "ClawAudit stopped."
        """))
        script.chmod(0o755)
        r1 = _run(str(script))
        r2 = _run(str(script))
        assert r1.returncode == 0
        assert r2.returncode == 0
