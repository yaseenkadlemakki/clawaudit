"""Unit tests for SessionCollector code-block-as-command detection (issue #39233)."""
import json
import pytest
from datetime import datetime
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.collector.session_collector import SessionCollector
from sentinel.models.event import Event


def _cfg() -> SentinelConfig:
    return SentinelConfig({
        "openclaw": {
            "gateway_url": "http://localhost", "gateway_token": "",
            "skills_dir": "/s", "workspace_skills_dir": "/w", "config_file": "/c.json",
        },
        "sentinel": {
            "scan_interval_seconds": 60, "log_dir": "/l",
            "findings_file": "/f.jsonl", "baseline_file": "/b.json", "policies_dir": "/p",
        },
        "alerts": {"enabled": True, "dedup_window_seconds": 300, "channels": {}},
        "api": {"enabled": False, "port": 18790, "bind": "loopback"},
    })


def _make_tool_use_record(command: str, tool_name: str = "bash") -> str:
    return json.dumps({
        "type": "tool_use",
        "name": tool_name,
        "ts": "2025-01-01T12:00:00",
        "input": {"command": command},
    })


def _make_tool_result_record(output: str) -> str:
    return json.dumps({
        "type": "tool_result",
        "role": "tool",
        "ts": "2025-01-01T12:00:01",
        "output": output,
    })


@pytest.mark.unit
class TestSessionCollectorCodeBlock:
    def _collector_and_events(self):
        events: list[Event] = []
        col = SessionCollector(_cfg(), events.append)
        return col, events

    def test_python_code_block_detected_in_tool_use(self, tmp_path):
        """Issue #39233 repro: Python class definition executed as bash command."""
        col, events = self._collector_and_events()
        python_code = (
            "from dataclasses import dataclass\n"
            "from enum import Enum\n"
            "class RemediationStatus(str, Enum):\n"
            "    PENDING = 'pending'\n"
        )
        session = tmp_path / "session-code.jsonl"
        session.write_text(_make_tool_use_record(python_code))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert len(code_events) == 1
        assert code_events[0].severity == "HIGH"
        assert "python" in code_events[0].evidence

    def test_shell_errors_detected_in_tool_result(self, tmp_path):
        """Shell error output indicates non-shell code was executed."""
        col, events = self._collector_and_events()
        shell_output = (
            "zsh:1: command not found: python\n"
            "zsh:2: command not found: from\n"
            "zsh:3: command not found: from\n"
        )
        session = tmp_path / "session-err.jsonl"
        session.write_text(_make_tool_result_record(shell_output))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert len(code_events) == 1
        assert "shell_errors" in code_events[0].evidence

    def test_legitimate_bash_not_flagged(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "session-ok.jsonl"
        session.write_text(_make_tool_use_record("git status && ls -la"))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert code_events == []

    def test_short_command_not_flagged(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "session-short.jsonl"
        session.write_text(_make_tool_use_record("ls"))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert code_events == []

    def test_non_bash_tool_not_inspected(self, tmp_path):
        """Tool calls to non-shell tools (e.g. 'write', 'read') should be skipped."""
        col, events = self._collector_and_events()
        python_code = (
            "from pathlib import Path\n"
            "class Config:\n"
            "    pass\n"
        )
        session = tmp_path / "session-write.jsonl"
        session.write_text(_make_tool_use_record(python_code, tool_name="write"))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert code_events == []

    def test_event_references_pol_011(self, tmp_path):
        col, events = self._collector_and_events()
        python_code = (
            "from dataclasses import dataclass\n"
            "from enum import Enum\n"
            "class Status(Enum):\n"
            "    OK = 'ok'\n"
        )
        session = tmp_path / "session-pol.jsonl"
        session.write_text(_make_tool_use_record(python_code))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert any("POL-011" in e.policy_refs for e in code_events)

    def test_entity_is_session_id(self, tmp_path):
        col, events = self._collector_and_events()
        python_code = (
            "from pathlib import Path\n"
            "import json\n"
            "class Loader:\n"
            "    pass\n"
        )
        session = tmp_path / "my-session-99.jsonl"
        session.write_text(_make_tool_use_record(python_code))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert code_events[0].entity == "my-session-99"

    def test_dedup_same_code_block(self, tmp_path):
        """Same code block in same session should only emit one event."""
        col, events = self._collector_and_events()
        python_code = (
            "from typing import Optional\n"
            "class Foo:\n"
            "    pass\n"
        )
        record = _make_tool_use_record(python_code)
        session = tmp_path / "session-dup.jsonl"
        session.write_text(record + "\n" + record)
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert len(code_events) == 1

    def test_typescript_code_block_detected(self, tmp_path):
        col, events = self._collector_and_events()
        ts_code = (
            "import React from 'react';\n"
            "export default function App() {\n"
            "  return <div>Hello</div>;\n"
            "}\n"
        )
        session = tmp_path / "session-ts.jsonl"
        session.write_text(_make_tool_use_record(ts_code))
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert len(code_events) == 1
        assert "ts" in code_events[0].evidence

    def test_input_as_string_not_dict(self, tmp_path):
        """Handle case where input is a plain string, not a dict."""
        col, events = self._collector_and_events()
        python_code = (
            "from os import path\n"
            "class Builder:\n"
            "    def build(self):\n"
            "        pass\n"
        )
        record = json.dumps({
            "type": "tool_use",
            "name": "bash",
            "ts": "2025-01-01T12:00:00",
            "input": python_code,
        })
        session = tmp_path / "session-str.jsonl"
        session.write_text(record)
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert len(code_events) == 1

    def test_tool_result_with_list_content(self, tmp_path):
        """Handle tool_result where content is a list of text blocks."""
        col, events = self._collector_and_events()
        record = json.dumps({
            "type": "tool_result",
            "role": "tool",
            "ts": "2025-01-01T12:00:01",
            "content": [
                {"type": "text", "text": "zsh:1: command not found: from"},
                {"type": "text", "text": "zsh:2: command not found: class"},
                {"type": "text", "text": "zsh:3: no matches found: Enum"},
            ],
        })
        session = tmp_path / "session-list.jsonl"
        session.write_text(record)
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert len(code_events) == 1

    def test_single_shell_error_not_enough(self, tmp_path):
        """A single shell error line is not enough to trigger (threshold is 2)."""
        col, events = self._collector_and_events()
        record = _make_tool_result_record("zsh:1: command not found: foo")
        session = tmp_path / "session-single.jsonl"
        session.write_text(record)
        col._analyze_session_file(session)
        code_events = [e for e in events if e.event_type == "code_block_as_command"]
        assert code_events == []

    def test_runaway_and_code_block_both_detected(self, tmp_path):
        """Both runaway_agent and code_block_as_command can fire in same session."""
        col, events = self._collector_and_events()
        lines = []
        # Add enough tool calls to trigger runaway
        base = datetime(2025, 1, 1, 12, 0, 0)
        for i in range(35):
            from datetime import timedelta
            ts = (base + timedelta(seconds=i)).isoformat()
            lines.append(json.dumps({"type": "tool_use", "ts": ts}))
        # Add a code-block tool call
        python_code = (
            "from enum import Enum\n"
            "class Status(Enum):\n"
            "    OK = 'ok'\n"
        )
        lines.append(_make_tool_use_record(python_code))
        session = tmp_path / "session-both.jsonl"
        session.write_text("\n".join(lines))
        col._analyze_session_file(session)
        event_types = {e.event_type for e in events}
        assert "runaway_agent" in event_types
        assert "code_block_as_command" in event_types
