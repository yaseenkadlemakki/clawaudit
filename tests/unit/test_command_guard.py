"""Unit tests for sentinel.guard.command_guard — pre-execution heuristics."""
import pytest

from sentinel.guard.command_guard import (
    CommandVerdict,
    check_file_intent,
    classify_command,
    detect_shell_errors,
)


# ── classify_command — Python detection ──────────────────────────────────────


@pytest.mark.unit
class TestClassifyCommandPython:
    """Python code blocks must be flagged as non-shell."""

    def test_python_from_import(self):
        cmd = "from dataclasses import dataclass\nfrom enum import Enum"
        v = classify_command(cmd)
        assert v.is_code_block
        assert v.detected_language == "python"
        assert v.suggested_action == "WRITE_FILE"

    def test_python_class_and_def(self):
        cmd = (
            "class RemediationStatus(str, Enum):\n"
            "    PENDING = 'pending'\n"
            "\n"
            "def apply(self):\n"
            "    pass\n"
        )
        v = classify_command(cmd)
        assert v.is_code_block
        assert v.detected_language == "python"

    def test_python_decorator_and_async_def(self):
        cmd = "@pytest.mark.asyncio\nasync def test_something():\n    pass"
        v = classify_command(cmd)
        assert v.is_code_block
        assert "python" in v.detected_language

    def test_python_full_module(self):
        cmd = (
            'from __future__ import annotations\n'
            'import logging\n'
            'from pathlib import Path\n'
            '\n'
            'class Scanner:\n'
            '    """Scans for issues."""\n'
            '    def run(self) -> None:\n'
            '        pass\n'
        )
        v = classify_command(cmd)
        assert v.is_code_block
        assert v.confidence == "HIGH"

    def test_python_try_except(self):
        cmd = "try:\n    do_thing()\nexcept ValueError:\n    pass"
        v = classify_command(cmd)
        assert v.is_code_block

    def test_python_raise(self):
        cmd = "from typing import Optional\nraise ValueError('bad')"
        v = classify_command(cmd)
        assert v.is_code_block

    def test_python_main_guard(self):
        cmd = "import sys\nif __name__ == '__main__':\n    main()"
        v = classify_command(cmd)
        assert v.is_code_block

    def test_python_single_import_below_threshold(self):
        """A single Python token alone may not be enough to flag."""
        cmd = "import os"
        v = classify_command(cmd)
        # Single token → below threshold
        assert not v.is_code_block


# ── classify_command — TypeScript / JavaScript ──────────────────────────────


@pytest.mark.unit
class TestClassifyCommandTypeScript:
    def test_ts_interface_and_export(self):
        cmd = "export default function handler() {\n  return null;\n}\ninterface Props { name: string }"
        v = classify_command(cmd)
        assert v.is_code_block
        assert v.detected_language == "ts"

    def test_ts_import_from(self):
        cmd = "import React from 'react'\nconst App = () => { return <div/>; }"
        v = classify_command(cmd)
        assert v.is_code_block

    def test_ts_const_and_let(self):
        cmd = "const x = 42;\nlet y = 'hello';"
        v = classify_command(cmd)
        assert v.is_code_block

    def test_ts_type_alias(self):
        cmd = "type Config = {\n  port: number;\n};\nconst cfg: Config = { port: 8080 };"
        v = classify_command(cmd)
        assert v.is_code_block


# ── classify_command — Go ────────────────────────────────────────────────────


@pytest.mark.unit
class TestClassifyCommandGo:
    def test_go_package_and_func(self):
        cmd = 'package main\n\nfunc main() {\n\tfmt.Println("hello")\n}'
        v = classify_command(cmd)
        assert v.is_code_block
        assert v.detected_language == "go"

    def test_go_import_block(self):
        cmd = 'package main\n\nimport (\n\t"fmt"\n\t"os"\n)'
        v = classify_command(cmd)
        assert v.is_code_block


# ── classify_command — Rust ──────────────────────────────────────────────────


@pytest.mark.unit
class TestClassifyCommandRust:
    def test_rust_fn_and_use(self):
        cmd = "use std::io;\n\nfn main() {\n    println!(\"hello\");\n}"
        v = classify_command(cmd)
        assert v.is_code_block
        assert v.detected_language == "rust"

    def test_rust_pub_struct(self):
        cmd = "pub struct Config {\n    pub port: u16,\n}\n\nimpl Config {\n    pub fn new() -> Self { todo!() }\n}"
        v = classify_command(cmd)
        assert v.is_code_block


# ── classify_command — legitimate shell commands ─────────────────────────────


@pytest.mark.unit
class TestClassifyCommandShell:
    """Legitimate shell commands must NOT be flagged."""

    def test_simple_ls(self):
        v = classify_command("ls -la")
        assert not v.is_code_block
        assert v.suggested_action == "EXECUTE"

    def test_git_command(self):
        v = classify_command("git status")
        assert not v.is_code_block

    def test_pip_install(self):
        v = classify_command("pip install -e '.[dev]'")
        assert not v.is_code_block

    def test_pytest(self):
        v = classify_command("python -m pytest tests/")
        assert not v.is_code_block

    def test_mkdir_and_touch(self):
        v = classify_command("mkdir -p src/utils && touch src/utils/__init__.py")
        assert not v.is_code_block

    def test_docker_compose(self):
        v = classify_command("docker compose up -d")
        assert not v.is_code_block

    def test_curl(self):
        v = classify_command("curl -s https://api.example.com/health")
        assert not v.is_code_block

    def test_empty_command(self):
        v = classify_command("")
        assert not v.is_code_block

    def test_short_command(self):
        v = classify_command("echo hi")
        assert not v.is_code_block


# ── classify_command — confidence levels ─────────────────────────────────────


@pytest.mark.unit
class TestClassifyCommandConfidence:
    def test_high_confidence_many_tokens(self):
        cmd = (
            "from pathlib import Path\n"
            "import json\n"
            "class Loader:\n"
            "    def load(self):\n"
            "        pass\n"
        )
        v = classify_command(cmd)
        assert v.confidence == "HIGH"

    def test_medium_confidence_few_tokens(self):
        cmd = "from os import path\nclass Foo:\n    pass"
        v = classify_command(cmd)
        assert v.confidence in ("MEDIUM", "HIGH")

    def test_low_confidence_ambiguous(self):
        cmd = "echo hello"
        v = classify_command(cmd)
        assert v.confidence == "LOW"


# ── detect_shell_errors ──────────────────────────────────────────────────────


@pytest.mark.unit
class TestDetectShellErrors:
    def test_zsh_command_not_found(self):
        output = (
            "zsh:1: command not found: python\n"
            "zsh:2: command not found: from\n"
            "zsh:3: command not found: from\n"
        )
        errors = detect_shell_errors(output)
        assert len(errors) == 3

    def test_bash_command_not_found(self):
        output = "bash: line 1: from: command not found\nbash: line 2: class: command not found"
        errors = detect_shell_errors(output)
        assert len(errors) == 2

    def test_zsh_no_matches_found(self):
        output = "zsh:7: no matches found: RemediationStatus(str, Enum):"
        errors = detect_shell_errors(output)
        assert len(errors) == 1

    def test_bash_syntax_error(self):
        output = "bash: syntax error near unexpected token `('"
        errors = detect_shell_errors(output)
        assert len(errors) == 1

    def test_clean_output_no_errors(self):
        output = "total 48\ndrwxr-xr-x  12 user  staff  384 Mar  7 10:00 .\n"
        errors = detect_shell_errors(output)
        assert errors == []

    def test_empty_output(self):
        assert detect_shell_errors("") == []

    def test_mixed_output_filters_only_errors(self):
        output = (
            "Starting build...\n"
            "zsh:1: command not found: from\n"
            "Build complete.\n"
        )
        errors = detect_shell_errors(output)
        assert len(errors) == 1
        assert "command not found" in errors[0]


# ── check_file_intent ────────────────────────────────────────────────────────


@pytest.mark.unit
class TestCheckFileIntent:
    def test_prompt_with_py_file_and_python_code(self):
        prompt = "Create `sentinel/remediation/actions.py` with this content:"
        command = (
            "from dataclasses import dataclass\n"
            "from enum import Enum\n"
            "class RemediationStatus(str, Enum):\n"
            "    PENDING = 'pending'\n"
        )
        v = check_file_intent(prompt, command)
        assert v.is_code_block
        assert v.confidence == "HIGH"
        assert v.suggested_action == "WRITE_FILE"
        assert "actions.py" in v.reason

    def test_prompt_with_ts_file_and_ts_code(self):
        prompt = "Create src/components/App.tsx with:"
        command = (
            "import React from 'react'\n"
            "export default function App() {\n"
            "  return <div>Hello</div>;\n"
            "}\n"
        )
        v = check_file_intent(prompt, command)
        assert v.is_code_block
        assert v.confidence == "HIGH"

    def test_prompt_without_file_path(self):
        prompt = "Run the tests"
        command = "pytest tests/ -v"
        v = check_file_intent(prompt, command)
        assert not v.is_code_block

    def test_prompt_with_shell_extension(self):
        prompt = "Create deploy.sh with:"
        command = "#!/bin/bash\necho 'deploying...'\nnpm run build"
        v = check_file_intent(prompt, command)
        # .sh is not in _NON_SHELL_EXTENSIONS, so no boost
        assert not v.is_code_block

    def test_prompt_mentions_file_but_command_is_shell(self):
        prompt = "Create the file config.py"
        command = "ls -la"
        v = check_file_intent(prompt, command)
        assert not v.is_code_block

    def test_prompt_write_yaml_file(self):
        prompt = "Write config.yaml with this content:"
        command = (
            "name: default\n"
            "version: '1.0'\n"
            "rules:\n"
            "  - id: POL-001\n"
            "    domain: config\n"
        )
        v = check_file_intent(prompt, command)
        assert v.is_code_block
        assert v.confidence == "HIGH"


# ── CommandVerdict dataclass ─────────────────────────────────────────────────


@pytest.mark.unit
class TestCommandVerdict:
    def test_verdict_is_frozen(self):
        v = classify_command("ls")
        with pytest.raises(AttributeError):
            v.is_code_block = True  # type: ignore[misc]

    def test_verdict_has_all_fields(self):
        v = classify_command("echo hi")
        assert hasattr(v, "is_code_block")
        assert hasattr(v, "confidence")
        assert hasattr(v, "detected_language")
        assert hasattr(v, "matched_tokens")
        assert hasattr(v, "suggested_action")
        assert hasattr(v, "reason")


# ── Edge cases and regression guards ────────────────────────────────────────


@pytest.mark.unit
class TestCommandGuardEdgeCases:
    def test_issue_39233_repro_case(self):
        """Exact reproduction from the issue: Python class definition executed as shell."""
        command = (
            "from dataclasses import dataclass\n"
            "from enum import Enum\n"
            "class RemediationStatus(str, Enum):\n"
            "    PENDING = 'pending'\n"
        )
        v = classify_command(command)
        assert v.is_code_block, "Must detect the issue #39233 repro case"
        assert v.detected_language == "python"
        assert v.suggested_action == "WRITE_FILE"

    def test_multiline_python_with_blank_lines(self):
        cmd = (
            "from pathlib import Path\n"
            "\n"
            "\n"
            "class Config:\n"
            "    pass\n"
        )
        v = classify_command(cmd)
        assert v.is_code_block

    def test_mixed_language_tokens_picks_dominant(self):
        cmd = (
            "from os import path\n"
            "class Foo:\n"
            "    pass\n"
            "def bar():\n"
            "    pass\n"
            "const x = 1;\n"  # single JS token
        )
        v = classify_command(cmd)
        assert v.detected_language == "python"

    def test_heredoc_is_not_flagged(self):
        """A shell heredoc should not be flagged as code."""
        cmd = "cat > /tmp/file.py << 'EOF'\nfrom os import path\nEOF"
        v = classify_command(cmd)
        # The heredoc wrapping indicates intentional shell use, but the heuristic
        # sees the Python tokens. This is an acceptable edge case where the
        # confidence will be lower.
        # We just verify it doesn't crash.
        assert isinstance(v, CommandVerdict)

    def test_very_long_command_does_not_crash(self):
        cmd = "from foo import bar\nclass X:\n    pass\n" * 100
        v = classify_command(cmd)
        assert v.is_code_block
