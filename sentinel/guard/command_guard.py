"""Pre-execution heuristic to detect non-shell code being run as shell commands.

When an agent receives a code block adjacent to a file path, it should write the
content to a file — not execute it as a shell command.  This module provides a
classifier that inspects a candidate command string and returns a verdict
indicating whether it looks like file content rather than a valid shell command.

See: https://github.com/openclaw/openclaw/issues/39233
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------
# Language-specific token patterns that are *never* valid shell
# ---------------------------------------------------------------------------

# Python syntax tokens
_PYTHON_TOKENS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*from\s+\S+\s+import\s+"), "python_from_import"),
    (re.compile(r"^\s*import\s+[a-zA-Z_]"), "python_import"),
    (re.compile(r"^\s*class\s+[A-Z]\w*[\s(:]"), "python_class"),
    (re.compile(r"^\s*def\s+[a-z_]\w*\s*\("), "python_def"),
    (re.compile(r"^\s*@\w+"), "python_decorator"),
    (re.compile(r"^\s*if\s+__name__\s*=="), "python_main_guard"),
    (re.compile(r"^\s*async\s+def\s+"), "python_async_def"),
    (re.compile(r"^\s*raise\s+\w+"), "python_raise"),
    (re.compile(r"^\s*try\s*:"), "python_try"),
    (re.compile(r"^\s*except\s+\w+"), "python_except"),
    (re.compile(r"^\s*elif\s+"), "python_elif"),
    (re.compile(r'^\s*"""'), "python_docstring"),
]

# TypeScript / JavaScript syntax tokens
_TS_TOKENS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*interface\s+[A-Z]\w*"), "ts_interface"),
    (re.compile(r"^\s*type\s+[A-Z]\w*\s*="), "ts_type_alias"),
    (re.compile(r"^\s*const\s+\w+\s*[=:]"), "ts_const"),
    (re.compile(r"^\s*let\s+\w+\s*[=:]"), "ts_let"),
    (re.compile(r"^\s*export\s+(default\s+)?"), "ts_export"),
    (re.compile(r"^\s*import\s+.*\s+from\s+['\"]"), "ts_import"),
    (re.compile(r"^\s*function\s+\w+\s*\("), "ts_function"),
    (re.compile(r"^\s*=>\s*\{"), "ts_arrow"),
]

# YAML syntax tokens (not valid shell)
_YAML_TOKENS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\w[\w\s]*:\s*$"), "yaml_key_only"),
    (re.compile(r"^\s*-\s+\w+:\s+"), "yaml_list_item"),
]

# Go syntax tokens
_GO_TOKENS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*package\s+\w+"), "go_package"),
    (re.compile(r"^\s*func\s+\w+"), "go_func"),
    (re.compile(r"^\s*import\s+\("), "go_import_block"),
]

# Rust syntax tokens
_RUST_TOKENS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*fn\s+\w+"), "rust_fn"),
    (re.compile(r"^\s*pub\s+(fn|struct|enum|mod)\s+"), "rust_pub"),
    (re.compile(r"^\s*use\s+\w+::"), "rust_use"),
    (re.compile(r"^\s*impl\s+"), "rust_impl"),
]

_ALL_LANG_TOKENS = _PYTHON_TOKENS + _TS_TOKENS + _YAML_TOKENS + _GO_TOKENS + _RUST_TOKENS

# Shell-error signatures produced when non-shell code is executed by zsh/bash
_SHELL_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"zsh:\d+:\s+command not found:\s+"),
    re.compile(r"bash:\s+line\s+\d+:\s+.*:\s+command not found"),
    re.compile(r"zsh:\d+:\s+no matches found:"),
    re.compile(r"bash:\s+syntax error near unexpected token"),
]

# File extensions that are obviously not shell scripts
_NON_SHELL_EXTENSIONS = frozenset(
    {
        ".py",
        ".pyi",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".rb",
        ".lua",
        ".cs",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".swift",
        ".md",
    }
)

# Minimum number of language-specific tokens before we flag the command
_TOKEN_THRESHOLD = 2


@dataclass(frozen=True)
class CommandVerdict:
    """Result of inspecting a candidate command string."""

    is_code_block: bool
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    detected_language: str
    matched_tokens: tuple[str, ...]
    suggested_action: Literal["WRITE_FILE", "EXECUTE", "REVIEW"]
    reason: str


def _detect_file_path(text: str) -> str | None:
    """Extract a file path if one is mentioned adjacent to the code."""
    # Match patterns like: create `path/to/file.py`, or path/to/file.py:
    m = re.search(
        r"(?:create|write|implement|add|put|save)\s+[`'\"]?([^\s`'\"]+\.\w{1,5})[`'\"]?",
        text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1)
    # Standalone file path at start
    m = re.search(r"^([a-zA-Z_][\w/\\.-]+\.\w{1,5})\s*$", text, re.MULTILINE)
    if m:
        return m.group(1)
    return None


def _extension_of(path: str) -> str:
    """Return the lowercased extension of a path."""
    dot = path.rfind(".")
    return path[dot:].lower() if dot >= 0 else ""


def classify_command(command: str) -> CommandVerdict:
    """Classify whether a command string looks like file content, not a shell command.

    This is the main entry point.  It inspects the command for language-specific
    syntax tokens that are not valid shell, and returns a verdict.
    """
    lines = command.strip().splitlines()
    if not lines:
        return CommandVerdict(
            is_code_block=False,
            confidence="LOW",
            detected_language="unknown",
            matched_tokens=(),
            suggested_action="EXECUTE",
            reason="Empty command",
        )

    matched_tokens: list[str] = []
    lang_hits: dict[str, int] = {}

    for line in lines:
        for pattern, token_name in _ALL_LANG_TOKENS:
            if pattern.search(line):
                matched_tokens.append(token_name)
                lang = token_name.split("_")[0]
                lang_hits[lang] = lang_hits.get(lang, 0) + 1

    if not lang_hits:
        return CommandVerdict(
            is_code_block=False,
            confidence="LOW",
            detected_language="shell",
            matched_tokens=(),
            suggested_action="EXECUTE",
            reason="No non-shell syntax detected",
        )

    # Determine dominant language
    dominant_lang = max(lang_hits, key=lambda k: lang_hits[k])
    hit_count = lang_hits[dominant_lang]

    # Confidence calibration
    if hit_count >= 4:
        confidence: Literal["LOW", "MEDIUM", "HIGH"] = "HIGH"
    elif hit_count >= _TOKEN_THRESHOLD:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    is_code = hit_count >= _TOKEN_THRESHOLD

    return CommandVerdict(
        is_code_block=is_code,
        confidence=confidence,
        detected_language=dominant_lang,
        matched_tokens=tuple(matched_tokens),
        suggested_action="WRITE_FILE" if is_code else "REVIEW",
        reason=f"Detected {hit_count} {dominant_lang} syntax token(s) in command",
    )


def detect_shell_errors(output: str) -> list[str]:
    """Detect shell error patterns that indicate non-shell code was executed.

    Returns a list of matched error lines.
    """
    errors: list[str] = []
    for line in output.splitlines():
        for pattern in _SHELL_ERROR_PATTERNS:
            if pattern.search(line):
                errors.append(line.strip())
                break
    return errors


def check_file_intent(prompt: str, command: str) -> CommandVerdict:
    """Higher-level check combining prompt context with command analysis.

    If the prompt mentions a file path with a non-shell extension *and* the
    command contains language-specific tokens, confidence is boosted.
    """
    base_verdict = classify_command(command)

    file_path = _detect_file_path(prompt)
    if file_path and _extension_of(file_path) in _NON_SHELL_EXTENSIONS:
        # Boost: prompt says "create foo.py" and command has Python tokens
        if base_verdict.matched_tokens:
            return CommandVerdict(
                is_code_block=True,
                confidence="HIGH",
                detected_language=base_verdict.detected_language,
                matched_tokens=base_verdict.matched_tokens,
                suggested_action="WRITE_FILE",
                reason=(
                    f"Prompt references file '{file_path}' with non-shell extension "
                    f"and command contains {base_verdict.detected_language} syntax"
                ),
            )

    return base_verdict
