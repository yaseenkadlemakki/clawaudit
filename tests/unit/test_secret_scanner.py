"""Tests for the secret scanner."""

import pytest

from sentinel.analyzer.secret_scanner import SKIP_VALUES, SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner()


def test_detects_anthropic_key(scanner):
    text = "api_key = sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
    matches = scanner.scan_text(text, "test.txt")
    assert any(m.secret_type == "anthropic_key" for m in matches)


def test_detects_openai_key(scanner):
    text = "key = sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"
    matches = scanner.scan_text(text, "test.txt")
    assert any(m.secret_type == "openai_key" for m in matches)


def test_detects_aws_access_key(scanner):
    text = "aws_key = AKIAIOSFODNN7EXAMPLE"
    matches = scanner.scan_text(text, "test.txt")
    assert any(m.secret_type == "aws_access_key" for m in matches)


def test_detects_github_pat(scanner):
    text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    matches = scanner.scan_text(text, "test.txt")
    assert any(m.secret_type == "github_pat" for m in matches)


def test_detects_pem_key(scanner):
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
    matches = scanner.scan_text(text, "test.txt")
    assert any(m.secret_type == "pem_private_key" for m in matches)


def test_detects_jwt(scanner):
    text = "token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123def"
    matches = scanner.scan_text(text, "test.txt")
    assert any(m.secret_type == "jwt_token" for m in matches)


def test_skip_redacted_values(scanner):
    for skip_val in SKIP_VALUES:
        # Embed each known placeholder in a realistic key context and verify it is NOT flagged
        text = f'gateway_token = "{skip_val}"'
        matches = scanner.scan_text(text, "test.txt")
        assert len(matches) == 0, (
            f"Skip value {skip_val!r} was incorrectly flagged as a secret. "
            "SKIP_VALUES list must cover all placeholder patterns."
        )


def test_skip_placeholder_token(scanner):
    text = "token = YOUR_TOKEN_HERE"
    matches = scanner.scan_text(text, "test.txt")
    # YOUR_TOKEN_HERE is too short for most patterns — should be zero
    assert len(matches) == 0


def test_no_false_positives_on_short_strings(scanner):
    text = "sk-abc short"
    matches = scanner.scan_text(text, "test.txt")
    assert len(matches) == 0


def test_secret_value_not_in_evidence(scanner):
    """Verify matched value is never stored in the match object."""
    real_key = "sk-ant-api03-" + "A" * 30
    text = f"key = {real_key}"
    matches = scanner.scan_text(text, "test.txt")
    for m in matches:
        assert real_key not in m.context


def test_scan_dict(scanner):
    data = {"auth": {"token": "sk-ant-api03-" + "B" * 30}}
    matches = scanner.scan_dict(data, "config.json")
    assert len(matches) > 0
    assert matches[0].secret_type == "anthropic_key"


# ── Edge case tests ────────────────────────────────────────────────────────────


def test_scan_empty_string(scanner):
    """scan_text on empty string returns empty list without error."""
    matches = scanner.scan_text("", "empty.txt")
    assert matches == []


def test_scan_empty_dict(scanner):
    """scan_dict on empty dict returns empty list without error."""
    matches = scanner.scan_dict({}, "config.json")
    assert matches == []


def test_secret_value_not_in_context(scanner):
    """The matched context must not contain the raw secret value."""
    real_key = "sk-ant-api03-" + "Z" * 40
    text = f"export ANTHROPIC_API_KEY={real_key}"
    matches = scanner.scan_text(text, "env.sh")
    for m in matches:
        assert real_key not in m.context, "Raw secret value leaked into match context"


def test_nested_dict_scan(scanner):
    """Secrets nested multiple levels deep are detected."""
    data = {"level1": {"level2": {"key": "sk-ant-api03-" + "C" * 30}}}
    matches = scanner.scan_dict(data, "deep.json")
    assert len(matches) > 0
    assert all(m.secret_type == "anthropic_key" for m in matches)


# ── sanitize_line tests ───────────────────────────────────────────────────────


class TestSanitizeLine:
    def test_sanitize_single_aws_key(self, scanner):
        line = "key=AKIA1234567890ABCDEF end"
        result = scanner.sanitize_line(line)
        assert "AKIA1234567890ABCDEF" not in result
        assert "[REDACTED:aws_access_key]" in result

    def test_sanitize_multiple_secrets_on_one_line(self, scanner):
        """Both an AWS key and a generic Bearer token on the same line must be redacted."""
        aws_key = "AKIA1234567890ABCDEF"
        bearer = "Bearer averylongtokenvalue1234567890abc"
        line = f"aws={aws_key} auth={bearer}"
        result = scanner.sanitize_line(line)
        assert aws_key not in result, f"AWS key survived sanitize_line: {result!r}"
        assert "averylongtokenvalue1234567890abc" not in result, (
            f"Bearer token survived sanitize_line: {result!r}"
        )
        assert "[REDACTED:aws_access_key]" in result
        assert "[REDACTED:generic_bearer]" in result

    def test_sanitize_clean_line_unchanged(self, scanner):
        line = "INFO server started on port 8080"
        assert scanner.sanitize_line(line) == line

    def test_sanitize_preserves_non_secret_content(self, scanner):
        line = "prefix AKIA1234567890ABCDEF suffix"
        result = scanner.sanitize_line(line)
        assert "prefix" in result
        assert "suffix" in result

    def test_sanitize_idempotent_after_redaction(self, scanner):
        """Calling sanitize_line twice must not further mangle the marker."""
        line = "key=AKIA1234567890ABCDEF"
        once = scanner.sanitize_line(line)
        twice = scanner.sanitize_line(once)
        assert once == twice
