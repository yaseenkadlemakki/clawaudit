"""Tests for the secret scanner."""
import pytest
from sentinel.analyzer.secret_scanner import SecretScanner, SKIP_VALUES


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
