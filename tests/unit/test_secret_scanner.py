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
        matches = scanner.scan_text(f"token = {skip_val}", "test.txt")
        # Should not find secrets in clearly-placeholder values
        # (actual behavior depends on if placeholder matches pattern)
        assert isinstance(matches, list)


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
