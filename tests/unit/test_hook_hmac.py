"""Tests for HMAC validation in hooks API routes."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest


@pytest.mark.unit
class TestHmacValidation:
    """Test HMAC validation logic used by the hooks API."""

    def _sign(self, body: bytes, secret: str) -> str:
        return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    def test_valid_signature(self):
        secret = "abcd1234" * 8
        body = json.dumps({"tool_name": "exec", "session_id": "s1"}).encode()
        sig = self._sign(body, secret)

        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        provided = sig.removeprefix("sha256=")
        assert hmac.compare_digest(expected, provided)

    def test_invalid_signature(self):
        secret = "abcd1234" * 8
        body = json.dumps({"tool_name": "exec"}).encode()

        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(expected, "deadbeef" * 8)

    def test_missing_signature(self):
        """Empty signature should never match."""
        secret = "abcd1234" * 8
        body = b'{"tool_name": "exec"}'
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(expected, "")

    def test_tampered_body(self):
        secret = "abcd1234" * 8
        body = json.dumps({"tool_name": "exec"}).encode()
        sig = self._sign(body, secret)

        tampered = json.dumps({"tool_name": "exec", "evil": True}).encode()
        expected = hmac.new(secret.encode(), tampered, hashlib.sha256).hexdigest()
        provided = sig.removeprefix("sha256=")
        assert not hmac.compare_digest(expected, provided)
