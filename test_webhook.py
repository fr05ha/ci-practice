import hashlib
import hmac
import os
import pytest

from webhook import validate_webhook_signature


SECRET = "test-secret"


def make_signature(body: bytes, secret: str = SECRET) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


@pytest.fixture(autouse=True)
def set_webhook_secret(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)


class TestValidWebhookSignature:
    def test_valid_signature(self):
        body = b'{"action": "opened"}'
        assert validate_webhook_signature(body, make_signature(body)) is True

    def test_valid_empty_body(self):
        body = b""
        assert validate_webhook_signature(body, make_signature(body)) is True

    def test_valid_large_body(self):
        body = b"x" * 100_000
        assert validate_webhook_signature(body, make_signature(body)) is True


class TestInvalidWebhookSignature:
    def test_wrong_secret(self):
        body = b'{"action": "opened"}'
        sig = make_signature(body, secret="wrong-secret")
        assert validate_webhook_signature(body, sig) is False

    def test_tampered_body(self):
        body = b'{"action": "opened"}'
        sig = make_signature(body)
        assert validate_webhook_signature(b'{"action": "closed"}', sig) is False

    def test_tampered_signature(self):
        body = b'{"action": "opened"}'
        assert validate_webhook_signature(body, "sha256=" + "a" * 64) is False

    def test_wrong_algorithm_prefix(self):
        body = b'{"action": "opened"}'
        digest = hmac.new(SECRET.encode(), body, hashlib.sha1).hexdigest()
        with pytest.raises(ValueError, match="Unsupported signature algorithm"):
            validate_webhook_signature(body, f"sha1={digest}")


class TestMalformedHeader:
    def test_empty_header(self):
        with pytest.raises(ValueError, match="Missing signature header"):
            validate_webhook_signature(b"body", "")

    def test_no_prefix(self):
        with pytest.raises(ValueError, match="Unsupported signature algorithm"):
            validate_webhook_signature(b"body", "abc123")

    def test_only_prefix(self):
        assert validate_webhook_signature(b"body", "sha256=") is False


class TestMissingEnvVar:
    def test_missing_secret_env_var(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
        with pytest.raises(EnvironmentError, match="WEBHOOK_SECRET environment variable is not set"):
            validate_webhook_signature(b"body", make_signature(b"body"))
