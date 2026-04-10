import hashlib
import hmac
import os


def validate_webhook_signature(body: bytes, signature_header: str) -> bool:
    """
    Validate a GitHub webhook HMAC-SHA256 signature.

    The webhook secret is read from the WEBHOOK_SECRET environment variable,
    which should be set via a GitHub Actions secret (never hardcoded).

    Args:
        body: Raw request body bytes.
        signature_header: Value of the X-Hub-Signature-256 header (e.g. "sha256=abc123...").

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        ValueError: If the signature header is missing or malformed.
        EnvironmentError: If the WEBHOOK_SECRET environment variable is not set.
    """
    secret = os.environ.get("WEBHOOK_SECRET")
    if not secret:
        raise EnvironmentError("WEBHOOK_SECRET environment variable is not set")

    if not signature_header:
        raise ValueError("Missing signature header")

    if not signature_header.startswith("sha256="):
        raise ValueError(f"Unsupported signature algorithm: {signature_header!r}")

    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    provided = signature_header[len("sha256="):]

    return hmac.compare_digest(expected, provided)
