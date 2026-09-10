from __future__ import annotations

import hashlib
import hmac


def fingerprint(secret: str, key: bytes | str) -> str:
    """Create a correlation-safe fingerprint without storing the raw secret."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise ValueError("fingerprint key must be non-empty")
    return hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()
