"""Shared hashing helpers for JLM AI AGENT provenance."""

import hashlib
import json


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase SHA-256 digest of bytes."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).hexdigest()


def sha256_json(value) -> str:
    """Hash JSON-compatible data using deterministic serialization."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256_bytes(encoded)


def is_sha256_hex(value) -> bool:
    """Return True only for a 64-character hexadecimal SHA-256 digest."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True
