"""Fail-closed loader for the local JLM payment authorization key registry.

This registry contains public keys only. Private signing keys must remain
separate and must never be stored in this directory.
"""

import json
import os
import re
import stat
from pathlib import Path


REGISTRY_SCHEMA = "jlmai.payment-key-registry.v1"

REGISTRY_DIR = Path.home() / ".jlmai" / "payment-keys"
REGISTRY_PATH = REGISTRY_DIR / "registry.json"
TRUSTED_KEY_DIR = REGISTRY_DIR

MAX_REGISTRY_BYTES = 65536

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_KEY_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.pem$")


class RegistryError(ValueError):
    """The local trusted-key registry is invalid or unavailable."""


def _reject_duplicate_keys(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise RegistryError("Duplicate JSON key")
        result[key] = value

    return result


def _validate_directory(path):
    path = Path(path)

    try:
        info = path.lstat()
    except OSError as exc:
        raise RegistryError("Registry directory is unavailable") from exc

    if not stat.S_ISDIR(info.st_mode):
        raise RegistryError("Registry path must be a real directory")

    if info.st_uid != os.getuid():
        raise RegistryError("Registry directory has an unexpected owner")

    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RegistryError("Registry directory permissions must be 700 or stricter")


def _read_registry_file(path):
    path = Path(path)

    if not hasattr(os, "O_NOFOLLOW"):
        raise RegistryError("Platform lacks required no-follow file protection")

    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)

    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise RegistryError("Registry file is unavailable or unsafe") from exc

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode):
            raise RegistryError("Registry must be a regular file")

        if info.st_uid != os.getuid():
            raise RegistryError("Registry file has an unexpected owner")

        if stat.S_IMODE(info.st_mode) & 0o077:
            raise RegistryError("Registry file permissions must be 600 or stricter")

        if info.st_size <= 0 or info.st_size > MAX_REGISTRY_BYTES:
            raise RegistryError("Registry file size is invalid")

        chunks = []
        remaining = MAX_REGISTRY_BYTES + 1

        while remaining > 0:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)

        data = b"".join(chunks)

        if len(data) > MAX_REGISTRY_BYTES:
            raise RegistryError("Registry file is too large")

        return data

    finally:
        os.close(descriptor)


def _validate_public_key(filename):
    if not isinstance(filename, str) or not _KEY_FILENAME.fullmatch(filename):
        raise RegistryError("Invalid public-key filename")

    key_path = TRUSTED_KEY_DIR / filename

    try:
        info = key_path.lstat()
    except OSError as exc:
        raise RegistryError("Trusted public key is unavailable") from exc

    if not stat.S_ISREG(info.st_mode):
        raise RegistryError("Trusted public key must be a regular file")

    if info.st_uid != os.getuid():
        raise RegistryError("Trusted public key has an unexpected owner")

    if stat.S_IMODE(info.st_mode) & 0o022:
        raise RegistryError("Trusted public key must not be group/world writable")

    return str(key_path)


def load_trusted_keys():
    """Load and validate the application-controlled local key registry."""

    _validate_directory(REGISTRY_DIR.parent)
    _validate_directory(REGISTRY_DIR)

    raw = _read_registry_file(REGISTRY_PATH)

    try:
        registry = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError("Registry JSON is invalid") from exc

    if not isinstance(registry, dict):
        raise RegistryError("Registry root must be an object")

    if set(registry) != {"schema", "keys"}:
        raise RegistryError("Registry fields are invalid")

    if registry.get("schema") != REGISTRY_SCHEMA:
        raise RegistryError("Registry schema is unsupported")

    entries = registry.get("keys")

    if not isinstance(entries, dict) or not entries:
        raise RegistryError("Registry must contain at least one key")

    trusted_keys = {}

    for key_id, entry in entries.items():
        if not isinstance(key_id, str) or not _IDENTIFIER.fullmatch(key_id):
            raise RegistryError("Invalid registry key identifier")

        if not isinstance(entry, dict):
            raise RegistryError("Registry key entry must be an object")

        if set(entry) != {"signer_id", "public_key_file", "status"}:
            raise RegistryError("Registry key entry fields are invalid")

        signer_id = entry.get("signer_id")
        status = entry.get("status")

        if not isinstance(signer_id, str) or not _IDENTIFIER.fullmatch(signer_id):
            raise RegistryError("Invalid registry signer identifier")

        if not isinstance(status, str) or status not in {"ACTIVE", "REVOKED"}:
            raise RegistryError("Invalid registry key status")

        public_key_path = _validate_public_key(
            entry.get("public_key_file")
        )

        trusted_keys[key_id] = {
            "signer_id": signer_id,
            "public_key_path": public_key_path,
            "status": status,
        }

    return trusted_keys
