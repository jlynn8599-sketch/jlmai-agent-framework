"""Fail-closed Ed25519 signing and verification using the OpenSSL CLI.

This module signs bytes only. It does not authorize or execute payments.
Private keys must be PEM files with owner-only filesystem permissions.
"""

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


class OpenSSLExecutionError(RuntimeError):
    """OpenSSL could not complete a cryptographic operation."""


def _resolve_openssl(openssl_bin):
    executable = shutil.which(str(openssl_bin))
    if executable is None:
        raise OpenSSLExecutionError("OpenSSL executable was not found")
    return executable


def _require_regular_file(path, description):
    path = Path(path)

    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{description} is unavailable") from exc

    if not stat.S_ISREG(mode):
        raise ValueError(f"{description} must be a regular file")

    return path


def _validate_message(message):
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")


def _validate_timeout(timeout):
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a positive number")


def _run_openssl(args, timeout):
    try:
        result = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OpenSSLExecutionError("OpenSSL operation timed out") from exc
    except OSError as exc:
        raise OpenSSLExecutionError("Unable to execute OpenSSL") from exc

    return result


def sign_message(
    message,
    private_key_path,
    openssl_bin="openssl",
    timeout=10,
):
    """Sign message bytes with a protected Ed25519 PEM private key."""
    _validate_message(message)
    _validate_timeout(timeout)

    key_path = _require_regular_file(
        private_key_path, "Private key"
    )

    if key_path.is_symlink():
        raise ValueError("Private key must not be a symbolic link")

    permissions = stat.S_IMODE(key_path.stat().st_mode)
    if permissions & 0o077:
        raise ValueError(
            "Private key permissions are too broad; use chmod 600"
        )

    executable = _resolve_openssl(openssl_bin)

    with tempfile.TemporaryDirectory(prefix="jlmai-ed25519-") as temp:
        temp_path = Path(temp)
        message_file = temp_path / "message.bin"
        signature_file = temp_path / "signature.bin"

        message_file.write_bytes(message)

        result = _run_openssl(
            [
                executable,
                "pkeyutl",
                "-sign",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(message_file),
                "-out",
                str(signature_file),
            ],
            timeout,
        )

        if result.returncode != 0:
            raise OpenSSLExecutionError(
                "Ed25519 signing failed"
            )

        try:
            signature = signature_file.read_bytes()
        except OSError as exc:
            raise OpenSSLExecutionError(
                "OpenSSL did not produce a signature"
            ) from exc

        if len(signature) != 64:
            raise OpenSSLExecutionError(
                "Unexpected Ed25519 signature length"
            )

        return signature


def verify_message(
    message,
    signature,
    public_key_path,
    openssl_bin="openssl",
    timeout=10,
):
    """Verify message bytes using an independently trusted public key."""
    _validate_message(message)
    _validate_timeout(timeout)

    if not isinstance(signature, bytes) or len(signature) != 64:
        return False

    try:
        key_path = _require_regular_file(
            public_key_path, "Public key"
        )
    except ValueError:
        return False

    if key_path.is_symlink():
        return False

    executable = _resolve_openssl(openssl_bin)

    with tempfile.TemporaryDirectory(prefix="jlmai-ed25519-") as temp:
        temp_path = Path(temp)
        message_file = temp_path / "message.bin"
        signature_file = temp_path / "signature.bin"

        message_file.write_bytes(message)
        signature_file.write_bytes(signature)

        result = _run_openssl(
            [
                executable,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(message_file),
                "-sigfile",
                str(signature_file),
            ],
            timeout,
        )

        return result.returncode == 0
