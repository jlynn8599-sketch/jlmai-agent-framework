"""Ed25519 tests using temporary keys; no real payments are made."""

import shutil
import subprocess

import pytest

from v2.payment_signatures import (
    OpenSSLExecutionError,
    sign_message,
    verify_message,
)


@pytest.fixture
def keypairs(tmp_path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is unavailable")

    pairs = []

    for index in range(2):
        private_key = tmp_path / f"private-{index}.pem"
        public_key = tmp_path / f"public-{index}.pem"

        subprocess.run(
            [
                openssl,
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                openssl,
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )

        private_key.chmod(0o600)
        pairs.append((private_key, public_key))

    return pairs


def test_ed25519_sign_and_verify(keypairs):
    private_key, public_key = keypairs[0]
    message = b"JLM AI AGENT authorization test"

    signature = sign_message(message, private_key)

    assert len(signature) == 64
    assert verify_message(message, signature, public_key) is True


def test_rejects_tampered_message(keypairs):
    private_key, public_key = keypairs[0]
    signature = sign_message(b"original", private_key)

    assert verify_message(
        b"tampered", signature, public_key
    ) is False


def test_rejects_wrong_public_key(keypairs):
    private_key, unused_public = keypairs[0]
    wrong_public = keypairs[1][1]

    signature = sign_message(b"authorization", private_key)

    assert verify_message(
        b"authorization", signature, wrong_public
    ) is False


def test_rejects_invalid_signature_length(keypairs):
    public_key = keypairs[0][1]

    assert verify_message(
        b"authorization", b"short", public_key
    ) is False


def test_rejects_private_key_with_broad_permissions(keypairs):
    private_key, unused_public = keypairs[0]
    private_key.chmod(0o644)

    with pytest.raises(ValueError):
        sign_message(b"authorization", private_key)


def test_rejects_missing_private_key(tmp_path):
    with pytest.raises(ValueError):
        sign_message(
            b"authorization",
            tmp_path / "missing-private.pem",
        )


def test_rejects_non_bytes_message(keypairs):
    private_key, unused_public = keypairs[0]

    with pytest.raises(TypeError):
        sign_message("not bytes", private_key)


def test_rejects_non_ed25519_private_key(keypairs, tmp_path):
    openssl = shutil.which("openssl")
    rsa_key = tmp_path / "rsa-private.pem"

    subprocess.run(
        [
            openssl,
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(rsa_key),
        ],
        check=True,
        capture_output=True,
    )

    rsa_key.chmod(0o600)

    with pytest.raises(OpenSSLExecutionError):
        sign_message(b"authorization", rsa_key)
