"""Payment authorization envelope security tests; no transfers occur."""

import base64
import shutil
import subprocess

import pytest
from v2 import payment_authorization

from v2.payment_authorization import (
    create_authorization_envelope,
    verify_authorization_envelope,
)
from v2.tests.test_payment_policy import (
    make_payment,
    make_payment_request,
)
from v2.tests.test_framework import make_witness_chain
from v2.provenance import validate_request


@pytest.fixture
def authorization_setup(tmp_path, monkeypatch):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is unavailable")

    private_key = tmp_path / "authorization-private.pem"
    public_key = tmp_path / "authorization-public.pem"

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

    payment = make_payment()
    provenance = make_payment_request(payment)

    trusted_keys = {
        "jlmai-test-key-001": {
            "signer_id": "jlmai-test-signer",
            "public_key_path": str(public_key),
            "status": "ACTIVE",
        }
    }

    monkeypatch.setattr(
        payment_authorization,
        "load_trusted_keys",
        lambda: trusted_keys,
    )

    envelope = create_authorization_envelope(
        payment=payment,
        provenance_request=provenance,
        signer_id="jlmai-test-signer",
        key_id="jlmai-test-key-001",
        private_key_path=private_key,
    )

    return {
        "payment": payment,
        "provenance": provenance,
        "private_key": private_key,
        "public_key": public_key,
        "trusted_keys": trusted_keys,
        "envelope": envelope,
    }


def verify(setup, envelope=None, payment=None, provenance=None, keys=None):
    if keys is not None:
        setup["trusted_keys"].clear()
        setup["trusted_keys"].update(
            {key_id: dict(entry) for key_id, entry in keys.items()}
        )

    return verify_authorization_envelope(
        envelope if envelope is not None else setup["envelope"],
        payment if payment is not None else setup["payment"],
        provenance if provenance is not None else setup["provenance"],
    )


def test_valid_authorization_envelope_passes(authorization_setup):
    assert verify(authorization_setup) is True


def test_tampered_payment_is_rejected(authorization_setup):
    payment = dict(authorization_setup["payment"])
    payment["amount_minor"] = 2500

    assert verify(authorization_setup, payment=payment) is False


def test_tampered_signature_is_rejected(authorization_setup):
    envelope = dict(authorization_setup["envelope"])
    signature = bytearray(
        base64.b64decode(envelope["signature"])
    )
    signature[0] ^= 1
    envelope["signature"] = base64.b64encode(signature).decode("ascii")

    assert verify(authorization_setup, envelope=envelope) is False


def test_unknown_key_id_is_rejected(authorization_setup):
    envelope = dict(authorization_setup["envelope"])
    envelope["key_id"] = "unknown-key"

    assert verify(authorization_setup, envelope=envelope) is False


def test_revoked_key_is_rejected(authorization_setup):
    keys = {
        key_id: dict(entry)
        for key_id, entry in authorization_setup["trusted_keys"].items()
    }
    keys["jlmai-test-key-001"]["status"] = "REVOKED"

    assert verify(authorization_setup, keys=keys) is False


def test_signer_key_identity_mismatch_is_rejected(authorization_setup):
    keys = {
        key_id: dict(entry)
        for key_id, entry in authorization_setup["trusted_keys"].items()
    }
    keys["jlmai-test-key-001"]["signer_id"] = "different-signer"

    assert verify(authorization_setup, keys=keys) is False


def test_changed_envelope_request_id_is_rejected(authorization_setup):
    envelope = dict(authorization_setup["envelope"])
    envelope["request_id"] = "different-request"

    assert verify(authorization_setup, envelope=envelope) is False


def test_invalid_provenance_is_rejected(authorization_setup):
    provenance = dict(authorization_setup["provenance"])
    provenance["risk"] = provenance["threshold"]

    assert verify(authorization_setup, provenance=provenance) is False


def test_unknown_signer_is_rejected(authorization_setup):
    envelope = dict(authorization_setup["envelope"])
    envelope["signer_id"] = "unknown-signer"

    assert verify(authorization_setup, envelope=envelope) is False


def test_extra_envelope_field_is_rejected(authorization_setup):
    envelope = dict(authorization_setup["envelope"])
    envelope["public_key_path"] = "/untrusted/key.pem"

    assert verify(authorization_setup, envelope=envelope) is False


def test_malformed_signature_encoding_is_rejected(authorization_setup):
    envelope = dict(authorization_setup["envelope"])
    envelope["signature"] = "not-valid-base64!"

    assert verify(authorization_setup, envelope=envelope) is False


def test_envelope_does_not_execute_payment(authorization_setup):
    assert verify(authorization_setup) is True
    assert "executed" not in authorization_setup["envelope"]


def test_valid_changed_provenance_cannot_reuse_old_signature(
    authorization_setup,
):
    provenance = dict(authorization_setup["provenance"])

    # Change T4 source data without changing the payment commitment.
    provenance["original"] = {
        **provenance["original"],
        "role": "operator",
    }

    # Rebuild all five witnesses for the changed request.
    provenance["witnesses"] = make_witness_chain(provenance)

    # Confirm this is a valid, independently rebuilt T1-T5 request.
    result = validate_request(provenance)
    assert result["allowed"] is True

    # The original signature must not authorize the changed provenance.
    assert verify(authorization_setup, provenance=provenance) is False

    # The signed envelope must contain a SHA-256 provenance commitment.
    commitment = authorization_setup["envelope"]["provenance_commitment"]
    assert isinstance(commitment, str)
    assert len(commitment) == 64
