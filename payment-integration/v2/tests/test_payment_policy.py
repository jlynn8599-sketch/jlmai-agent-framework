"""Tests for local payment policy evaluation; no real payments are made."""

from v2.payment_policy import evaluate_payment
from v2.tests.test_framework import make_request, make_witness_chain
from v2.hashing import sha256_json
from v2.payment_authorization import create_authorization_envelope
from v2.provenance import validate_request
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch


def make_policy():
    return {
        "max_amount_minor": 50000,
        "allowed_currencies": ["USD"],
        "allowed_destinations": ["merchant_demo"],
        "required_capabilities": ["payment:authorize"],
        "granted_capabilities": ["payment:authorize"],
    }


def make_payment():
    return {
        "amount_minor": 1250,
        "currency": "USD",
        "destination": "merchant_demo",
        "idempotency_key": "test-payment-001",
    }


def make_payment_request(payment):
    request = make_request()
    commitment = sha256_json(payment)
    request["payment_commitment"] = commitment
    request["expected_hash"] = commitment
    request["actual_hash"] = commitment
    request["witnesses"] = make_witness_chain(request)
    return request


def evaluate(payment=None, policy=None, provenance=None, seen=None):
    payment = payment if payment is not None else make_payment()
    provenance = (
        provenance if provenance is not None
        else make_payment_request(payment)
    )

    # Invalid provenance must reach the policy's provenance rejection path.
    valid_provenance = (
        isinstance(provenance, dict)
        and validate_request(provenance).get("allowed") is True
        and provenance.get("payment_commitment") == sha256_json(payment)
    )

    if not valid_provenance:
        return evaluate_payment(
            payment,
            provenance,
            policy if policy is not None else make_policy(),
            seen_idempotency_keys=seen,
        )

    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("OpenSSL is required for signed policy tests")

    with tempfile.TemporaryDirectory() as directory:
        private_key = Path(directory) / "test-private.pem"
        public_key = Path(directory) / "test-public.pem"

        subprocess.run(
            [
                openssl, "genpkey",
                "-algorithm", "ED25519",
                "-out", str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                openssl, "pkey",
                "-in", str(private_key),
                "-pubout",
                "-out", str(public_key),
            ],
            check=True,
            capture_output=True,
        )
        private_key.chmod(0o600)

        signer_id = "jlmai-policy-test-signer"
        key_id = "jlmai-policy-test-key"

        envelope = create_authorization_envelope(
            payment=payment,
            provenance_request=provenance,
            signer_id=signer_id,
            key_id=key_id,
            private_key_path=private_key,
        )

        trusted_keys = {
            key_id: {
                "signer_id": signer_id,
                "public_key_path": str(public_key),
                "status": "ACTIVE",
            }
        }

        with patch(
            "v2.payment_authorization.load_trusted_keys",
            return_value=trusted_keys,
        ):
            return evaluate_payment(
                payment,
                provenance,
                policy if policy is not None else make_policy(),
                seen_idempotency_keys=seen,
                authorization_envelope=envelope,
            )


def test_valid_payment_policy_passes_without_execution():
    result = evaluate()
    assert result["status"] == "PASS"
    assert result["allowed"] is True
    assert result["executed"] is False


def test_rejects_non_dictionary_payment():
    result = evaluate(payment=None)  # Normal helper uses a valid payment.
    assert result["allowed"] is True
    result = evaluate_payment(None, make_request(), make_policy())
    assert result["allowed"] is False


def test_rejects_zero_negative_or_boolean_amount():
    for amount in (0, -1, True, 1.5, "1250"):
        payment = make_payment()
        payment["amount_minor"] = amount
        assert evaluate(payment=payment)["allowed"] is False


def test_rejects_amount_over_limit():
    payment = make_payment()
    payment["amount_minor"] = 50001
    assert evaluate(payment=payment)["allowed"] is False


def test_rejects_unapproved_currency_or_destination():
    payment = make_payment()
    payment["currency"] = "EUR"
    assert evaluate(payment=payment)["allowed"] is False

    payment = make_payment()
    payment["destination"] = "unapproved_destination"
    assert evaluate(payment=payment)["allowed"] is False


def test_rejects_duplicate_idempotency_key():
    result = evaluate(seen=["test-payment-001"])
    assert result["allowed"] is False
    assert "Duplicate" in result["reason"]


def test_rejects_missing_capability():
    policy = make_policy()
    policy["granted_capabilities"] = []
    assert evaluate(policy=policy)["allowed"] is False


def test_rejects_failed_provenance():
    request = make_request()
    request["risk"] = request["threshold"]
    assert evaluate(provenance=request)["allowed"] is False


def test_rejects_incomplete_policy():
    assert evaluate(policy={})["allowed"] is False


def test_rejects_invalid_idempotency_key():
    payment = make_payment()
    payment["idempotency_key"] = " "
    assert evaluate(payment=payment)["allowed"] is False



def test_rejects_changed_payment_with_old_provenance():
    original = make_payment()
    provenance = make_payment_request(original)

    changes = {
        "amount_minor": 2500,
        "currency": "EUR",
        "destination": "another_merchant",
        "idempotency_key": "different-payment-key",
    }

    for field, changed_value in changes.items():
        changed = dict(original)
        changed[field] = changed_value
        result = evaluate_payment(changed, provenance, make_policy())
        assert result["allowed"] is False, field


def test_accepts_exact_payment_with_matching_commitment():
    payment = make_payment()
    provenance = make_payment_request(payment)

    result = evaluate(payment=payment, provenance=provenance)

    assert result["status"] == "PASS"
    assert result["allowed"] is True
    assert result["executed"] is False


def test_rejects_payment_provenance_without_commitment():
    payment = make_payment()
    result = evaluate_payment(payment, make_request(), make_policy())

    assert result["status"] == "FAIL"
    assert result["allowed"] is False


def test_rejects_tampered_payment_commitment_evidence():
    payment = make_payment()
    provenance = make_payment_request(payment)
    provenance["witnesses"][2]["evidence"]["payment_commitment"] = "tampered"

    result = evaluate_payment(payment, provenance, make_policy())

    assert result["allowed"] is False

def test_rejects_payment_without_signed_authorization():
    payment = make_payment()
    provenance = make_payment_request(payment)

    result = evaluate_payment(payment, provenance, make_policy())

    assert result["status"] == "FAIL"
    assert result["allowed"] is False
    assert result["reason"] == "Signed payment authorization is required"


def test_rejects_malformed_authorization_envelope():
    payment = make_payment()
    provenance = make_payment_request(payment)

    result = evaluate_payment(
        payment,
        provenance,
        make_policy(),
        authorization_envelope={"placeholder": True},
    )

    assert result["status"] == "FAIL"
    assert result["allowed"] is False
    assert result["reason"] == (
        "Ed25519 payment authorization verification failed"
    )
