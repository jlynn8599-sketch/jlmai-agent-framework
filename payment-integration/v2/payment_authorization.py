"""Ed25519 payment authorization envelope binding.

This module verifies authorization signatures only.
It does not execute, submit, or settle payments.
Public keys must come from a trusted local registry.
"""

import base64
import json
import re

from .hashing import sha256_json
from .payment_signatures import sign_message, verify_message
from .provenance import validate_request
from .payment_key_registry import load_trusted_keys


SCHEMA = "jlmai.payment-authorization.v1"
ALGORITHM = "Ed25519"

PAYLOAD_FIELDS = {
    "schema",
    "algorithm",
    "authorization_version",
    "signer_id",
    "key_id",
    "request_id",
    "payment_commitment",
    "provenance_commitment",
}

ENVELOPE_FIELDS = PAYLOAD_FIELDS | {"signature"}


def _canonical_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _valid_identifier(value):
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 200
    )


def _authorization_context(payment, provenance_request):
    if not isinstance(payment, dict):
        raise ValueError("Payment must be a dictionary")

    if not isinstance(provenance_request, dict):
        raise ValueError("Provenance request must be a dictionary")

    try:
        commitment = sha256_json(payment)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("Payment cannot be deterministically hashed") from exc

    if provenance_request.get("payment_commitment") != commitment:
        raise ValueError("Payment commitment mismatch")

    provenance = validate_request(provenance_request)

    if not isinstance(provenance, dict) or provenance.get("allowed") is not True:
        raise ValueError("T1-T5 provenance validation failed")

    witnesses = provenance_request.get("witnesses")

    if not isinstance(witnesses, list) or len(witnesses) != 5:
        raise ValueError("Exactly five valid witnesses are required")

    request_id = witnesses[0].get("request_id")

    if not _valid_identifier(request_id):
        raise ValueError("Invalid provenance request ID")

    try:
        provenance_commitment = sha256_json(provenance_request)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("Provenance cannot be deterministically hashed") from exc
    return commitment, provenance_commitment, request_id


def create_authorization_envelope(
    payment,
    provenance_request,
    signer_id,
    key_id,
    private_key_path,
    authorization_version="1",
):
    """Create a signed envelope for an already validated payment request."""

    if not _valid_identifier(signer_id):
        raise ValueError("Invalid signer ID")

    if not _valid_identifier(key_id):
        raise ValueError("Invalid key ID")

    if not _valid_identifier(authorization_version):
        raise ValueError("Invalid authorization version")

    commitment, provenance_commitment, request_id = _authorization_context(
        payment,
        provenance_request,
    )

    payload = {
        "schema": SCHEMA,
        "algorithm": ALGORITHM,
        "authorization_version": authorization_version,
        "signer_id": signer_id,
        "key_id": key_id,
        "request_id": request_id,
        "payment_commitment": commitment,
        "provenance_commitment": provenance_commitment,
    }

    signature = sign_message(
        _canonical_bytes(payload),
        private_key_path,
    )

    return {
        **payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_authorization_envelope(envelope, payment, provenance_request):
    """Verify authorization using the application-controlled local registry.

    Callers cannot supply or override trusted public keys.
    Registry failures reject authorization.
    """
    try:
        if not isinstance(envelope, dict):
            return False

        if set(envelope) != ENVELOPE_FIELDS:
            return False

        if envelope.get("schema") != SCHEMA:
            return False

        if envelope.get("algorithm") != ALGORITHM:
            return False

        for field in (
            "authorization_version",
            "signer_id",
            "key_id",
            "request_id",
            "payment_commitment",
            "provenance_commitment",
        ):
            if not _valid_identifier(envelope.get(field)):
                return False

        commitment, provenance_commitment, request_id = (
            _authorization_context(payment, provenance_request)
        )

        if envelope["payment_commitment"] != commitment:
            return False

        if envelope["provenance_commitment"] != provenance_commitment:
            return False

        if envelope["request_id"] != request_id:
            return False

        trusted_keys = load_trusted_keys()
        trusted_entry = trusted_keys.get(envelope["key_id"])

        if not isinstance(trusted_entry, dict):
            return False

        if trusted_entry.get("status") != "ACTIVE":
            return False

        if trusted_entry.get("signer_id") != envelope["signer_id"]:
            return False

        public_key_path = trusted_entry.get("public_key_path")

        if not isinstance(public_key_path, str) or not public_key_path.strip():
            return False

        encoded_signature = envelope.get("signature")

        if not isinstance(encoded_signature, str):
            return False

        signature = base64.b64decode(encoded_signature, validate=True)

        if len(signature) != 64:
            return False

        payload = {
            field: envelope[field]
            for field in PAYLOAD_FIELDS
        }

        return verify_message(
            _canonical_bytes(payload),
            signature,
            public_key_path,
        ) is True

    except Exception:
        return False
