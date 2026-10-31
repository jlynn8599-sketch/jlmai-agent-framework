"""Fail-closed local payment policy checks. No provider calls or transfers."""

import re

from .provenance import validate_request
from .hashing import sha256_json
from .payment_authorization import verify_authorization_envelope


def _fail(reason):
    return {
        "status": "FAIL",
        "allowed": False,
        "reason": reason,
    }


def evaluate_payment(
    payment,
    provenance_request,
    policy,
    seen_idempotency_keys=None,
    *,
    authorization_envelope=None,
):
    """Evaluate a proposed payment against trusted policy and T1-T5 evidence.

    This function does not execute a payment or reserve an idempotency key.
    Production callers must use durable, atomic idempotency reservation and
    provider-side idempotency before executing any transaction.
    """
    try:
        if not isinstance(payment, dict):
            return _fail("Payment must be a dictionary")

        if not isinstance(policy, dict):
            return _fail("Trusted policy must be a dictionary")

        required_policy = {
            "max_amount_minor",
            "allowed_currencies",
            "allowed_destinations",
            "required_capabilities",
            "granted_capabilities",
        }
        if not required_policy.issubset(policy):
            return _fail("Payment policy is incomplete")

        amount = payment.get("amount_minor")
        if (
            isinstance(amount, bool)
            or not isinstance(amount, int)
            or amount <= 0
        ):
            return _fail("Amount must be a positive integer in minor units")

        maximum = policy["max_amount_minor"]
        if (
            isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or maximum <= 0
        ):
            return _fail("Configured payment limit is invalid")

        if amount > maximum:
            return _fail("Payment exceeds the configured amount limit")

        currency = payment.get("currency")
        if not isinstance(currency, str) or not re.fullmatch(
            r"[A-Z]{3}", currency
        ):
            return _fail("Currency must be a three-letter uppercase code")

        currencies = policy["allowed_currencies"]
        if not isinstance(currencies, (list, tuple, set, frozenset)):
            return _fail("Configured currency allowlist is invalid")
        if not all(
            isinstance(item, str)
            and re.fullmatch(r"[A-Z]{3}", item)
            for item in currencies
        ):
            return _fail("Configured currency allowlist is invalid")
        if currency not in currencies:
            return _fail("Currency is not allowed")

        destination = payment.get("destination")
        if not isinstance(destination, str) or not destination.strip():
            return _fail("Payment destination is required")

        destinations = policy["allowed_destinations"]
        if not isinstance(destinations, (list, tuple, set, frozenset)):
            return _fail("Configured destination allowlist is invalid")
        if not all(
            isinstance(item, str) and item.strip()
            for item in destinations
        ):
            return _fail("Configured destination allowlist is invalid")
        if destination not in destinations:
            return _fail("Destination is not allowed")

        key = payment.get("idempotency_key")
        if (
            not isinstance(key, str)
            or not key.strip()
            or len(key) > 200
        ):
            return _fail("A valid idempotency key is required")

        if seen_idempotency_keys is not None:
            if not isinstance(
                seen_idempotency_keys, (list, tuple, set, frozenset)
            ):
                return _fail("Idempotency record is invalid")
            if not all(
                isinstance(item, str) for item in seen_idempotency_keys
            ):
                return _fail("Idempotency record is invalid")
            if key in seen_idempotency_keys:
                return _fail("Duplicate idempotency key")

        required = policy["required_capabilities"]
        granted = policy["granted_capabilities"]

        # Validate capability policy independently of payment input.
        from .gates import validate_t2

        if validate_t2(required, granted) is not True:
            return _fail("Required payment capabilities are not authorized")

        # Bind authorization to the exact payment payload.
        try:
            payment_commitment = sha256_json(payment)
        except (TypeError, ValueError, UnicodeError):
            return _fail("Payment payload cannot be deterministically hashed")

        if (
            not isinstance(provenance_request, dict)
            or provenance_request.get("payment_commitment")
            != payment_commitment
        ):
            return _fail("Payment does not match its authorization commitment")

        provenance = validate_request(provenance_request)
        if not isinstance(provenance, dict) or provenance.get(
            "allowed"
        ) is not True:
            return _fail("T1-T5 provenance validation failed")

        if not isinstance(authorization_envelope, dict):
            return _fail("Signed payment authorization is required")

        if verify_authorization_envelope(
            authorization_envelope,
            payment,
            provenance_request,
        ) is not True:
            return _fail("Ed25519 payment authorization verification failed")

        return {
            "status": "PASS",
            "allowed": True,
            "reason": "Payment policy, T1-T5 provenance, and signature passed",
            "amount_minor": amount,
            "currency": currency,
            "destination": destination,
            "idempotency_key": key,
            "provenance_status": provenance["status"],
            "executed": False,
        }

    except Exception:
        return _fail("Unexpected policy validation error")
