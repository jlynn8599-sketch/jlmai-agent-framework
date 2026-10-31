"""Fail-closed validation gates for JLM AI AGENT."""

from .hashing import is_sha256_hex, sha256_json


def validate_t1(risk, threshold):
    """T1: Pass only when risk is strictly below threshold."""
    if (
        isinstance(risk, bool)
        or isinstance(threshold, bool)
        or not isinstance(risk, (int, float))
        or not isinstance(threshold, (int, float))
    ):
        return False
    if risk != risk or threshold != threshold:
        return False
    if abs(risk) == float("inf") or abs(threshold) == float("inf"):
        return False
    return risk < threshold


def validate_t2(required, granted):
    """T2: Every required capability must be explicitly granted."""
    if not isinstance(required, (list, tuple, set, frozenset)):
        return False
    if not isinstance(granted, (list, tuple, set, frozenset)):
        return False
    if not all(isinstance(x, str) and x for x in required):
        return False
    if not all(isinstance(x, str) and x for x in granted):
        return False
    return set(required).issubset(set(granted))


def validate_t3(expected_hash, actual_hash):
    """T3: Compare valid SHA-256 digests."""
    if not is_sha256_hex(expected_hash) or not is_sha256_hex(actual_hash):
        return False
    return expected_hash.lower() == actual_hash.lower()


def validate_t4(original, disclosed, allowed_keys):
    """T4: Disclose only allowed original fields without changing values."""
    if not isinstance(original, dict) or not isinstance(disclosed, dict):
        return False
    if not isinstance(allowed_keys, (list, tuple, set, frozenset)):
        return False
    if not all(isinstance(key, str) for key in allowed_keys):
        return False
    if not set(disclosed).issubset(set(allowed_keys)):
        return False
    if not set(disclosed).issubset(set(original)):
        return False

    for key, value in disclosed.items():
        if sha256_json(value) != sha256_json(original[key]):
            return False
    return True
