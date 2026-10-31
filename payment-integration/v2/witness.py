"""T5 witness-chain creation and fail-closed verification."""

from .hashing import sha256_bytes, sha256_json, is_sha256_hex

GENESIS_HASH = "0" * 64

REQUIRED_FIELDS = {
    "request_id",
    "witness_id",
    "stage",
    "parent_witness_id",
    "input_hash",
    "output_hash",
    "transformation",
    "evidence",
    "provenance",
    "validation_status",
    "timestamp",
}


def _witness_body(witness):
    """Return the signed/hashed witness fields, excluding witness_hash."""
    return {key: value for key, value in witness.items()
            if key != "witness_hash"}


def create_witness(
    request_id,
    witness_id,
    stage,
    parent_witness_id,
    input_hash,
    output_hash,
    transformation,
    evidence,
    provenance,
    validation_status,
    timestamp,
    previous_hash=GENESIS_HASH,
):
    """Create a witness linked cryptographically to the previous witness."""
    if not isinstance(previous_hash, str) or not is_sha256_hex(previous_hash):
        raise ValueError("previous_hash must be a valid SHA-256 digest")

    witness = {
        "request_id": request_id,
        "witness_id": witness_id,
        "stage": stage,
        "parent_witness_id": parent_witness_id,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "transformation": transformation,
        "evidence": evidence,
        "provenance": provenance,
        "validation_status": validation_status,
        "timestamp": timestamp,
    }

    witness["witness_hash"] = sha256_bytes(
        previous_hash.encode("ascii")
        + sha256_json(witness).encode("ascii")
    )
    return witness


def validate_t5(witnesses):
    """Validate exactly five ordered, hash-linked T1-T5 witnesses."""
    expected_stages = ("T1", "T2", "T3", "T4", "T5")

    if not isinstance(witnesses, list):
        return False
    if len(witnesses) != len(expected_stages):
        return False

    previous_hash = GENESIS_HASH
    previous_id = None
    request_id = None
    seen_ids = set()

    for index, witness in enumerate(witnesses):
        if not isinstance(witness, dict):
            return False
        if not REQUIRED_FIELDS.issubset(witness):
            return False

        if witness.get("stage") != expected_stages[index]:
            return False

        for field in (
            "request_id", "witness_id", "stage",
            "transformation", "timestamp",
        ):
            value = witness.get(field)
            if not isinstance(value, str) or not value.strip():
                return False

        if index == 0:
            request_id = witness["request_id"]
            if witness.get("parent_witness_id") is not None:
                return False
        else:
            if witness["request_id"] != request_id:
                return False
            if witness.get("parent_witness_id") != previous_id:
                return False

        witness_id = witness["witness_id"]
        if witness_id in seen_ids:
            return False
        seen_ids.add(witness_id)

        if not is_sha256_hex(witness.get("input_hash")):
            return False
        if not is_sha256_hex(witness.get("output_hash")):
            return False
        if not isinstance(witness.get("evidence"), dict):
            return False
        if not witness["evidence"]:
            return False
        if not isinstance(witness.get("provenance"), dict):
            return False
        if not witness["provenance"]:
            return False
        if witness.get("validation_status") != "PASS":
            return False
        if not is_sha256_hex(witness.get("witness_hash")):
            return False

        try:
            expected_hash = sha256_bytes(
                previous_hash.encode("ascii")
                + sha256_json(_witness_body(witness)).encode("ascii")
            )
        except (TypeError, ValueError, UnicodeError):
            return False

        if witness["witness_hash"] != expected_hash:
            return False

        previous_hash = witness["witness_hash"]
        previous_id = witness_id

    return True
