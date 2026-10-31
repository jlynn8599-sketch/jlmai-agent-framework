from v2.hashing import sha256_bytes, sha256_json
from v2.gates import validate_t1, validate_t2, validate_t3, validate_t4
from v2.witness import (
    GENESIS_HASH,
    create_witness,
    validate_t5,
)
from v2.provenance import validate_request


def make_witness_chain(request):
    digest_in = sha256_bytes(b"input")
    digest_out = sha256_bytes(b"output")

    gate_evidence = {
        "T1": {
            "gate": "T1",
            "risk": request["risk"],
            "threshold": request["threshold"],
            "result": (
                "PASS"
                if validate_t1(request["risk"], request["threshold"])
                else "FAIL"
            ),
        },
        "T2": {
            "gate": "T2",
            "required_capabilities": request["required_capabilities"],
            "granted_capabilities": request["granted_capabilities"],
            "result": (
                "PASS"
                if validate_t2(
                    request["required_capabilities"],
                    request["granted_capabilities"],
                )
                else "FAIL"
            ),
        },
        "T3": {
            "gate": "T3",
            "expected_hash": request["expected_hash"],
            "actual_hash": request["actual_hash"],
            **(
                {"payment_commitment": request["payment_commitment"]}
                if "payment_commitment" in request else {}
            ),
            "result": (
                "PASS"
                if validate_t3(
                    request["expected_hash"], request["actual_hash"]
                )
                else "FAIL"
            ),
        },
        "T4": {
            "gate": "T4",
            "original": request["original"],
            "disclosed": request["disclosed"],
            "allowed_keys": request["allowed_keys"],
            "result": (
                "PASS"
                if validate_t4(
                    request["original"],
                    request["disclosed"],
                    request["allowed_keys"],
                )
                else "FAIL"
            ),
        },
        "T5": {
            "gate": "T5",
            "result": "PASS",
            "chain_length": 5,
        },
    }

    witnesses = []
    previous_hash = GENESIS_HASH
    previous_id = None

    for index, stage in enumerate(("T1", "T2", "T3", "T4", "T5"), 1):
        witness = create_witness(
            request_id="pytest-request",
            witness_id=f"w{index}",
            stage=stage,
            parent_witness_id=previous_id,
            input_hash=digest_in,
            output_hash=digest_out,
            transformation=f"test_{stage.lower()}",
            evidence=gate_evidence[stage],
            provenance={"source": "local-test"},
            validation_status="PASS",
            timestamp=f"2026-10-26T12:00:0{index}Z",
            previous_hash=previous_hash,
        )
        witnesses.append(witness)
        previous_hash = witness["witness_hash"]
        previous_id = witness["witness_id"]

    return witnesses


def make_request():
    digest = sha256_bytes(b"output")
    request = {
        "risk": 1,
        "threshold": 2,
        "required_capabilities": ["read"],
        "granted_capabilities": ["read", "write"],
        "expected_hash": digest,
        "actual_hash": digest,
        "original": {"name": "JLM", "role": "agent"},
        "disclosed": {"name": "JLM"},
        "allowed_keys": ["name"],
    }
    request["witnesses"] = make_witness_chain(request)
    return request


def test_hashing_is_deterministic():
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
    assert sha256_json({"a": 1, "b": 2}) == sha256_json(
        {"b": 2, "a": 1}
    )


def test_t1_requires_risk_below_threshold():
    assert validate_t1(1, 2) is True
    assert validate_t1(2, 2) is False
    assert validate_t1(float("nan"), 2) is False


def test_t2_requires_authorized_capabilities():
    assert validate_t2(["read"], ["read", "write"]) is True
    assert validate_t2(["admin"], ["read"]) is False


def test_t3_requires_matching_hashes():
    digest = sha256_bytes(b"payload")
    assert validate_t3(digest, digest) is True
    assert validate_t3(digest, sha256_bytes(b"different")) is False


def test_t4_limits_disclosure():
    original = {"name": "JLM", "role": "agent"}
    assert validate_t4(original, {"name": "JLM"}, ["name"]) is True
    assert validate_t4(original, {"role": "agent"}, ["name"]) is False
    assert validate_t4(original, {"name": "changed"}, ["name"]) is False


def test_t5_accepts_complete_ordered_chain():
    assert validate_t5(make_witness_chain(make_request())) is True


def test_t5_rejects_empty_chain():
    assert validate_t5([]) is False


def test_t5_rejects_single_witness():
    assert validate_t5(make_witness_chain(make_request())[:1]) is False


def test_t5_rejects_wrong_stage_order():
    chain = make_witness_chain(make_request())
    chain[0], chain[1] = chain[1], chain[0]
    assert validate_t5(chain) is False


def test_t5_rejects_tampered_evidence():
    chain = make_witness_chain(make_request())
    chain[2]["evidence"]["result"] = "tampered"
    assert validate_t5(chain) is False


def test_valid_request_passes_all_gates():
    result = validate_request(make_request())
    assert result["status"] == "PASS", result
    assert result["allowed"] is True
    assert all(result["gate_results"].values())


def test_failed_t1_blocks_request():
    request = make_request()
    request["risk"] = request["threshold"]
    result = validate_request(request)
    assert result["status"] == "FAIL"
    assert result["allowed"] is False
    assert result["gate_results"]["T1"] is False


def test_missing_required_input_fails_closed():
    request = make_request()
    del request["witnesses"]
    result = validate_request(request)
    assert result["status"] == "FAIL"
    assert result["allowed"] is False


def test_non_dictionary_request_fails_closed():
    result = validate_request(None)
    assert result["status"] == "FAIL"
    assert result["allowed"] is False


def test_request_rejects_forged_evidence_even_when_chain_rehashed():
    request = make_request()
    chain = request["witnesses"]

    # Change evidence without changing the request's actual risk.
    chain[0]["evidence"]["risk"] = 999

    # Recalculate every chain hash so the chain remains internally valid.
    previous_hash = GENESIS_HASH
    for witness in chain:
        body = {
            key: value
            for key, value in witness.items()
            if key != "witness_hash"
        }
        witness["witness_hash"] = sha256_bytes(
            previous_hash.encode("ascii")
            + sha256_json(body).encode("ascii")
        )
        previous_hash = witness["witness_hash"]

    # The hash chain should pass, but the request evidence must fail.
    assert validate_t5(chain) is True
    result = validate_request(request)
    assert result["status"] == "FAIL"
    assert result["allowed"] is False


def test_request_rejects_non_dictionary_witness():
    request = make_request()
    request["witnesses"][2] = None

    result = validate_request(request)

    assert result["status"] == "FAIL"
    assert result["allowed"] is False


def test_request_rejects_missing_witnesses():
    request = make_request()
    del request["witnesses"]

    result = validate_request(request)

    assert result["status"] == "FAIL"
    assert result["allowed"] is False


def test_request_rejects_invalid_witness_chain_type():
    request = make_request()
    request["witnesses"] = "not-a-witness-chain"

    result = validate_request(request)

    assert result["status"] == "FAIL"
    assert result["allowed"] is False
