"""Fail-closed orchestration for JLM AI AGENT T1-T5."""

from .gates import validate_t1, validate_t2, validate_t3, validate_t4
from .witness import validate_t5


REQUIRED_INPUTS = {
    "risk",
    "threshold",
    "required_capabilities",
    "granted_capabilities",
    "expected_hash",
    "actual_hash",
    "original",
    "disclosed",
    "allowed_keys",
    "witnesses",
}


def validate_request(request):
    """Require passing gates and evidence bound to the request."""
    gate_results = {
        "T1": False,
        "T2": False,
        "T3": False,
        "T4": False,
        "T5": False,
    }

    try:
        if not isinstance(request, dict):
            return {
                "status": "FAIL",
                "allowed": False,
                "gate_results": gate_results,
                "reason": "Request must be a dictionary",
            }

        missing = REQUIRED_INPUTS - set(request)
        if missing:
            return {
                "status": "FAIL",
                "allowed": False,
                "gate_results": gate_results,
                "reason": "Missing required inputs: "
                + ", ".join(sorted(missing)),
            }

        payment_commitment = request.get("payment_commitment")
        if payment_commitment is not None:
            if (
                not isinstance(payment_commitment, str)
                or request["expected_hash"] != payment_commitment
                or request["actual_hash"] != payment_commitment
            ):
                return {
                    "status": "FAIL",
                    "allowed": False,
                    "gate_results": gate_results,
                    "reason": "Payment commitment does not match T3 hashes",
                }

        validators = {
            "T1": lambda: validate_t1(
                request["risk"], request["threshold"]
            ),
            "T2": lambda: validate_t2(
                request["required_capabilities"],
                request["granted_capabilities"],
            ),
            "T3": lambda: validate_t3(
                request["expected_hash"], request["actual_hash"]
            ),
            "T4": lambda: validate_t4(
                request["original"],
                request["disclosed"],
                request["allowed_keys"],
            ),
        }

        for gate, validator in validators.items():
            try:
                gate_results[gate] = validator() is True
            except Exception:
                gate_results[gate] = False

        witnesses = request["witnesses"]
        gate_results["T5"] = validate_t5(witnesses) is True

        # Expected evidence is derived from the actual request and
        # computed gate outcomes, not trusted from the witnesses.
        expected_evidence = {
            "T1": {
                "gate": "T1",
                "risk": request["risk"],
                "threshold": request["threshold"],
                "result": "PASS" if gate_results["T1"] else "FAIL",
            },
            "T2": {
                "gate": "T2",
                "required_capabilities": request["required_capabilities"],
                "granted_capabilities": request["granted_capabilities"],
                "result": "PASS" if gate_results["T2"] else "FAIL",
            },
            "T3": {
                "gate": "T3",
                "expected_hash": request["expected_hash"],
                "actual_hash": request["actual_hash"],
                **({"payment_commitment": payment_commitment}
                   if payment_commitment is not None else {}),
                "result": "PASS" if gate_results["T3"] else "FAIL",
            },
            "T4": {
                "gate": "T4",
                "original": request["original"],
                "disclosed": request["disclosed"],
                "allowed_keys": request["allowed_keys"],
                "result": "PASS" if gate_results["T4"] else "FAIL",
            },
            "T5": {
                "gate": "T5",
                "result": "PASS",
                "chain_length": 5,
            },
        }

        expected_stages = ("T1", "T2", "T3", "T4", "T5")

        if not isinstance(witnesses, list) or len(witnesses) != 5:
            gate_results["T5"] = False
        else:
            for witness, stage in zip(witnesses, expected_stages):
                if not isinstance(witness, dict):
                    gate_results["T5"] = False
                    break
                if witness.get("stage") != stage:
                    gate_results["T5"] = False
                    break
                if witness.get("request_id") != witnesses[0].get("request_id"):
                    gate_results["T5"] = False
                    break
                if witness.get("evidence") != expected_evidence[stage]:
                    gate_results["T5"] = False
                    break

        passed = all(gate_results.values())

        return {
            "status": "PASS" if passed else "FAIL",
            "allowed": passed,
            "gate_results": gate_results,
            "reason": (
                "All required gates and evidence checks passed"
                if passed
                else "A gate or witness evidence check failed"
            ),
        }

    except Exception:
        return {
            "status": "FAIL",
            "allowed": False,
            "gate_results": gate_results,
            "reason": "Unexpected validation error",
        }
