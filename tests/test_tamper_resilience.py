"""
Security tests verifying 100% fail-closed block rate across all 12 adversarial release tamper vectors.
"""

from pathlib import Path
from assurance.policy import ReleasePolicyEngine
from benchmark.tamper_vectors import generate_tampered_evidence_suite, TAMPER_VECTOR_TAXONOMY


def test_tamper_resilience_suite_12_vectors():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    tamper_suite = generate_tampered_evidence_suite()
    assert len(tamper_suite) == 12, "Tamper suite must contain exactly 12 vectors!"

    seen_nonces = set()

    for vector_id, meta, tampered_evidence in tamper_suite:
        test_seen_nonces = seen_nonces.copy()
        if vector_id == "V4_REPLAYED_NONCE":
            test_seen_nonces.add(tampered_evidence["nonce"])

        passed, violations, details = policy_engine.evaluate(
            evidence=tampered_evidence,
            seen_nonces=test_seen_nonces
        )

        assert passed is False, f"TAMPER DEFECT: Vector {vector_id} ({meta['name']}) unexpectedly passed policy gate!"
        assert len(violations) > 0, f"Vector {vector_id} failed without violation messages!"
        assert details["fail_closed_enforced"] is True
