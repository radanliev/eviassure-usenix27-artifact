"""
Unit tests for fail-closed release policy evaluation.
"""

from pathlib import Path
from assurance.policy import ReleasePolicyEngine
from assurance.evidence import create_evidence_pack, DEFAULT_SECRET_KEY
from assurance.verifier import evaluate_release_gate


def test_clean_evidence_approval():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    clean_bundle = create_evidence_pack(signed=True)
    passed, violations, details = policy_engine.evaluate(clean_bundle)

    assert passed is True
    assert len(violations) == 0
    assert details["passed"] is True


def test_unsigned_evidence_rejection():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    unsigned_bundle = create_evidence_pack(signed=False)
    passed, violations, details = policy_engine.evaluate(unsigned_bundle)

    assert passed is False
    assert any("Unsigned evidence" in v for v in violations)


def test_verifier_output_file(tmp_path):
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    decision_file = tmp_path / "release_decision.json"

    res = evaluate_release_gate(
        policy_path=policy_path,
        output_decision_file=decision_file
    )

    assert res["passed"] is True
    assert res["status"] == "APPROVED"
    assert decision_file.exists()


def test_naive_timestamp_handling():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    bundle = create_evidence_pack(signed=True)
    b_dict = bundle.to_dict()
    b_dict["timestamp"] = "2026-08-11T22:00:00"  # Naive ISO timestamp string without timezone offset
    
    passed, violations, details = policy_engine.evaluate(b_dict)
    # Ensure it evaluates cleanly without TypeError exception
    assert isinstance(passed, bool)


def test_threshold_signature_policy():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    
    # Load and adjust policy data to require 2 signatures
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)
    policy_engine.release_conditions["min_required_signatures"] = 2
    
    # 1. Create a bundle signed with only 1 signature
    bundle = create_evidence_pack(signed=True, use_ed25519=True)
    passed, violations, details = policy_engine.evaluate(bundle)
    assert passed is False  # Rejected because min_required_signatures is 2 but only 1 exists
    assert any("Insufficient valid signatures" in v for v in violations)

    # 2. The SAME key signing a second time must NOT satisfy the threshold:
    # K-of-M counts DISTINCT authorized signers (N10). A single compromised
    # key re-signing a bundle is one signer, not two.
    bundle.sign_ed25519_multi()  # second signature, same demo key
    passed, violations, details = policy_engine.evaluate(bundle)
    assert passed is False
    assert any("Insufficient valid signatures" in v for v in violations)

    # 3. A second, DISTINCT key pinned in the trusted registry satisfies the
    # threshold.
    from assurance.crypto import generate_ed25519_keypair
    second_priv, _, second_pub_b64, second_key_id = generate_ed25519_keypair()
    policy_engine.trusted_keys[second_key_id] = second_pub_b64
    bundle.sign_ed25519_multi(private_key=second_priv, pub_key_b64=second_pub_b64)
    passed, violations, details = policy_engine.evaluate(bundle)
    assert passed is True
    assert len(violations) == 0


def test_seen_nonces_eviction():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)
    policy_engine.release_conditions["max_evidence_age_seconds"] = 10
    
    from datetime import datetime, timezone, timedelta
    expired_dt = datetime.now(timezone.utc) - timedelta(seconds=12)
    bundle = create_evidence_pack(signed=True, use_ed25519=True)
    bundle.timestamp = expired_dt.isoformat()
    bundle.sign_ed25519()
    
    seen_nonces = {bundle.nonce}
    
    passed, violations, details = policy_engine.evaluate(bundle, seen_nonces=seen_nonces)
    
    # The stale pre-seeded nonce is evicted before the replay check, so the
    # evaluation proceeds and the engine records the nonce freshly (N3):
    # an engine that processes a nonce must commit it to the seen-set.
    assert bundle.nonce in seen_nonces


