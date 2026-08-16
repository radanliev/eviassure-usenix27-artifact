"""
Regression tests for findings from the 2026-08 adversarial review (N1-N15).

Each test locks in a corrected behavior that previously admitted a concrete
attack:
- N1: HMAC signatures are not forgeable against the shipped policy (no
  operator secret is configured, so HMAC is rejected; the source-code
  constant is not a secret).
- N3: the engine records processed nonces, so an honest caller sharing one
  seen-set across evaluations gets real replay detection.
- N5: duplicate JSON keys in a wire document are rejected at ingestion.
- N10: a signature threshold counts DISTINCT signers, not signature copies.
"""

from pathlib import Path
import json

from assurance.evidence import create_evidence_pack, EvidenceBundle, DEFAULT_SECRET_KEY
from assurance.crypto import sign_payload_hmac
from assurance.policy import ReleasePolicyEngine

_POLICY = Path(__file__).parent.parent / "governance" / "release_policy.yaml"


def _engine(**overrides) -> ReleasePolicyEngine:
    engine = ReleasePolicyEngine.from_yaml(_POLICY)
    for k, v in overrides.items():
        engine.release_conditions[k] = v
    return engine


def test_n1_forged_hmac_signature_blocked():
    """N1: an HMAC signature computed over the public source constant must be
    rejected by the shipped policy, which has no operator-configured secret."""
    engine = _engine()
    bundle = create_evidence_pack(use_ed25519=False, signed=False)
    b_dict = bundle.to_dict()
    b_dict["signed"] = True
    b_dict["sig_alg"] = "hmac-sha256"
    b_dict["key_id"] = "KEY-HMAC-OPERATOR-1"
    payload = {
        "evidence_id": b_dict["evidence_id"],
        "timestamp": b_dict["timestamp"],
        "nonce": b_dict["nonce"],
        "agent_system_version": b_dict["agent_system_version"],
        "test_pass_pct": b_dict["test_pass_pct"],
        "unresolved_drift": b_dict["unresolved_drift"],
        "execution_traces_count": b_dict["execution_traces_count"],
        "merkle_root": b_dict["merkle_root"],
        "artifact_digests": b_dict["artifact_digests"],
        "sig_alg": "hmac-sha256",
        "key_id": "KEY-HMAC-OPERATOR-1",
        "kms_key_arn": b_dict.get("kms_key_arn"),
    }
    b_dict["signature"] = sign_payload_hmac(payload, DEFAULT_SECRET_KEY)

    passed, violations, _ = engine.evaluate(b_dict)

    assert passed is False
    assert any("hmac" in v.lower() for v in violations), violations


def test_n1_hmac_allowed_only_with_policy_secret():
    """N1: if a deployment explicitly re-enables HMAC with an operator-held
    secret, HMAC signatures over THAT secret verify; over the public constant
    they do not."""
    engine = _engine(allowed_sig_algs=["ed25519", "hmac-sha256"],
                     hmac_secret_key="operator-hold-secret-2x")
    bundle = create_evidence_pack(use_ed25519=False, signed=False)
    b_dict = bundle.to_dict()
    b_dict["signed"] = True
    b_dict["sig_alg"] = "hmac-sha256"
    b_dict["key_id"] = "KEY-HMAC-OPERATOR-1"
    payload = {
        "evidence_id": b_dict["evidence_id"],
        "timestamp": b_dict["timestamp"],
        "nonce": b_dict["nonce"],
        "agent_system_version": b_dict["agent_system_version"],
        "test_pass_pct": b_dict["test_pass_pct"],
        "unresolved_drift": b_dict["unresolved_drift"],
        "execution_traces_count": b_dict["execution_traces_count"],
        "merkle_root": b_dict["merkle_root"],
        "artifact_digests": b_dict["artifact_digests"],
        "sig_alg": "hmac-sha256",
        "key_id": "KEY-HMAC-OPERATOR-1",
        "kms_key_arn": b_dict.get("kms_key_arn"),
    }
    b_dict["signature"] = sign_payload_hmac(payload, "operator-hold-secret-2x")
    passed, violations, _ = engine.evaluate(b_dict)
    assert passed is True, violations


def test_n3_engine_records_processed_nonce():
    """N3: evaluating the same bundle twice against one shared seen-set must
    block the second evaluation as a replay -- the engine commits nonces it
    processes rather than leaving replay bookkeeping to the caller."""
    engine = _engine()
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    b_dict = bundle.to_dict()

    seen_nonces = set()
    first_passed, first_violations, _ = engine.evaluate(b_dict, seen_nonces=seen_nonces)
    second_passed, second_violations, _ = engine.evaluate(b_dict, seen_nonces=seen_nonces)

    assert first_passed is True
    assert bundle.nonce in seen_nonces
    assert second_passed is False
    assert any("Replayed evidence nonce" in v for v in second_violations)


def test_n5_duplicate_json_key_blocked_at_ingestion():
    """N5: a wire document repeating a key (parser-dependent value) is rejected
    before policy logic runs, even when the parsed value is otherwise clean."""
    engine = _engine()
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    b_dict = bundle.to_dict()

    from assurance.crypto import canonical_json
    wire = canonical_json(b_dict)
    wire_dup = wire[:-1] + ',"test_pass_pct":85.5}'
    parsed = json.loads(wire_dup)
    assert parsed["test_pass_pct"] == 85.5  # last-wins parse differs from signed value
    parsed["raw_wire_json"] = wire_dup

    passed, violations, _ = engine.evaluate(parsed)
    assert passed is False
    assert any("SERIALIZATION_VIOLATION" in v for v in violations)


def test_n10_threshold_counts_distinct_signers():
    """N10: min_required_signatures=3 must not be satisfied by one key signing
    three times."""
    engine = _engine(min_required_signatures=3)
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    bundle.sign_ed25519_multi()
    bundle.sign_ed25519_multi()

    passed, violations, _ = engine.evaluate(bundle)
    assert passed is False
    assert any("Insufficient valid signatures" in v for v in violations)

    from assurance.crypto import generate_ed25519_keypair
    second_priv, _, second_pub_b64, second_key_id = generate_ed25519_keypair()
    third_priv, _, third_pub_b64, third_key_id = generate_ed25519_keypair()
    engine.trusted_keys[second_key_id] = second_pub_b64
    engine.trusted_keys[third_key_id] = third_pub_b64
    bundle.sign_ed25519_multi(private_key=second_priv, pub_key_b64=second_pub_b64)
    bundle.sign_ed25519_multi(private_key=third_priv, pub_key_b64=third_pub_b64)

    passed, violations, _ = engine.evaluate(bundle)
    assert passed is True, violations


def test_raw_payload_never_serializes():
    """The Sec 3.2 claim 'raw_payload is excluded from serialization' must be
    enforced by construction, not by accident of no caller setting it."""
    import json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from assurance.evidence import ExecutionTraceRecord, create_evidence_pack
    from assurance.crypto import hash_sha256

    t = ExecutionTraceRecord(trace_id="X", agent_id="a", action="x",
                             status="SUCCESS", duration_ms=1.0,
                             output_hash=hash_sha256("o"),
                             raw_payload="SECRET-PII-STRING")
    bundle = create_evidence_pack(traces=[t], use_ed25519=True, signed=True)
    blob = json.dumps(bundle.to_dict())
    assert "SECRET-PII-STRING" not in blob, "raw_payload leaked into serialized bundle"
    assert "raw_payload" not in bundle.to_dict()["traces"][0], "raw_payload key serialized"
