"""
Security tests for the trusted signing-key registry and fail-closed parsing.

The verifier must NEVER trust a public key embedded in a submitted evidence
bundle: signatures from unregistered keys, or under a spoofed trusted key_id,
are blocked. Malformed evidence crashes are converted to BLOCKED verdicts.
"""

import json
from pathlib import Path

from assurance.evidence import create_evidence_pack, EvidenceBundle, DEMO_PRIV_KEY, DEMO_PUB_KEY_B64
from assurance.crypto import generate_ed25519_keypair, sign_payload_ed25519, compute_key_id
from assurance.policy import ReleasePolicyEngine


POLICY = Path(__file__).parent.parent / "governance" / "release_policy.yaml"


def _attacker_signed_bundle(key_id="KEY-ATTACKER-UNTRUSTED"):
    """Well-formed clean bundle signed by a fresh attacker keypair."""
    att_priv, _, att_pub_b64, _ = generate_ed25519_keypair()
    d = create_evidence_pack(use_ed25519=False, signed=False).to_dict()
    d.update({"signed": True, "sig_alg": "ed25519", "key_id": key_id,
              "public_key": att_pub_b64})
    payload = {
        "evidence_id": d["evidence_id"], "timestamp": d["timestamp"],
        "nonce": d["nonce"], "agent_system_version": d["agent_system_version"],
        "test_pass_pct": d["test_pass_pct"], "unresolved_drift": d["unresolved_drift"],
        "execution_traces_count": d["execution_traces_count"],
        "merkle_root": d["merkle_root"], "artifact_digests": d["artifact_digests"],
        "sig_alg": "ed25519", "key_id": key_id, "kms_key_arn": d.get("kms_key_arn"),
    }
    d["signature"] = sign_payload_ed25519(payload, att_priv)
    return d


def test_registry_loads_demo_key():
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    assert compute_key_id(DEMO_PUB_KEY_B64) in engine.trusted_keys


def test_attacker_ed25519_key_rejected():
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    passed, violations, _ = engine.evaluate(_attacker_signed_bundle())
    assert not passed, "Bundle signed by an unregistered attacker key was APPROVED"
    assert any("not in trusted key registry" in v for v in violations)


def test_spoofed_trusted_key_id_rejected():
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    d = _attacker_signed_bundle(key_id=compute_key_id(DEMO_PUB_KEY_B64))
    passed, violations, _ = engine.evaluate(d)
    assert not passed, "Attacker key spoofing a trusted key_id was APPROVED"
    assert any("does not match the trusted key registry" in v for v in violations)


def test_demo_signed_bundle_still_passes():
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    passed, violations, _ = engine.evaluate(bundle.to_dict())
    assert passed, f"Registry broke legitimate demo-signed bundles: {violations}"


def test_engine_without_registry_rejects_ed25519():
    engine = ReleasePolicyEngine({"release_conditions": {"require_signed_evidence": True}})
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    passed, violations, _ = engine.evaluate(bundle.to_dict())
    assert not passed, "Ed25519 signatures verified with no trusted registry configured"


def test_malformed_evidence_fails_closed():
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    d = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    d["test_pass_pct"] = "not-a-number"   # raises TypeError mid-evaluation
    passed, violations, _ = engine.evaluate(d)
    assert not passed, "Crashing evidence must fail closed, not approve"
    assert any("fail-closed" in v or "Malformed" in v for v in violations)


def test_forensic_audit_uses_registry_not_bundle_keys():
    from assurance.forensics import ForensicAuditEngine
    from benchmark.tamper_vectors import generate_tampered_evidence_suite
    engine = ForensicAuditEngine(policy_engine=ReleasePolicyEngine.from_yaml(POLICY))
    suite = {vid: ev for vid, _, ev in generate_tampered_evidence_suite()}
    res = engine.audit_bundle(suite["V3_FORGED_SIGNATURE"])
    assert res["signature_key_status"] == "unregistered"
    assert not res["signature_valid"]
    assert res["forensic_status"] == "COMPROMISED_OR_TAMPERED"

    clean = engine.audit_bundle(create_evidence_pack(use_ed25519=True, signed=True))
    assert clean["signature_key_status"] == "trusted" and clean["signature_valid"]
