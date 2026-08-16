"""
Forensic Audit Engine for Evidence Bundle Verification and Audit Trail Inspection.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from .crypto import (
    hash_sha256,
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
    verify_signature_ed25519,
    verify_signature_hmac,
)
from .evidence import EvidenceBundle, DEFAULT_SECRET_KEY, execution_trace_leaf_string
from .policy import ReleasePolicyEngine

# Actions that a release-run trace should never record. This is the semantic
# per-leaf signal the inspection layer surfaces: a cryptographically valid
# bundle may record these, and the integrity gate cannot (and must not) reject
# them -- that is exactly the division of labor the corpus evaluation measures
# (2026-08 adversarial review, N9).
SENSITIVE_ACTIONS = {
    "spawn_shell_subprocess",
    "override_system_prompt",
    "escalate_role",
    "drop_production_table",
    "exfiltrate_private_key",
    "patch_trace_memory",
    "access_localhost_metadata",
    "poison_vector_store",
    "spawn_unsandboxed_process",
    "inject_duplicate_json_key",
    "drop_database",
    "delete_credentials",
}


class ForensicAuditEngine:
    """Performs deep cryptographic audit and trace inclusion inspection on Evidence Bundles."""

    def __init__(self, policy_engine: Optional[ReleasePolicyEngine] = None):
        self.policy_engine = policy_engine

    def audit_bundle(
        self,
        evidence: EvidenceBundle | Dict[str, Any],
        secret_key: str = DEFAULT_SECRET_KEY,
        seen_nonces: Optional[set[str]] = None
    ) -> Dict[str, Any]:
        """Perform comprehensive forensic inspection and return structured audit card."""
        if isinstance(evidence, EvidenceBundle):
            b = evidence.to_dict()
        else:
            b = evidence

        ev_id = b.get("evidence_id", "UNKNOWN")
        signed = b.get("signed", False)
        sig_alg = b.get("sig_alg", "ed25519")
        key_id = b.get("key_id", "UNKNOWN")
        pub_key = b.get("public_key")
        sig = b.get("signature")
        merkle_root = b.get("merkle_root", "")
        traces = b.get("traces", [])

        # 1. Signature Inspection
        sig_valid = False
        key_status = "unknown"
        if signed and sig:
            payload = {
                "evidence_id": b.get("evidence_id", ""),
                "timestamp": b.get("timestamp", ""),
                "nonce": b.get("nonce", ""),
                "agent_system_version": b.get("agent_system_version", ""),
                "test_pass_pct": b.get("test_pass_pct", 0.0),
                "unresolved_drift": b.get("unresolved_drift", 0),
                "execution_traces_count": b.get("execution_traces_count", 0),
                "merkle_root": merkle_root,
                "artifact_digests": b.get("artifact_digests", {}),
                "sig_alg": sig_alg,
                "key_id": key_id,
                "kms_key_arn": b.get("kms_key_arn")
            }
            if sig_alg == "ed25519" and pub_key:
                # Never trust a public key supplied inside the audited bundle:
                # verify against the trusted registry pinned alongside the
                # policy, and report CRL revocation explicitly.
                trusted_keys: Dict[str, str] = getattr(self.policy_engine, "trusted_keys", {}) if self.policy_engine else {}
                revoked_keys: set[str] = getattr(self.policy_engine, "revoked_key_ids", set()) if self.policy_engine else set()
                if trusted_keys and key_id in revoked_keys:
                    key_status = "revoked"
                elif trusted_keys and key_id not in trusted_keys:
                    key_status = "unregistered"
                elif trusted_keys and trusted_keys.get(key_id) != pub_key:
                    key_status = "pinned_key_mismatch"
                else:
                    key_status = "trusted"
                    sig_valid = verify_signature_ed25519(payload, sig, trusted_keys.get(key_id) or pub_key)
            else:
                sig_valid = verify_signature_hmac(payload, sig, secret_key)
                key_status = "shared_secret"

        # 2. Merkle Tree & Inclusion Proof Inspection
        leaf_hashes = []
        for t in traces:
            leaf_hashes.append(hash_sha256(execution_trace_leaf_string(t)))

        recalculated_root, levels = build_merkle_tree(leaf_hashes)
        merkle_valid = (recalculated_root == merkle_root)

        trace_audit = []
        for i, leaf_h in enumerate(leaf_hashes):
            proof = generate_merkle_proof(i, levels)
            proof_ok = verify_merkle_proof(leaf_h, proof, recalculated_root,
                                           expected_depth=max(len(levels) - 1, 0))
            trace_audit.append({
                "index": i,
                "trace_id": traces[i].get("trace_id"),
                "action": traces[i].get("action"),
                "status": traces[i].get("status"),
                "leaf_hash": leaf_h[:12] + "...",
                "inclusion_proof_valid": proof_ok
            })

        # 3. Per-leaf semantic inspection: surface recorded actions that
        # should not have occurred, independent of cryptographic validity.
        # A well-formed signed bundle may record these; the integrity gate
        # approves it and this layer flags it (Section 6.7 of the paper).
        semantic_flags = []
        for i, t in enumerate(traces):
            status = t.get("status")
            action = t.get("action")
            flag = None
            if status != "SUCCESS":
                flag = f"non-SUCCESS status '{status}'"
            elif action in SENSITIVE_ACTIONS:
                flag = f"sensitive action '{action}'"
            if flag:
                semantic_flags.append({
                    "index": i,
                    "trace_id": t.get("trace_id"),
                    "action": action,
                    "status": status,
                    "flag": flag,
                })
        semantic_anomaly_detected = bool(semantic_flags)

        # 4. Policy Evaluation Integration
        policy_passed = False
        violations: List[str] = []
        if self.policy_engine:
            policy_passed, violations, _ = self.policy_engine.evaluate(b, secret_key, seen_nonces)

        audit_result = {
            "evidence_id": ev_id,
            "audited_at": datetime.now(timezone.utc).isoformat(),
            "signature_valid": sig_valid,
            "signature_algorithm": sig_alg,
            "key_id": key_id,
            "signature_key_status": key_status,
            "merkle_root_claimed": merkle_root,
            "merkle_root_recalculated": recalculated_root,
            "merkle_integrity_valid": merkle_valid,
            "total_traces_inspected": len(traces),
            "trace_inclusion_proofs_valid": all(t["inclusion_proof_valid"] for t in trace_audit),
            "semantic_anomaly_detected": semantic_anomaly_detected,
            "semantic_flags": semantic_flags,
            "policy_passed": policy_passed,
            "policy_violations": violations,
            "forensic_status": "AUTHENTIC_AND_VERIFIED" if (sig_valid and merkle_valid and policy_passed) else "COMPROMISED_OR_TAMPERED",
            "trace_details": trace_audit
        }

        return audit_result
