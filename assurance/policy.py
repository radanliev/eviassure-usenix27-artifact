"""
Release Policy Evaluation Engine for Fail-Closed Gate Enforcement.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List, Optional
import hmac
import re
import yaml
from pathlib import Path

from .evidence import EvidenceBundle, DEFAULT_SECRET_KEY, DEMO_PUB_KEY_B64, execution_trace_leaf_string
from .crypto import (detect_duplicate_json_keys, build_merkle_tree, hash_sha256,
                     verify_signature_hmac, verify_signature_ed25519)


_NONCE_TIMESTAMPS: Dict[str, datetime] = {}


class ReleasePolicyEngine:
    def __init__(self, policy_data: Dict[str, Any],
                 trusted_keys: Optional[Dict[str, Dict[str, str]]] = None):
        self.policy_data = policy_data
        self.policy_name = policy_data.get("policy_name", "Fail-Closed Security Gate Policy")
        self.version = policy_data.get("version", "1.0.0")
        self.release_conditions = policy_data.get("release_conditions", {})
        self.revoked_key_ids = set(policy_data.get("revoked_key_ids", []))
        # Trusted key registry: key_id -> pinned public key. Signatures from
        # unregistered keys are rejected, and verification always uses the
        # pinned key — never a public key supplied inside the evidence bundle.
        self.trusted_keys: Dict[str, str] = {}
        for kid, info in (trusted_keys or {}).items():
            if isinstance(info, dict) and info.get("public_key"):
                self.trusted_keys[kid] = info["public_key"]
            elif isinstance(info, str):
                self.trusted_keys[kid] = info

    @classmethod
    def from_yaml(cls, yaml_path: Path | str) -> "ReleasePolicyEngine":
        yaml_path = Path(yaml_path)
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        trusted = {}
        keys_path = yaml_path.parent / "trusted_keys.yaml"
        if keys_path.exists():
            with open(keys_path, 'r', encoding='utf-8') as f:
                trusted = (yaml.safe_load(f) or {}).get("trusted_keys", {})
        return cls(data, trusted_keys=trusted)

    def evaluate(
        self,
        evidence: EvidenceBundle | Dict[str, Any],
        secret_key: str = DEFAULT_SECRET_KEY,
        seen_nonces: Optional[set[str]] = None
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Evaluate evidence pack against policy rules.
        Returns: (passed: bool, violations: List[str], details: Dict[str, Any])

        Fail-closed: any exception while parsing evidence is itself a
        BLOCKED verdict, never a crash or an approval.
        """
        try:
            return self._evaluate(evidence, secret_key=secret_key,
                                  seen_nonces=seen_nonces)
        except Exception as exc:  # noqa: BLE001 — the gate must fail closed
            return False, [f"POLICY_VIOLATION: Malformed evidence rejected (fail-closed): {type(exc).__name__}"], {
                "passed": False, "violations_count": 1, "fail_closed_enforced": True,
                "parse_error": str(exc)[:200],
            }

    def _evaluate(
        self,
        evidence: EvidenceBundle | Dict[str, Any],
        secret_key: str = DEFAULT_SECRET_KEY,
        seen_nonces: Optional[set[str]] = None
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        violations = []
        details = {}

        if isinstance(evidence, dict):
            bundle_dict = evidence
            is_signed = bundle_dict.get("signed", False)
            sig = bundle_dict.get("signature")
            sig_alg = bundle_dict.get("sig_alg", "ed25519")
            key_id = bundle_dict.get("key_id")
            pub_key = bundle_dict.get("public_key")
            test_pass_pct = bundle_dict.get("test_pass_pct", 0.0)
            unresolved_drift = bundle_dict.get("unresolved_drift", 999)
            timestamp_str = bundle_dict.get("timestamp", "")
            nonce = bundle_dict.get("nonce", "")
            merkle_root = bundle_dict.get("merkle_root", "")
            traces = bundle_dict.get("traces", [])
            evidence_id = bundle_dict.get("evidence_id", "UNKNOWN")
            slsa_pred = bundle_dict.get("slsa_predicate")
        else:
            is_signed = evidence.signed
            sig = evidence.signature
            sig_alg = evidence.sig_alg
            key_id = evidence.key_id
            pub_key = evidence.public_key
            test_pass_pct = evidence.test_pass_pct
            unresolved_drift = evidence.unresolved_drift
            timestamp_str = evidence.timestamp
            nonce = evidence.nonce
            merkle_root = evidence.merkle_root
            traces = evidence.traces
            evidence_id = evidence.evidence_id
            slsa_pred = evidence.slsa_predicate
            bundle_dict = evidence.to_dict()

        rc = self.release_conditions

        # 0. Serialization ingestion check (N5): a wire document that contains
        # duplicate JSON keys is ambiguous -- `json.loads` keeps the last
        # occurrence while other parsers keep the first, so the same signed
        # bytes evaluate differently per reader. The ingestion boundary rejects
        # it before any policy or signature logic runs. If no raw wire text is
        # present (e.g., in-process API callers), this check is vacuous.
        if isinstance(evidence, dict) and isinstance(evidence.get("raw_wire_json"), str):
            dup_keys = detect_duplicate_json_keys(evidence["raw_wire_json"])
            if dup_keys:
                violations.append(
                    "SERIALIZATION_VIOLATION: non-canonical wire document with duplicate "
                    f"JSON keys ({', '.join(dup_keys)}); parser-dependent values rejected."
                )

        # 1. Signature & Key Validity Checks
        req_sig = rc.get("require_signed_evidence", True)
        allowed_algs = rc.get("allowed_sig_algs", ["ed25519", "hmac-sha256"])
        min_sigs = rc.get("min_required_signatures", 1)
        # HMAC verification uses the operator-configured policy secret ONLY.
        # Falling back to a source-code constant would make the signature
        # forgeable by anyone who can read the repository (2026-08 adversarial
        # review, N1). No policy secret => HMAC signatures are rejected.
        hmac_secret_key = rc.get("hmac_secret_key")

        if req_sig:
            sig_list = list(bundle_dict.get("signatures", []))
            
            # If the single signature is present but not in the signatures list, include it
            if is_signed and sig:
                single_sig_in_list = any(s.get("signature") == sig for s in sig_list)
                if not single_sig_in_list:
                    sig_list.append({
                        "signature": sig,
                        "sig_alg": sig_alg,
                        "key_id": key_id,
                        "public_key": pub_key,
                        "kms_key_arn": bundle_dict.get("kms_key_arn")
                    })
            
            if not sig_list:
                violations.append("POLICY_VIOLATION: Unsigned evidence bundle rejected.")
            else:
                valid_sigs_count = 0
                # N10: a signature threshold counts DISTINCT authorized keys.
                # The same key re-signing a bundle (or the same signature
                # copied) advances no threshold; "K-of-M" means K different
                # signers, so a single compromised key cannot satisfy it.
                valid_sig_key_ids: set[str] = set()
                for sig_entry in sig_list:
                    s_sig = sig_entry.get("signature")
                    s_alg = sig_entry.get("sig_alg", "ed25519")
                    s_key_id = sig_entry.get("key_id")
                    s_pub = sig_entry.get("public_key")
                    s_arn = sig_entry.get("kms_key_arn")
                    
                    if s_alg not in allowed_algs:
                        violations.append(f"POLICY_VIOLATION: Signature algorithm '{s_alg}' not allowed by policy.")
                        continue
                    if s_key_id and s_key_id in self.revoked_key_ids:
                        violations.append(f"POLICY_VIOLATION: Key ID '{s_key_id}' has been revoked!")
                        continue

                    # Trusted-key registry: the public key travels inside the
                    # attacker-controllable bundle, so it is never trusted.
                    # Verification uses the registry-pinned key, and unknown
                    # key IDs are rejected outright.
                    pinned_pub = None
                    if s_alg == "ed25519":
                        enforce_registry = rc.get("require_trusted_key", True)
                        if enforce_registry:
                            if not self.trusted_keys:
                                violations.append("POLICY_VIOLATION: No trusted key registry configured; Ed25519 signatures cannot be authenticated.")
                                continue
                            if s_key_id not in self.trusted_keys:
                                violations.append(f"POLICY_VIOLATION: Key ID '{s_key_id}' not in trusted key registry.")
                                continue
                            pinned_pub = self.trusted_keys[s_key_id]
                            if s_pub and not hmac.compare_digest(s_pub, pinned_pub):
                                violations.append(f"POLICY_VIOLATION: Public key for '{s_key_id}' does not match the trusted key registry.")
                                continue
                        else:
                            pinned_pub = None
                        kms_pattern = rc.get("kms_key_arn_pattern")
                        if kms_pattern and (not s_arn or not re.match(kms_pattern, s_arn)):
                            violations.append("POLICY_VIOLATION: Signing key KMS ARN missing or outside the required boundary.")
                            continue

                    payload_to_verify = {
                        "evidence_id": bundle_dict.get("evidence_id", ""),
                        "timestamp": bundle_dict.get("timestamp", ""),
                        "nonce": bundle_dict.get("nonce", ""),
                        "agent_system_version": bundle_dict.get("agent_system_version", ""),
                        "test_pass_pct": bundle_dict.get("test_pass_pct", 0.0),
                        "unresolved_drift": bundle_dict.get("unresolved_drift", 0),
                        "execution_traces_count": bundle_dict.get("execution_traces_count", 0),
                        "merkle_root": bundle_dict.get("merkle_root", ""),
                        "artifact_digests": bundle_dict.get("artifact_digests", {}),
                        "sig_alg": s_alg,
                        "key_id": s_key_id,
                        "kms_key_arn": s_arn
                    }
                    
                    if s_alg == "ed25519":
                        verify_pub = pinned_pub or s_pub
                        if not verify_pub:
                            violations.append("POLICY_VIOLATION: Missing public key for Ed25519 verification.")
                        else:
                            if verify_signature_ed25519(payload_to_verify, s_sig, verify_pub):
                                if s_key_id not in valid_sig_key_ids:
                                    valid_sig_key_ids.add(s_key_id)
                                    valid_sigs_count += 1
                            else:
                                violations.append("POLICY_VIOLATION: Invalid or forged Ed25519 signature.")
                    else:
                        if not hmac_secret_key:
                            violations.append(
                                "POLICY_VIOLATION: HMAC-SHA256 signatures require an "
                                "operator-configured 'hmac_secret_key' in the policy; "
                                "the source-code default constant is not a secret."
                            )
                            continue
                        if verify_signature_hmac(payload_to_verify, s_sig, hmac_secret_key):
                            if (s_key_id or s_sig) not in valid_sig_key_ids:
                                valid_sig_key_ids.add(s_key_id or s_sig)
                                valid_sigs_count += 1
                        else:
                            violations.append("POLICY_VIOLATION: Invalid or forged HMAC signature.")
                            
                if valid_sigs_count < min_sigs:
                    violations.append(
                        f"POLICY_VIOLATION: Insufficient valid signatures ({valid_sigs_count} < required {min_sigs})."
                    )

        # 2. Merkle Root Integrity check
        verify_merkle = rc.get("verify_merkle_root", True)
        if verify_merkle and traces:
            leaf_hashes = []
            for t in traces:
                if isinstance(t, dict):
                    leaf_hashes.append(hash_sha256(execution_trace_leaf_string(t)))
            recalculated_root, _ = build_merkle_tree(leaf_hashes)
            if recalculated_root != merkle_root:
                violations.append(
                    f"POLICY_VIOLATION: Merkle root mismatch! Claimed: {merkle_root[:12]}..., Recalculated: {recalculated_root[:12]}..."
                )

        # 2b. Signed trace-count binding: the signed execution_traces_count
        # must match the traces actually present - auditors derive Merkle
        # proof depth from this count, so a lie here breaks proof binding.
        # (Condition-gated like every other check so the ablation study can
        # measure its marginal contribution; default ON = fail-closed.)
        claimed_count = bundle_dict.get("execution_traces_count")
        if rc.get("enforce_trace_count", True) and claimed_count is not None and claimed_count != len(traces):
            violations.append(
                f"POLICY_VIOLATION: Execution trace count mismatch ({claimed_count} claimed, {len(traces)} present)."
            )

        # 3. Test Pass Percentage check
        min_pass_pct = rc.get("min_passing_tests_pct", 100.0)
        if test_pass_pct < min_pass_pct:
            violations.append(
                f"POLICY_VIOLATION: Sub-threshold test pass rate ({test_pass_pct}% < min required {min_pass_pct}%)."
            )

        # 4. Drift Findings check
        allowed_drift = rc.get("allowed_drift_findings", 0)
        if unresolved_drift > allowed_drift:
            violations.append(
                f"POLICY_VIOLATION: Unresolved drift findings present ({unresolved_drift} > allowed {allowed_drift})."
            )

        # 5. Timestamp Freshness & Clock Skew check
        max_age = rc.get("max_evidence_age_seconds", 3600)
        max_future_skew = rc.get("max_future_clock_skew_seconds", 30)
        if timestamp_str:
            try:
                ev_dt = datetime.fromisoformat(timestamp_str)
                if ev_dt.tzinfo is None:
                    ev_dt = ev_dt.replace(tzinfo=timezone.utc)
                now_dt = datetime.now(timezone.utc)
                age = (now_dt - ev_dt).total_seconds()
                if age < -max_future_skew:
                    violations.append(f"POLICY_VIOLATION: Timestamp post-dated in the future (skew: {int(-age)}s > max {max_future_skew}s).")
                elif age > max_age:
                    violations.append(f"POLICY_VIOLATION: Evidence timestamp expired ({int(age)}s > max {max_age}s).")
            except Exception:
                violations.append("POLICY_VIOLATION: Invalid timestamp ISO format.")

        # 6. Replay Nonce Check
        if seen_nonces is not None and nonce:
            # Record current nonce timestamp
            try:
                ev_dt = datetime.fromisoformat(timestamp_str)
                if ev_dt.tzinfo is None:
                    ev_dt = ev_dt.replace(tzinfo=timezone.utc)
                _NONCE_TIMESTAMPS[nonce] = ev_dt
            except Exception:
                pass

            # Prune expired nonces from seen_nonces in-place
            now_dt = datetime.now(timezone.utc)
            max_age = rc.get("max_evidence_age_seconds", 3600)
            
            expired = []
            for n in list(seen_nonces):
                if n in _NONCE_TIMESTAMPS:
                    age = (now_dt - _NONCE_TIMESTAMPS[n]).total_seconds()
                    if age > max_age:
                        expired.append(n)
            
            for n in expired:
                seen_nonces.discard(n)
                _NONCE_TIMESTAMPS.pop(n, None)

            if nonce in seen_nonces:
                violations.append(f"POLICY_VIOLATION: Replayed evidence nonce detected ({nonce}).")
            else:
                # The engine itself records the nonce once it has been
                # processed, so a caller sharing one set across evaluations
                # gets real replay detection without manual bookkeeping
                # (2026-08 adversarial review, N3).
                seen_nonces.add(nonce)

        # 7. SLSA Provenance Envelope check
        require_slsa = rc.get("require_slsa_envelope", False)
        if require_slsa and not slsa_pred:
            violations.append("POLICY_VIOLATION: Missing required SLSA v1.0 / in-toto provenance statement envelope.")

        passed = (len(violations) == 0)

        details = {
            "evidence_id": evidence_id,
            "policy_name": self.policy_name,
            "passed": passed,
            "violations_count": len(violations),
            "violations": violations,
            "sig_alg": sig_alg,
            "key_id": key_id,
            "fail_closed_enforced": True
        }

        return passed, violations, details
