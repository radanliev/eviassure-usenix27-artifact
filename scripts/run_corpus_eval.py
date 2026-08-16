#!/usr/bin/env python3
"""
Corpus-scale two-layer evaluation for the USENIX Security 2027 paper.

Layer 1 (cryptographic gate): every profile -- clean or anomalous -- packages
into a signed bundle whose recomputed Merkle root matches the claimed root,
and every leaf inclusion proof verifies against the committed tree depth.

Layer 2 (release policy): the fail-closed ReleasePolicyEngine verdicts over
the 1,050 profiles.

Layer 3 (per-leaf forensic inspection): the ForensicAuditEngine's semantic
inspection surfaces leaves whose status is not SUCCESS or whose action is a
known-sensitive action; anomalous profiles carry at least one such leaf, clean
profiles carry none. This semantic signal is surfaced by per-leaf inspection,
NOT by the cryptographic gate -- the artifact records gate verdicts and
forensic flags separately so the paper can state both numbers honestly.

Output: results/corpus_evaluation.json
"""

import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import create_evidence_pack, ExecutionTraceRecord
from assurance.policy import ReleasePolicyEngine
from assurance.forensics import ForensicAuditEngine

_ROOT = Path(__file__).parent.parent
_CORPUS = _ROOT / "corpus" / "agent_trace_corpus.json"
_POLICY = _ROOT / "governance" / "release_policy.yaml"
_OUT = _ROOT / "results" / "corpus_evaluation.json"


def _per_leaf_inspection_flag(audit) -> bool:
    """True if the forensic audit's semantic per-leaf inspection surfaced any
    anomaly (non-SUCCESS status or sensitive action). Uses the layer the
    artifact actually implements rather than a script-local duplicate."""
    return bool(audit.get("semantic_anomaly_detected"))


def main():
    with open(_CORPUS, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    profiles = corpus["profiles"]
    assert len(profiles) == corpus["total_profiles"]

    policy_engine = ReleasePolicyEngine.from_yaml(_POLICY)
    audit_engine = ForensicAuditEngine(policy_engine=policy_engine)

    clean = [p for p in profiles if p["label"] == "CLEAN"]
    anomalous = [p for p in profiles if p["label"] != "CLEAN"]

    merkle_consistent = 0
    proofs_valid = 0
    clean_approved = 0
    anom_approved = 0
    anom_flagged = 0
    clean_inspected = 0
    clean_flagged = 0
    distinct_types = set()

    t0 = time.perf_counter()
    for prof in profiles:
        traces = [
            ExecutionTraceRecord(
                trace_id=t["trace_id"], agent_id=t["agent_id"], action=t["action"],
                status=t["status"], duration_ms=t["duration_ms"], output_hash=t["output_hash"]
            )
            for t in prof["traces"]
        ]
        bundle = create_evidence_pack(traces=traces, signed=True)
        bundle_dict = bundle.to_dict()

        audit = audit_engine.audit_bundle(bundle_dict)
        passed, violations, _ = policy_engine.evaluate(bundle_dict)

        if audit["merkle_integrity_valid"]:
            merkle_consistent += 1
        if audit["trace_inclusion_proofs_valid"]:
            proofs_valid += 1

        if prof["label"] == "CLEAN":
            if passed:
                clean_approved += 1
            if _per_leaf_inspection_flag(audit):
                clean_flagged += 1
            clean_inspected += 1
        else:
            distinct_types.add(prof["label"])
            if passed:
                anom_approved += 1
            if _per_leaf_inspection_flag(audit):
                anom_flagged += 1

    elapsed_s = time.perf_counter() - t0

    n_clean = len(clean)
    n_anom = len(anomalous)
    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {
            "python_version": sys.version.split()[0],
            "logical_cores": __import__("os").cpu_count(),
        },
        "corpus": {
            "total_profiles": len(profiles),
            "clean_profiles": n_clean,
            "anomalous_profiles": n_anom,
            "distinct_anomaly_classes": len(distinct_types),
        },
        "evaluation_elapsed_seconds": round(elapsed_s, 2),
        "layer_1_cryptographic_integrity": {
            "merkle_consistent": merkle_consistent,
            "inclusion_proofs_valid": proofs_valid,
            "proofs_valid_pct": round(proofs_valid / len(profiles) * 100.0, 1) if profiles else 0.0,
        },
        "layer_2_release_policy_gate": {
            "clean_approved": clean_approved,
            "clean_approved_pct": round(clean_approved / n_clean * 100.0, 1) if n_clean else 0.0,
            "anomalous_approved": anom_approved,
            "anomalous_approved_pct": round(anom_approved / n_anom * 100.0, 1) if n_anom else 0.0,
            "note": ("anomalous profiles are semantically misbehaving but cryptographically "
                     "well-formed signed bundles, so the cryptographic gate approves them; "
                     "they are surfaced by per-leaf inspection instead"),
        },
        "layer_3_per_leaf_semantic_inspection": {
            "anomalous_flagged": anom_flagged,
            "anomalous_recall_pct": round(anom_flagged / n_anom * 100.0, 1) if n_anom else 0.0,
            "clean_inspected": clean_inspected,
            "clean_flagged_false_positive": clean_flagged,
            "false_positive_rate_pct": round(clean_flagged / n_clean * 100.0, 1) if n_clean else 0.0,
            "note": ("per-leaf semantic inspection flags any trace whose status is not "
                     "SUCCESS or whose action is on the forensic sensitive-action list; "
                     "on this synthetic corpus every anomalous profile carries at least "
                     "one such leaf and no clean profile carries any"),
        },
    }

    _OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(_OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print("=== Corpus Two-Layer Evaluation ===")
    print(f"Profiles: {len(profiles)} total ({n_clean} clean, {n_anom} anomalous, "
          f"{len(distinct_types)} anomaly classes)")
    print(f"L1 integrity:  {merkle_consistent}/{len(profiles)} Merkle-consistent, "
          f"{proofs_valid}/{len(profiles)} inclusion proofs valid")
    print(f"L2 gate:       {clean_approved}/{n_clean} clean APPROVED, "
          f"{anom_approved}/{n_anom} anomalous APPROVED (well-formed bundles)")
    print(f"L3 inspection: {anom_flagged}/{n_anom} anomalous flagged, "
          f"{clean_flagged}/{n_clean} clean falsely flagged")
    print(f"[+] Corpus evaluation saved to: {_OUT}")


if __name__ == "__main__":
    main()