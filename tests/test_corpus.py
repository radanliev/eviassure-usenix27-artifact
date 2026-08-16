"""
Unit and integration tests for the expanded N=1,050 agent trace corpus.

Corpus integrity, attestation leaf hashing, and gate behavior: all profiles
package into Merkle-consistent signed bundles; clean profiles pass policy
verification; planted anomalies are *semantic* signals (non-SUCCESS trace
statuses visible to forensic inspection), not cryptographic tampering, so
they do not trip the cryptographic gate.
"""

import json
from pathlib import Path
from assurance.crypto import hash_sha256, build_merkle_tree
from assurance.evidence import ExecutionTraceRecord, create_evidence_pack
from assurance.policy import ReleasePolicyEngine

def test_expanded_corpus_loading():
    corpus_path = Path(__file__).parent.parent / "corpus" / "agent_trace_corpus.json"
    assert corpus_path.exists(), "Corpus JSON file must exist!"

    with open(corpus_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_profiles"] >= 1000, "Corpus must contain at least 1,000 profiles!"
    assert data["total_anomalies"] == 50, "Corpus must contain exactly 50 anomaly profiles!"
    assert len(data["profiles"]) == data["total_profiles"]
    assert len(data["agent_architectures"]) == 5, "Corpus must span five agent architectures"

def test_corpus_anomaly_detection_and_merkle_hashing():
    corpus_path = Path(__file__).parent.parent / "corpus" / "agent_trace_corpus.json"
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    with open(corpus_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    anomalies = 0
    clean_passed = 0
    distinct_anomaly_types = set()

    for prof in data["profiles"]:
        label = prof["label"]
        traces = [
            ExecutionTraceRecord(
                trace_id=t["trace_id"],
                agent_id=t["agent_id"],
                action=t["action"],
                status=t["status"],
                duration_ms=t["duration_ms"],
                output_hash=t["output_hash"]
            )
            for t in prof["traces"]
        ]

        bundle = create_evidence_pack(traces=traces, signed=True)
        bundle_dict = bundle.to_dict()

        # Every profile, clean or anomalous, is Merkle-consistent
        leaf_hashes = [t.to_hash() for t in traces]
        root, _ = build_merkle_tree(leaf_hashes)
        assert root == bundle.merkle_root, "Merkle root mismatch!"

        passed, violations, _ = policy_engine.evaluate(bundle_dict)

        if label != "CLEAN":
            anomalies += 1
            distinct_anomaly_types.add(label)
            # Planted anomalies are semantic: at least one trace carries a
            # non-SUCCESS status that forensic inspection surfaces per-leaf.
            assert any(t.status != "SUCCESS" for t in traces), (
                f"Anomaly profile {prof['profile_id']} ({label}) has no non-SUCCESS trace"
            )
        else:
            clean_passed += 1
            assert passed, f"Clean profile {prof['profile_id']} failed the gate: {violations}"

    assert anomalies == 50, f"Expected 50 anomaly profiles, got {anomalies}"
    assert clean_passed == 1000, f"Expected 1,000 clean passes, got {clean_passed}"
    assert len(distinct_anomaly_types) == 10, (
        f"Expected 10 distinct anomaly types, got {len(distinct_anomaly_types)}"
    )
