"""
Regression test: the corpus-scale two-layer evaluation artifact must agree
with the corpus itself. If profile counts, gate verdicts, or inspection flags
drift, the paper's Section 6.7 numbers (reported from
results/corpus_evaluation.json) would silently rot.
"""

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_corpus_evaluation_matches_corpus_counts():
    corpus = json.loads((ROOT / "corpus" / "agent_trace_corpus.json").read_text())
    ev = json.loads((ROOT / "results" / "corpus_evaluation.json").read_text())

    profiles = corpus["profiles"]
    clean = [p for p in profiles if p["label"] == "CLEAN"]
    anomalous = [p for p in profiles if p["label"] != "CLEAN"]

    assert ev["corpus"]["total_profiles"] == len(profiles) == corpus["total_profiles"]
    assert ev["corpus"]["clean_profiles"] == len(clean)
    assert ev["corpus"]["anomalous_profiles"] == len(anomalous)
    assert ev["corpus"]["distinct_anomaly_classes"] == len({p["label"] for p in anomalous})

    l1 = ev["layer_1_cryptographic_integrity"]
    assert l1["merkle_consistent"] == len(profiles)
    assert l1["inclusion_proofs_valid"] == len(profiles)

    l2 = ev["layer_2_release_policy_gate"]
    assert l2["clean_approved"] == len(clean)
    assert l2["clean_approved_pct"] == 100.0
    assert l2["anomalous_approved"] == len(anomalous)

    l3 = ev["layer_3_per_leaf_semantic_inspection"]
    assert l3["anomalous_flagged"] == len(anomalous)
    assert l3["anomalous_recall_pct"] == 100.0
    assert l3["clean_flagged_false_positive"] == 0
    assert l3["false_positive_rate_pct"] == 0.0


def test_every_anomaly_class_has_non_success_leaf():
    """The inspection layer's flag definition, asserted against the corpus:
    every anomaly profile carries at least one non-SUCCESS trace, and every
    clean profile carries only SUCCESS traces."""
    corpus = json.loads((ROOT / "corpus" / "agent_trace_corpus.json").read_text())
    for prof in corpus["profiles"]:
        statuses = {t["status"] for t in prof["traces"]}
        if prof["label"] == "CLEAN":
            assert statuses == {"SUCCESS"}, prof["profile_id"]
        else:
            assert statuses != {"SUCCESS"}, prof["profile_id"]