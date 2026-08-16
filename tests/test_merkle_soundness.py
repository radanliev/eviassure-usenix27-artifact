"""
Regression tests for the soundness gaps found by the 2026-08-15 adversarial
review (docs/PEER_REVIEW_2026-08-15.md):

M1 - internal Merkle nodes verified as leaves via shortened proof paths
     (no hash collision needed; CVE-2012-2459 family). Fixed by binding
     verification to the committed tree depth.
M2 - the signed execution_traces_count was never compared to len(traces);
     bundles lied about trace counts and passed.
M3 - the blinding tag truncated a 256-bit HMAC to 64 bits.
"""

from pathlib import Path

from assurance.crypto import (
    hash_sha256, build_merkle_tree, generate_merkle_proof,
    verify_merkle_proof, expected_tree_depth,
)
from assurance.evidence import (
    ExecutionTraceRecord, EvidenceBundle, create_evidence_pack,
    DEMO_PRIV_KEY, DEMO_PUB_KEY_B64,
)
from assurance.policy import ReleasePolicyEngine

POLICY = Path(__file__).parent.parent / "governance" / "release_policy.yaml"


def _tree(n):
    leaves = [hash_sha256(f"trace-{i}") for i in range(n)]
    root, levels = build_merkle_tree(leaves)
    return leaves, root, levels


def _shortened_path(levels, level_idx, node_idx):
    """Proof path from (level_idx, node_idx) upward, as an attacker would craft."""
    path, idx = [], node_idx
    for lvl in levels[level_idx:-1]:
        sib = lvl[idx + 1] if idx % 2 == 0 and idx + 1 < len(lvl) else lvl[idx - 1] if idx % 2 == 1 else lvl[idx]
        path.append({"hash": sib, "position": "right" if idx % 2 == 0 else "left"})
        idx //= 2
    return path


def test_internal_node_cannot_verify_as_leaf_with_depth_bound():
    """The exact attack from the review: internal node + shortened path."""
    leaves, root, levels = _tree(16)
    internal = levels[1][2]                      # covers leaves 4-5
    att = _shortened_path(levels, 1, 2)          # 3 nodes, not 4
    depth = expected_tree_depth(16)
    assert len(att) == depth - 1
    # without the depth bound the attack succeeded (see review M1)
    assert verify_merkle_proof(internal, att, root) is True
    # with the committed depth it must fail
    assert verify_merkle_proof(internal, att, root, expected_depth=depth) is False
    # and honest proofs still verify
    honest = generate_merkle_proof(5, levels)
    assert verify_merkle_proof(leaves[5], honest, root, expected_depth=depth) is True


def test_depth_helper_matches_built_trees():
    for n in (1, 2, 3, 16, 100, 1000, 4096):
        _, _, levels = _tree(n)
        assert len(levels) - 1 == expected_tree_depth(n), n


def test_signed_trace_count_is_enforced():
    """M2: lying about execution_traces_count must block, not pass."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    d = bundle.to_dict()
    d["execution_traces_count"] = 999
    eb = EvidenceBundle(**{k: v for k, v in d.items() if k not in ("signature", "signatures")})
    eb.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)   # properly signed lie
    passed, violations, _ = engine.evaluate(eb.to_dict())
    assert not passed
    assert any("trace count mismatch" in v for v in violations)

    # honest bundle still passes
    ok, vi, _ = engine.evaluate(create_evidence_pack(use_ed25519=True, signed=True).to_dict())
    assert ok, vi


def test_blinding_tag_is_256_bit():
    """M3: blinded output hash carries the full HMAC digest (64 hex)."""
    rec = ExecutionTraceRecord(trace_id="T", agent_id="a", action="x",
                               status="SUCCESS", duration_ms=1.0,
                               output_hash=hash_sha256("secret payload"))
    blinded = rec.blind_payload("s" * 32).output_hash
    assert len(blinded) == 64
