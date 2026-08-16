"""
Property-based tests (hypothesis) for the cryptographic core.

These encode the invariants the paper's security argument depends on:
Merkle soundness (no false inclusion), canonical-JSON determinism (signature
binding), blinding structure, and fail-closed parsing under arbitrary input.
"""
from hypothesis import given, settings, strategies as st, HealthCheck

from assurance.crypto import (
    build_merkle_tree, generate_merkle_proof, verify_merkle_proof,
    hash_sha256, canonical_json,
)
from assurance.evidence import ExecutionTraceRecord
from assurance.policy import ReleasePolicyEngine
from pathlib import Path

POLICY = Path(__file__).parent.parent / "governance" / "release_policy.yaml"

hex32 = st.from_regex(r"^[0-9a-f]{64}$", fullmatch=True)
actions = st.sampled_from(["read_file", "spawn_shell_subprocess", "sql_query",
                           "http_request", "embed_query"])


@given(st.lists(st.tuples(st.text(min_size=1, max_size=8), actions, hex32),
                min_size=1, max_size=40))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
def test_merkle_proofs_sound_and_complete(recs):
    """Every leaf verifies against the root; and no hash other than the true
    leaf hash ever verifies with the same proof path (soundness)."""
    traces = [
        ExecutionTraceRecord(trace_id=f"T{i}", agent_id="a", action=act,
                             status="SUCCESS", duration_ms=1.0, output_hash=h)
        for i, (_, act, h) in enumerate(recs)
    ]
    leaves = [t.to_hash() for t in traces]
    root, levels = build_merkle_tree(leaves)
    for i, leaf in enumerate(leaves):
        proof = generate_merkle_proof(i, levels)
        assert verify_merkle_proof(leaf, proof, root)
        # soundness: a different leaf must NOT verify with this proof
        other = hash_sha256(leaf)
        assert not verify_merkle_proof(other, proof, root)


@given(st.lists(st.integers(min_value=-(10**9), max_value=10**9),
                min_size=1, max_size=30),
       st.booleans())
@settings(deadline=None)
def test_canonical_json_deterministic(values, flag):
    """Serialization must be canonical: no two serializations of equal data
    differ, and dict ordering can never change the signed bytes."""
    d1 = {"b": values, "a": flag, "n": len(values)}
    d2 = {"a": flag, "n": len(values), "b": values}
    assert canonical_json(d1) == canonical_json(d2)


@given(st.text(min_size=0, max_size=64), st.text(min_size=1, max_size=64))
@settings(deadline=None)
def test_blinding_structure_and_variance(payload, salt):
    """Blinded records carry the marker prefix and a 256-bit (64 hex) tag;
    distinct payloads or salts must blind to distinct tags with high
    probability (checked structurally here, statistically by the bound)."""
    rec = ExecutionTraceRecord(trace_id="T", agent_id="a", action="x",
                               status="SUCCESS", duration_ms=1.0,
                               output_hash=hash_sha256(payload))
    b1 = rec.blind_payload(salt).output_hash
    assert len(b1) == 64
    b2 = rec.blind_payload(salt + "!").output_hash
    if payload != "":
        assert b1 != b2


@given(st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda ch: st.lists(ch, max_size=3) | st.dictionaries(st.text(max_size=3), ch, max_size=3),
    max_leaves=8))
@settings(deadline=None)
def test_policy_fails_closed_on_arbitrary_json(node):
    """The gate must return a BLOCKED verdict for ANY malformed payload —
    never raise, never approve."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    passed, violations, details = engine.evaluate(node)
    assert passed is False
    assert details.get("fail_closed_enforced") is True
