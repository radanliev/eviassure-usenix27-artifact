"""
Unit tests for cryptographic evidence packaging, Ed25519 signatures, Merkle trees, and SLSA envelopes.
"""

from assurance.crypto import (
    hash_sha256,
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
    sign_payload_hmac,
    verify_signature_hmac,
    generate_ed25519_keypair,
    sign_payload_ed25519,
    verify_signature_ed25519,
)
from assurance.evidence import create_evidence_pack, DEFAULT_SECRET_KEY, DEMO_PRIV_KEY, DEMO_PUB_KEY_B64


def test_hash_sha256():
    digest = hash_sha256("test_payload")
    assert isinstance(digest, str)
    assert len(digest) == 64


def test_merkle_tree_construction_and_proof():
    leaves = [hash_sha256(f"leaf_{i}") for i in range(5)]
    root, levels = build_merkle_tree(leaves)

    assert isinstance(root, str)
    assert len(root) == 64
    assert len(levels) > 1

    idx = 2
    proof = generate_merkle_proof(idx, levels)
    assert len(proof) > 0
    assert verify_merkle_proof(leaves[idx], proof, root) is True


def test_ed25519_keypair_generation_and_verification():
    priv_key, pub_key, pub_b64, key_id = generate_ed25519_keypair()
    payload = {"evidence_id": "EVD-ED25519-TEST", "pass_pct": 100.0}

    sig_b64 = sign_payload_ed25519(payload, priv_key)
    assert verify_signature_ed25519(payload, sig_b64, pub_b64) is True

    # Modified payload verification failure
    tampered = {"evidence_id": "EVD-ED25519-TEST", "pass_pct": 99.0}
    assert verify_signature_ed25519(tampered, sig_b64, pub_b64) is False


def test_evidence_pack_slsa_envelope():
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    slsa_env = bundle.generate_slsa_envelope()

    assert slsa_env["_type"] == "https://in-toto.io/Statement/v0.1"
    assert slsa_env["predicateType"] == "https://slsa.dev/provenance/v1"
    assert bundle.verify_signature() is True


def test_privacy_trace_blinding():
    bundle = create_evidence_pack(blind_privacy=True, privacy_salt="custom-salt-99", signed=True)
    assert bundle.signed is True
    assert bundle.verify_signature() is True
    assert len(bundle.traces[0]["output_hash"]) == 64
    assert bundle.traces[0].get("raw_payload") is None


def test_sparse_merkle_proof_generation():
    bundle = create_evidence_pack(signed=True)
    proofs = bundle.generate_sparse_proofs(audit_indices=[0, 2])
    assert len(proofs) == 2
    assert proofs[0]["index"] == 0
    assert "proof_path" in proofs[0]
