"""
Cryptographic primitives, Ed25519 asymmetric signing, Merkle tree engine, and SLSA/in-toto attestation formatters.
"""

import hmac
import hashlib
import json
import base64
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def hash_sha256(data: str | bytes) -> str:
    """Compute SHA-256 digest of string or bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def canonical_json(data: Dict[str, Any]) -> str:
    """Produce deterministic, key-sorted JSON string."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def detect_duplicate_json_keys(wire_json: str) -> List[str]:
    """Return the list of object keys that occur more than once in a raw JSON
    wire document.

    Duplicate keys are a parser-dependent malleability vector: `json.loads`
    keeps the LAST occurrence while other parsers keep the FIRST, so the same
    signed bytes can evaluate to different values depending on the reader. The
    ingestion boundary rejects such documents outright (2026-08 adversarial
    review, N5)."""
    duplicates: List[str] = []
    seen: Dict[str, int] = {}

    def _pairs_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        for key, value in pairs:
            seen[key] = seen.get(key, 0) + 1
        return dict(pairs)

    try:
        # A duplicate-preserving parse surfaces duplicate keys at every object
        # level; the values are ignored, only the key counts matter.
        json.loads(wire_json, object_pairs_hook=_pairs_hook)
    except json.JSONDecodeError:
        return ["<unparseable-json>"]

    duplicates = [k for k, c in seen.items() if c > 1]
    return sorted(duplicates)


# --- Merkle Tree Engine ---

def build_merkle_tree(leaves: List[str]) -> Tuple[str, List[List[str]]]:
    """
    Build a SHA-256 Merkle tree from a list of leaf hashes or strings.
    Returns (merkle_root, levels_tree).
    """
    if not leaves:
        empty_root = hash_sha256("EMPTY_TREE")
        return empty_root, [[empty_root]]

    current_level = [hash_sha256(leaf) if len(leaf) != 64 else leaf for leaf in leaves]
    levels = [current_level]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hash_sha256(f"{left}:{right}")
            next_level.append(combined)
        levels.append(next_level)
        current_level = next_level

    return current_level[0], levels


def generate_merkle_proof(index: int, levels: List[List[str]]) -> List[Dict[str, str]]:
    """Generate inclusion proof path for a leaf at index."""
    proof = []
    curr_idx = index
    for level in levels[:-1]:
        is_right = (curr_idx % 2 == 1)
        sibling_idx = curr_idx - 1 if is_right else curr_idx + 1
        if sibling_idx < len(level):
            sibling_hash = level[sibling_idx]
        else:
            sibling_hash = level[curr_idx]

        proof.append({
            "position": "left" if is_right else "right",
            "hash": sibling_hash
        })
        curr_idx //= 2
    return proof


def expected_tree_depth(n_leaves: int) -> int:
    """Proof path length for a tree over n_leaves (the committed geometry).

    Without binding the proof to this length, an internal node digest can be
    presented as a leaf with a shortened path (classic Merkle ambiguity,
    CVE-2012-2459 family) - a forgery that needs no hash collision.
    Third-party auditors MUST pass expected_depth, derived from the signed
    execution_traces_count, alongside the root.
    """
    if n_leaves < 1:
        return 0
    return (n_leaves - 1).bit_length()


def verify_merkle_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str,
                        expected_depth: int | None = None) -> bool:
    """Verify Merkle tree inclusion proof against expected root.

    When expected_depth is given, the proof must contain exactly that many
    node steps; shorter paths (internal-node-as-leaf substitution) are
    rejected.
    """
    if expected_depth is not None and len(proof) != expected_depth:
        return False
    current = hash_sha256(leaf_hash) if len(leaf_hash) != 64 else leaf_hash
    for step in proof:
        sibling = step["hash"]
        if step["position"] == "right":
            combined = f"{current}:{sibling}"
        else:
            combined = f"{sibling}:{current}"
        current = hash_sha256(combined)
    return current == expected_root


# --- HMAC-SHA256 Cryptography ---

def sign_payload_hmac(payload: Dict[str, Any], secret_key: str) -> str:
    """Sign payload dictionary with HMAC-SHA256."""
    canonical_str = canonical_json(payload)
    return hmac.new(
        secret_key.encode('utf-8'),
        canonical_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_signature_hmac(payload: Dict[str, Any], signature: str, secret_key: str) -> bool:
    """Verify payload signature against HMAC-SHA256 key."""
    expected_sig = sign_payload_hmac(payload, secret_key)
    return hmac.compare_digest(expected_sig, signature)


# --- Asymmetric Ed25519 Cryptography ---

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, str, str]:
    """
    Generate an Ed25519 private/public keypair.
    Returns: (priv_key_obj, pub_key_obj, pub_key_base64, key_id).
    """
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    key_id = f"KEY-{hash_sha256(pub_bytes)[:12]}"
    
    return priv_key, pub_key, pub_b64, key_id


def compute_key_id(pub_key_b64: str) -> str:
    """Compute key ID digest from base64 raw public key."""
    pub_bytes = base64.b64decode(pub_key_b64.encode('utf-8'))
    return f"KEY-{hash_sha256(pub_bytes)[:12]}"


def sign_payload_ed25519(payload: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
    """Sign payload dictionary with Ed25519 private key."""
    canonical_str = canonical_json(payload)
    sig_bytes = private_key.sign(canonical_str.encode('utf-8'))
    return base64.b64encode(sig_bytes).decode('utf-8')


def verify_signature_ed25519(payload: Dict[str, Any], signature_b64: str, pub_key_b64: str) -> bool:
    """Verify Ed25519 signature using base64 public key."""
    try:
        pub_bytes = base64.b64decode(pub_key_b64.encode('utf-8'))
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64.encode('utf-8'))
        canonical_str = canonical_json(payload)
        pub_key.verify(sig_bytes, canonical_str.encode('utf-8'))
        return True
    except Exception:
        return False


# --- SLSA v1.0 / in-toto Attestation Formatting ---

def format_intoto_statement(
    subject_name: str,
    subject_sha256: str,
    predicate_type: str,
    predicate_payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Format in-toto v0.2 / SLSA v1.0 Statement envelope."""
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": subject_name,
                "digest": {
                    "sha256": subject_sha256
                }
            }
        ],
        "predicateType": predicate_type,
        "predicate": predicate_payload
    }


def format_slsa_provenance(
    builder_id: str,
    build_type: str,
    invocation_params: Dict[str, Any],
    materials: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Format SLSA Provenance v1.0 predicate payload."""
    return {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": invocation_params,
            "internalParameters": {
                "builderId": builder_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "resolvedDependencies": materials
        },
        "runDetails": {
            "builder": {
                "id": builder_id
            },
            "metadata": {
                "invocationId": hash_sha256(f"{builder_id}:{build_type}")[:16]
            }
        }
    }
