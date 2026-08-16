"""
Evidence Bundle Schema, Ed25519/HMAC Attestations, Privacy Blinding, and Sparse Merkle Proof Engine.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import base64
import uuid
import hmac
import hashlib
from typing import List, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import (
    hash_sha256,
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
    sign_payload_hmac,
    verify_signature_hmac,
    generate_ed25519_keypair,
    sign_payload_ed25519,
    verify_signature_ed25519,
    format_intoto_statement,
    format_slsa_provenance,
    compute_key_id
)

DEFAULT_SECRET_KEY = "usenix-security-2027-release-assurance-key"

# Static demo Ed25519 keypair (DEMO/TEST ONLY — never use in production).
# Fixed so packager and verifier processes derive the same key; its public
# half is pinned in governance/trusted_keys.yaml and nothing else is trusted.
DEMO_PRIV_SEED = bytes.fromhex(
    "d842fd18d672140d2cb1f725f5b72e79574461dbae1c80f16a986264fea4407e")
DEMO_PRIV_KEY = Ed25519PrivateKey.from_private_bytes(DEMO_PRIV_SEED)
DEMO_PUB_KEY = DEMO_PRIV_KEY.public_key()
DEMO_PUB_KEY_B64 = base64.b64encode(DEMO_PUB_KEY.public_bytes_raw()).decode("utf-8")
DEMO_KEY_ID = compute_key_id(DEMO_PUB_KEY_B64)


@dataclass
class ExecutionTraceRecord:
    trace_id: str
    agent_id: str
    action: str
    status: str
    duration_ms: float
    output_hash: str
    raw_payload: Optional[str] = None

    def blind_payload(self, salt: str) -> "ExecutionTraceRecord":
        """Produce privacy-blinded trace record replacing raw payload with salted HMAC hash."""
        blinded_hash = hmac.new(
            salt.encode('utf-8'),
            self.output_hash.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return ExecutionTraceRecord(
            trace_id=self.trace_id,
            agent_id=self.agent_id,
            action=self.action,
            status=self.status,
            duration_ms=self.duration_ms,
            output_hash=f"BLINDED-{blinded_hash}",
            raw_payload=None
        )

    def to_hash(self) -> str:
        return hash_sha256(execution_trace_leaf_string(self))



def execution_trace_leaf_string(trace: Any) -> str:
    """Canonical leaf content for one execution trace record.

    Single source of truth for the Merkle leaf string, shared by the packager
    (to_hash), the verifier's root re-derivation (policy.py), the forensic
    audit engine (forensics.py), and sparse-proof generation. Every field the
    trace schema declares -- including duration_ms -- is committed; changing
    any of them invalidates the root (2026-08 adversarial review, N2)."""
    if hasattr(trace, "duration_ms"):
        return f"{trace.trace_id}:{trace.agent_id}:{trace.action}:{trace.status}:{trace.duration_ms}:{trace.output_hash}"
    return f"{trace['trace_id']}:{trace['agent_id']}:{trace['action']}:{trace['status']}:{trace['duration_ms']}:{trace['output_hash']}"


@dataclass
class BrowserActionTraceRecord:
    trace_id: str
    agent_id: str
    action: str  # "click", "navigate", "type", "screenshot"
    status: str
    duration_ms: float
    url: str
    element_selector: str
    dom_state_hash: str
    screenshot_sha256: Optional[str] = None

    def to_hash(self) -> str:
        raw = f"{self.trace_id}:{self.agent_id}:{self.action}:{self.status}:{self.duration_ms}:{self.url}:{self.element_selector}:{self.dom_state_hash}:{self.screenshot_sha256 or ''}"
        return hash_sha256(raw)


def realistic_dom_fragment(i: int) -> str:
    """A realistic DOM serialization sample: nested nodes, attributes, and
    per-step dynamic content, mirroring what a browser agent would serialize.

    Shared by the web/UI specimen (specimens/web_app_runner.py) and the
    UI-attestation hashing benchmark so the measured cost reflects real DOM
    content rather than a stub string (2026-08 adversarial review, N8)."""
    return (
        "<html><head><title>Release Control Plane</title></head>"
        "<body><div id='app'><header class='navbar'><h1>Release Dashboard</h1>"
        "<nav><a href='/releases' class='active'>Releases</a><a href='/agents'>Agents</a></nav>"
        "</header><main><section class='panel' data-step='{i}'><div class='metric-card'>"
        "<span class='label'>deploy-status</span><span class='value'>Ready</span></div>"
        "<div class='metric-card'><span class='label'>build-id</span>"
        "<span class='value'>bld-{i:04d}</span></div>"
        "<form id='release-form' action='/api/release' method='POST' "
        "data-agent='web-browser-agent-v1'><input type='hidden' name='csrf' "
        "value='tok-{i:04d}'/><button id='deploy-release' type='submit'>Deploy</button>"
        "</form></section></main><footer>EviAssure runtime 1.2.0</footer></div></body></html>"
    ).format(i=i)



_SENTINEL = object()


@dataclass
class EvidenceBundle:
    evidence_id: str
    timestamp: str
    nonce: str
    agent_system_version: str
    test_pass_pct: float
    unresolved_drift: int
    execution_traces_count: int
    merkle_root: str
    traces: List[Dict[str, Any]] = field(default_factory=list)
    artifact_digests: Dict[str, str] = field(default_factory=dict)
    sig_alg: str = "ed25519"  # "ed25519" or "hmac-sha256"
    key_id: Optional[str] = None
    public_key: Optional[str] = None
    kms_key_arn: Optional[str] = None
    slsa_predicate: Optional[Dict[str, Any]] = None
    sparse_proofs: Optional[List[Dict[str, Any]]] = None
    signed: bool = False
    signature: Optional[str] = None
    signatures: List[Dict[str, Any]] = field(default_factory=list)

    def payload_for_signing(self, sig_alg_override: Any = _SENTINEL, key_id_override: Any = _SENTINEL, kms_arn_override: Any = _SENTINEL) -> Dict[str, Any]:
        """Return canonical dictionary payload excluding signature field."""
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "agent_system_version": self.agent_system_version,
            "test_pass_pct": self.test_pass_pct,
            "unresolved_drift": self.unresolved_drift,
            "execution_traces_count": self.execution_traces_count,
            "merkle_root": self.merkle_root,
            "artifact_digests": self.artifact_digests,
            "sig_alg": sig_alg_override if sig_alg_override is not _SENTINEL else self.sig_alg,
            "key_id": key_id_override if key_id_override is not _SENTINEL else self.key_id,
            "kms_key_arn": kms_arn_override if kms_arn_override is not _SENTINEL else self.kms_key_arn
        }

    def sign_hmac(self, secret_key: str = DEFAULT_SECRET_KEY) -> None:
        self.sig_alg = "hmac-sha256"
        self.key_id = f"KEY-HMAC-{hash_sha256(secret_key)[:8]}"
        payload = self.payload_for_signing()
        self.signature = sign_payload_hmac(payload, secret_key)
        self.signed = True

    def sign_ed25519(self, private_key: "Ed25519PrivateKey" = DEMO_PRIV_KEY, pub_key_b64: str = DEMO_PUB_KEY_B64, kms_arn: Optional[str] = "kms://aws/arn:aws:kms:us-east-1:000000000000:key/usenix-release-gate") -> None:
        self.sig_alg = "ed25519"
        self.public_key = pub_key_b64
        self.key_id = compute_key_id(pub_key_b64)
        self.kms_key_arn = kms_arn
        payload = self.payload_for_signing()
        self.signature = sign_payload_ed25519(payload, private_key)
        self.signed = True

    def sign_hmac_multi(self, secret_key: str = DEFAULT_SECRET_KEY) -> None:
        """Append an HMAC-SHA256 signature to the signatures list."""
        k_id = f"KEY-HMAC-{hash_sha256(secret_key)[:8]}"
        payload = self.payload_for_signing(sig_alg_override="hmac-sha256", key_id_override=k_id, kms_arn_override=None)
        sig = sign_payload_hmac(payload, secret_key)
        self.signatures.append({
            "signature": sig,
            "key_id": k_id,
            "sig_alg": "hmac-sha256"
        })
        self.signed = True

    def sign_ed25519_multi(self, private_key: "Ed25519PrivateKey" = DEMO_PRIV_KEY, pub_key_b64: str = DEMO_PUB_KEY_B64, kms_arn: Optional[str] = "kms://aws/arn:aws:kms:us-east-1:000000000000:key/usenix-release-gate") -> None:
        """Append an Ed25519 signature to the signatures list."""
        k_id = compute_key_id(pub_key_b64)
        payload = self.payload_for_signing(sig_alg_override="ed25519", key_id_override=k_id, kms_arn_override=kms_arn)
        sig = sign_payload_ed25519(payload, private_key)
        self.signatures.append({
            "signature": sig,
            "key_id": k_id,
            "public_key": pub_key_b64,
            "sig_alg": "ed25519",
            "kms_key_arn": kms_arn
        })
        self.signed = True

    def verify_signature(self, secret_key: str = DEFAULT_SECRET_KEY) -> bool:
        """Verify the signature(s). Returns True if at least one signature verifies cleanly."""
        payload = self.payload_for_signing()

        # Check signatures list first
        if self.signatures:
            valid_count = 0
            for sig_entry in self.signatures:
                s = sig_entry.get("signature")
                alg = sig_entry.get("sig_alg", "ed25519")
                pk = sig_entry.get("public_key")
                
                # Create a specific payload reflecting the specific signature fields
                p_copy = payload.copy()
                p_copy["sig_alg"] = alg
                p_copy["key_id"] = sig_entry.get("key_id")
                p_copy["kms_key_arn"] = sig_entry.get("kms_key_arn")

                if alg == "ed25519" and pk:
                    # Self-consistency only (does this signature match this
                    # bundle's own key?). Authentication against the trusted
                    # registry happens in ReleasePolicyEngine/ForensicAuditEngine.
                    # nosemgrep: verifier-trusts-payload-supplied-key
                    if s and verify_signature_ed25519(p_copy, s, pk):
                        valid_count += 1
                else:
                    if s and verify_signature_hmac(p_copy, s, secret_key):
                        valid_count += 1
            return valid_count > 0

        # Fallback to single signature
        if not self.signed or not self.signature:
            return False
        if self.sig_alg == "ed25519":
            if not self.public_key:
                return False
            return verify_signature_ed25519(payload, self.signature, self.public_key)
        else:
            return verify_signature_hmac(payload, self.signature, secret_key)

    def generate_sparse_proofs(self, audit_indices: List[int]) -> List[Dict[str, Any]]:
        """Generate compact O(log N) sparse Merkle inclusion proofs for target indices."""
        if not self.traces:
            return []
        leaf_hashes = []
        for t in self.traces:
            leaf_hashes.append(hash_sha256(execution_trace_leaf_string(t)))

        _, levels = build_merkle_tree(leaf_hashes)

        proofs = []
        for idx in audit_indices:
            if 0 <= idx < len(leaf_hashes):
                p_path = generate_merkle_proof(idx, levels)
                proofs.append({
                    "index": idx,
                    "leaf_hash": leaf_hashes[idx],
                    "proof_path": p_path
                })
        self.sparse_proofs = proofs
        return proofs

    def generate_slsa_envelope(self) -> Dict[str, Any]:
        """Wrap evidence into in-toto v0.2 / SLSA v1.0 Statement format."""
        slsa_prov = format_slsa_provenance(
            builder_id=f"https://usenix.org/agent-builder/{self.agent_system_version}",
            build_type="https://usenix.org/AgenticReleasePolicy/v1",
            invocation_params={"evidence_id": self.evidence_id, "nonce": self.nonce},
            materials=[
                {"uri": f"git+https://github.com/radanliev/demo-5-evidence-release-assurance-usenix@{self.agent_system_version}",
                 "digest": {"sha256": self.artifact_digests.get("policy_definition", hash_sha256("DEFAULT"))}}
            ]
        )
        statement = format_intoto_statement(
            subject_name="agentic_release_artifact.tar.gz",
            subject_sha256=self.merkle_root,
            predicate_type="https://slsa.dev/provenance/v1",
            predicate_payload=slsa_prov
        )
        self.slsa_predicate = statement
        return statement

    def to_dict(self) -> Dict[str, Any]:
        # raw_payload must NEVER serialize: bundles carry digests only. A
        # plain asdict() would leak collector-side PII if the field were set
        # (2026-08 check: the Sec 3.2 exclusion claim was previously true only
        # by accident of no caller setting it).
        def _drop_raw_payload(pairs):
            return {k: v for k, v in pairs if k != "raw_payload"}
        return asdict(self, dict_factory=_drop_raw_payload)


def create_evidence_pack(
    traces: Optional[List[ExecutionTraceRecord]] = None,
    test_pass_pct: float = 100.0,
    unresolved_drift: int = 0,
    agent_version: str = "v1.2.0-release",
    artifact_digests: Optional[Dict[str, str]] = None,
    secret_key: str = DEFAULT_SECRET_KEY,
    use_ed25519: bool = True,
    blind_privacy: bool = False,
    privacy_salt: str = "usenix-privacy-salt-2027",
    signed: bool = True
) -> EvidenceBundle:
    """Create a fully signed, Merkle-backed EvidenceBundle."""
    if traces is None:
        traces = [
            ExecutionTraceRecord(
                trace_id="TR-001",
                agent_id="agent-auth-guard",
                action="verify_user_token",
                status="SUCCESS",
                duration_ms=4.2,
                output_hash=hash_sha256("TOKEN_VALIDATED")
            ),
            ExecutionTraceRecord(
                trace_id="TR-002",
                agent_id="agent-policy-gate",
                action="evaluate_rbac",
                status="SUCCESS",
                duration_ms=8.7,
                output_hash=hash_sha256("RBAC_APPROVED")
            ),
            ExecutionTraceRecord(
                trace_id="TR-003",
                agent_id="agent-tool-executor",
                action="execute_db_query",
                status="SUCCESS",
                duration_ms=12.1,
                output_hash=hash_sha256("QUERY_EXECUTED_READONLY")
            ),
        ]

    if blind_privacy:
        traces = [t.blind_payload(privacy_salt) for t in traces]

    # Digests only: raw_payload must never enter the bundle (Sec 3.2).
    # asdict's dict_factory does not reach plain dicts, so filter here.
    trace_dicts = [
        {k: v for k, v in asdict(t).items() if k != "raw_payload"}
        for t in traces
    ]
    leaf_hashes = [t.to_hash() for t in traces]
    merkle_root, _ = build_merkle_tree(leaf_hashes)

    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = str(uuid.uuid4())
    evidence_id = f"EVD-{hash_sha256(f'{timestamp}:{nonce}')[:8]}"

    if artifact_digests is None:
        artifact_digests = {
            "model_weights": hash_sha256("MODEL_WEIGHTS_V1.2"),
            "agent_prompt_spec": hash_sha256("SYSTEM_PROMPT_CONSTRAINED"),
            "policy_definition": hash_sha256("FAIL_CLOSED_POLICY_V1")
        }

    bundle = EvidenceBundle(
        evidence_id=evidence_id,
        timestamp=timestamp,
        nonce=nonce,
        agent_system_version=agent_version,
        test_pass_pct=test_pass_pct,
        unresolved_drift=unresolved_drift,
        execution_traces_count=len(traces),
        merkle_root=merkle_root,
        traces=trace_dicts,
        artifact_digests=artifact_digests,
        sig_alg="ed25519" if use_ed25519 else "hmac-sha256",
        key_id=None,
        public_key=None,
        signed=False,
        signature=None
    )

    bundle.generate_slsa_envelope()

    if signed:
        if use_ed25519:
            bundle.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
        else:
            bundle.sign_hmac(secret_key)

    return bundle
