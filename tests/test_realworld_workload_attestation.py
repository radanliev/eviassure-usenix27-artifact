"""
Integration test for EviAssure attestation over complex real-world agent workloads.

Simulates a multi-tool software engineering agent (SWE-bench style) executing
source code modifications, unit test validation, git commits, and deployment calls.
"""

from pathlib import Path
from assurance.crypto import generate_ed25519_keypair, hash_sha256
from assurance.evidence import ExecutionTraceRecord, EvidenceBundle, create_evidence_pack
from assurance.policy import ReleasePolicyEngine

REPO_ROOT = Path(__file__).parent.parent


def test_realworld_swe_agent_workload_attestation():
    """Verify that a complex multi-step SWE-agent execution trace is correctly attested and approved."""
    priv_key, pub_key, pub_key_b64, key_id = generate_ed25519_keypair()
    
    # Simulate a 10-step software engineering agent workflow
    steps = [
        ("step_1", "SWEAgent", "checkout_repository", "SUCCESS", 120, "hash_repo_main"),
        ("step_2", "SWEAgent", "run_linter", "SUCCESS", 450, "hash_lint_clean"),
        ("step_3", "SWEAgent", "apply_patch_file", "SUCCESS", 210, "hash_patch_v1"),
        ("step_4", "SWEAgent", "execute_unit_tests", "SUCCESS", 1850, "hash_pytest_18_pass"),
        ("step_5", "SWEAgent", "build_container_image", "SUCCESS", 3400, "hash_image_sha256"),
        ("step_6", "SWEAgent", "run_security_vulnerability_scan", "SUCCESS", 920, "hash_trivy_0_vuln"),
        ("step_7", "SWEAgent", "generate_slsa_provenance", "SUCCESS", 110, "hash_slsa_envelope"),
        ("step_8", "SWEAgent", "stage_artifact_registry", "SUCCESS", 650, "hash_registry_ack"),
        ("step_9", "SWEAgent", "kms_sign_evidence_root", "SUCCESS", 45, "hash_kms_sig"),
        ("step_10", "SWEAgent", "trigger_release_gate", "SUCCESS", 15, "hash_gate_pass"),
    ]
    
    traces = [
        ExecutionTraceRecord(
            trace_id=step_id,
            agent_id=agent,
            action=action,
            status=status,
            duration_ms=dur,
            output_hash=out_h
        )
        for step_id, agent, action, status, dur, out_h in steps
    ]
    
    bundle = create_evidence_pack(
        traces=traces,
        test_pass_pct=100.0,
        unresolved_drift=0
    )
    
    assert bundle.signed is True
    assert len(bundle.traces) == 10
    assert bundle.merkle_root is not None
    
    engine = ReleasePolicyEngine.from_yaml(REPO_ROOT / "governance" / "release_policy.yaml")
    passed, violations, details = engine.evaluate(bundle)
    
    assert passed is True
    assert len(violations) == 0
