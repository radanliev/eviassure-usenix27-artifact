"""
Unit tests for browser and UI evidence attestation.
Verifies DOM state hashing, visual trace screenshot digests, and fail-closed blocking upon UI mutation.
"""

from pathlib import Path
from assurance.evidence import create_evidence_pack
from assurance.policy import ReleasePolicyEngine
from specimens.web_app_runner import WebBrowserAgentSpecimen, run_web_agent_attestation_demo

def test_browser_ui_clean_attestation_pass():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    _, bundle = run_web_agent_attestation_demo(tampered=False)
    bundle_dict = bundle.to_dict()

    passed, violations, details = policy_engine.evaluate(bundle_dict)
    assert passed is True, f"Clean UI attestation failed policy evaluation: {violations}"
    assert len(violations) == 0

def test_browser_ui_tampered_dom_fail_closed_block():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    specimen = WebBrowserAgentSpecimen()
    specimen.navigate()
    specimen.click_button()

    # Tamper with the Merkle trace output digest to simulate UI/DOM mutation injection
    specimen.exec_traces[1].output_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    # Re-create bundle with tampered trace
    bundle = create_evidence_pack(
        traces=specimen.exec_traces,
        test_pass_pct=100.0,
        unresolved_drift=0,
        signed=True
    )
    
    # Tamper with claimed Merkle root vs trace recalculated root
    bundle_dict = bundle.to_dict()
    bundle_dict["traces"][1]["output_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    passed, violations, details = policy_engine.evaluate(bundle_dict)
    assert passed is False, "Tampered DOM UI state unexpectedly passed release gate!"
    assert any("Merkle root mismatch" in v or "signature" in v.lower() for v in violations)
    assert details["fail_closed_enforced"] is True
