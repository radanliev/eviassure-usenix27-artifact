import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.verifier import evaluate_release_gate

def test_release_gate_approval():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    res = evaluate_release_gate(policy_path)
    
    assert res["passed"] is True
    assert res["signed"] is True
    assert res["status"] == "APPROVED"
