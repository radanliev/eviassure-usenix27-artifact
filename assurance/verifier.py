"""
Core Release Gate Evaluator for Evidence Assurance.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional

from .policy import ReleasePolicyEngine
from .evidence import create_evidence_pack, EvidenceBundle, DEFAULT_SECRET_KEY


def evaluate_release_gate(
    policy_path: Path | str,
    evidence: Optional[EvidenceBundle | Dict[str, Any]] = None,
    secret_key: str = DEFAULT_SECRET_KEY,
    seen_nonces: Optional[set[str]] = None,
    output_decision_file: Optional[Path | str] = None
) -> Dict[str, Any]:
    """
    Evaluate release policy gate against evidence pack.
    Returns release decision payload dictionary and writes decision JSON if path provided.
    """
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    if evidence is None:
        evidence = create_evidence_pack(secret_key=secret_key, signed=True)

    passed, violations, details = policy_engine.evaluate(
        evidence=evidence,
        secret_key=secret_key,
        seen_nonces=seen_nonces
    )

    ev_id = evidence.evidence_id if isinstance(evidence, EvidenceBundle) else evidence.get("evidence_id", "UNKNOWN")
    signed_status = evidence.signed if isinstance(evidence, EvidenceBundle) else evidence.get("signed", False)

    decision = {
        "status": "APPROVED" if passed else "BLOCKED",
        "passed": passed,
        "policy_name": policy_engine.policy_name,
        "evidence_id": ev_id,
        "signed": signed_status,
        "violations": violations,
        "enforcement": "FAIL_CLOSED"
    }

    if output_decision_file:
        out_p = Path(output_decision_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, 'w', encoding='utf-8') as f:
            json.dump(decision, f, indent=2)

    return decision
