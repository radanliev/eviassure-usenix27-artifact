#!/usr/bin/env python3
"""
Forensic Audit Inspection CLI Tool for Evidence Bundles.
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import DEFAULT_SECRET_KEY, create_evidence_pack
from assurance.policy import ReleasePolicyEngine
from assurance.forensics import ForensicAuditEngine


def main():
    parser = argparse.ArgumentParser(description="Run forensic audit inspection on Evidence Bundle.")
    parser.add_argument("--evidence", "-e", type=str, default=None, help="Path to evidence bundle JSON")
    parser.add_argument(
        "--policy",
        "-p",
        type=str,
        default=str(Path(__file__).parent.parent / "governance" / "release_policy.yaml"),
        help="Path to release policy YAML"
    )
    parser.add_argument("--secret-key", type=str, default=DEFAULT_SECRET_KEY, help="HMAC secret key")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output path for forensic audit report JSON")
    args = parser.parse_args()

    policy_engine = ReleasePolicyEngine.from_yaml(args.policy)
    audit_engine = ForensicAuditEngine(policy_engine=policy_engine)

    if args.evidence:
        with open(args.evidence, 'r', encoding='utf-8') as f:
            evidence_dict = json.load(f)
    else:
        # Default to fresh sample evidence bundle
        evidence_dict = create_evidence_pack(use_ed25519=True, signed=True).to_dict()

    audit_res = audit_engine.audit_bundle(evidence_dict, secret_key=args.secret_key)

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, 'w', encoding='utf-8') as f:
            json.dump(audit_res, f, indent=2)
        print(f"[*] Forensic audit report saved to: {args.output}")

    print("=== USENIX Security Forensic Audit Inspection ===")
    print(f"Evidence ID:          {audit_res['evidence_id']}")
    print(f"Forensic Status:      {audit_res['forensic_status']}")
    print(f"Signature Valid:      {audit_res['signature_valid']} ({audit_res['signature_algorithm']}, Key: {audit_res['key_id']})")
    print(f"Merkle Integrity:     {audit_res['merkle_integrity_valid']} (Root: {audit_res['merkle_root_claimed'][:16]}...)")
    print(f"Trace Inclusions:     {audit_res['trace_inclusion_proofs_valid']} ({audit_res['total_traces_inspected']} traces inspected)")
    print(f"Policy Gate Status:   {'PASSED' if audit_res['policy_passed'] else 'BLOCKED'}")

    if audit_res["policy_violations"]:
        print("\nPolicy Violations:")
        for v in audit_res["policy_violations"]:
            print(f"  - {v}")


if __name__ == "__main__":
    main()
