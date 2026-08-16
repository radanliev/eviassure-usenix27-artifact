#!/usr/bin/env python3
"""
USENIX Security Release Gate Verifier CLI
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.verifier import evaluate_release_gate
from assurance.evidence import DEFAULT_SECRET_KEY


def main():
    parser = argparse.ArgumentParser(description="Evaluate USENIX Security Fail-Closed Release Gate.")
    parser.add_argument(
        "--policy",
        type=str,
        default=str(Path(__file__).parent.parent / "governance" / "release_policy.yaml"),
        help="Path to policy YAML file"
    )
    parser.add_argument("--evidence", type=str, default=None, help="Path to evidence bundle JSON file")
    parser.add_argument("--secret-key", type=str, default=DEFAULT_SECRET_KEY, help="HMAC secret key")
    parser.add_argument("--output-decision", type=str, default=None, help="Output JSON path for release decision")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()

    evidence_dict = None
    if args.evidence:
        with open(args.evidence, 'r', encoding='utf-8') as f:
            evidence_dict = json.load(f)

    res = evaluate_release_gate(
        policy_path=args.policy,
        evidence=evidence_dict,
        secret_key=args.secret_key,
        output_decision_file=args.output_decision
    )

    if args.format == "json":
        print(json.dumps(res, indent=2))
    else:
        print("=== USENIX Security Release Gate Evaluation ===")
        print(f"Policy:      {res['policy_name']}")
        print(f"Evidence ID: {res['evidence_id']} (Signed: {res['signed']})")
        
        if res["violations"]:
            print("\nPolicy Violations Detected:")
            for v in res["violations"]:
                print(f"  - {v}")
            print()

        if res["passed"]:
            print("STATUS: RELEASE APPROVED (Fail-Closed Gate Passed)")
            sys.exit(0)
        else:
            print("STATUS: RELEASE BLOCKED (Policy Violation)")
            sys.exit(1)


if __name__ == "__main__":
    main()
