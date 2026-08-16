#!/usr/bin/env python3
"""
Cryptographic Evidence Packaging Helper for USENIX Security Release Assurance.
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import create_evidence_pack, DEFAULT_SECRET_KEY


def main():
    parser = argparse.ArgumentParser(description="Package and sign cryptographic evidence bundle.")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output JSON file path")
    parser.add_argument("--secret-key", type=str, default=DEFAULT_SECRET_KEY, help="HMAC secret key")
    parser.add_argument("--pass-pct", type=float, default=100.0, help="Test pass percentage")
    parser.add_argument("--drift", type=int, default=0, help="Unresolved drift findings count")
    parser.add_argument("--unsigned", action="store_true", help="Generate unsigned evidence pack")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output display format")
    args = parser.parse_args()

    bundle = create_evidence_pack(
        test_pass_pct=args.pass_pct,
        unresolved_drift=args.drift,
        secret_key=args.secret_key,
        signed=not args.unsigned
    )

    pack_dict = bundle.to_dict()

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, 'w', encoding='utf-8') as f:
            json.dump(pack_dict, f, indent=2)
        print(f"[*] Sealed evidence bundle written to: {args.output}")

    if args.format == "json":
        print(json.dumps(pack_dict, indent=2))
    else:
        print("=== Cryptographic Evidence Bundle Summary ===")
        print(f"Evidence ID: {bundle.evidence_id}")
        print(f"Timestamp:   {bundle.timestamp}")
        print(f"Merkle Root: {bundle.merkle_root[:16]}...")
        print(f"Traces:      {bundle.execution_traces_count}")
        print(f"Pass Pct:    {bundle.test_pass_pct}%")
        print(f"Drift Count: {bundle.unresolved_drift}")
        print(f"Signed:      {bundle.signed}")
        if bundle.signature:
            print(f"Signature:   {bundle.signature[:16]}...")


if __name__ == "__main__":
    main()
