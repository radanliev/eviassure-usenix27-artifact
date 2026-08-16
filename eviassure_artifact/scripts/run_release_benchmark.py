#!/usr/bin/env python3
"""
Empirical Release Assurance Benchmark Runner for USENIX Security 2027.
Measures packaging latency, multi-process verifier throughput, Merkle scaling,
sparse inclusion proof costs, blinding overhead, UI attestation hashing costs,
and 12-vector tamper resilience.
"""

import sys
import time

import yaml
import json
import uuid
import statistics
import concurrent.futures
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Any, List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import (EvidenceBundle, create_evidence_pack, ExecutionTraceRecord,
                                DEMO_PRIV_KEY, DEMO_PUB_KEY_B64, DEFAULT_SECRET_KEY,
                                realistic_dom_fragment)
from assurance.crypto import hash_sha256, build_merkle_tree, generate_merkle_proof, verify_merkle_proof
from assurance.policy import ReleasePolicyEngine
from benchmark.tamper_vectors import generate_tampered_evidence_suite

# N14: the throughput benchmark must measure a WARM policy engine. Each worker
# process lazily loads the engine once from YAML and reuses it for every task;
# the per-task re-parse the earlier benchmark did inflated cold-start cost and
# did not represent steady-state verification.
_ENGINE_CACHE: Dict[str, ReleasePolicyEngine] = {}


def _cpu_model() -> str:
    """Best-effort CPU model string (Darwin and Linux); falls back to 'unknown'."""
    try:
        if sys.platform == "darwin":
            import subprocess
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, check=True, timeout=5
            ).stdout.strip()
            return out or "unknown"
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def _get_engine(policy_path: str) -> ReleasePolicyEngine:
    if policy_path not in _ENGINE_CACHE:
        _ENGINE_CACHE[policy_path] = ReleasePolicyEngine.from_yaml(policy_path)
    return _ENGINE_CACHE[policy_path]


def _eval_worker(task: Tuple[str, Dict[str, Any]]) -> bool:
    policy_path, evidence_dict = task
    engine = _get_engine(policy_path)
    passed, _, _ = engine.evaluate(evidence_dict, seen_nonces=set())
    return passed


def _realistic_dom_fragment(i: int) -> str:
    """A non-stub DOM serialization sample (N8): shared with the web specimen
    via assurance.evidence so the benchmark and the specimen hash the same
    realistic HTML fragment."""
    return realistic_dom_fragment(i)


def measure_merkle_scaling(repeats: int = 5) -> List[Dict[str, Any]]:
    """Packaging latency and Merkle build time per trace count.

    The Merkle tree is built exactly ONCE per repetition and its latency is
    recorded; the bundle is then constructed from that same tree, so the two
    numbers are measured on a single build rather than two redundant ones
    (N15). Packaging latency therefore excludes the (separately reported)
    Merkle construction, and both timings are means over `repeats` runs.
    """
    results = []
    trace_counts = [10, 100, 1000, 10000, 100000, 1000000]

    artifact_digests = {
        "model_weights": hash_sha256("MODEL_WEIGHTS_V1.2"),
        "agent_prompt_spec": hash_sha256("SYSTEM_PROMPT_CONSTRAINED"),
        "policy_definition": hash_sha256("FAIL_CLOSED_POLICY_V1"),
    }

    for count in trace_counts:
        traces = [
            ExecutionTraceRecord(
                trace_id=f"TR-{i:06d}",
                agent_id="agent-worker",
                action="execute_step",
                status="SUCCESS",
                duration_ms=1.5,
                output_hash=hash_sha256(f"OUTPUT_{i}")
            )
            for i in range(count)
        ]
        leaf_hashes = [t.to_hash() for t in traces]
        trace_dicts = [asdict(t) for t in traces]

        pkg_times, merkle_times, sizes = [], [], []
        for _ in range(repeats):
            t1 = time.perf_counter()
            merkle_root, levels = build_merkle_tree(leaf_hashes)
            merkle_times.append((time.perf_counter() - t1) * 1000.0)

            t0 = time.perf_counter()
            bundle = EvidenceBundle(
                evidence_id=f"EVD-{hash_sha256(f'{time.time_ns()}')[:8]}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                nonce=str(uuid.uuid4()),
                agent_system_version="v1.2.0-release",
                test_pass_pct=100.0,
                unresolved_drift=0,
                execution_traces_count=len(traces),
                merkle_root=merkle_root,
                traces=trace_dicts,
                artifact_digests=artifact_digests,
            )
            bundle.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
            pkg_times.append((time.perf_counter() - t0) * 1000.0)

            sizes.append(len(json.dumps(bundle.to_dict())) / 1024.0)

        t_pkg = statistics.mean(pkg_times)
        t_merkle = statistics.mean(merkle_times)

        results.append({
            "trace_count": count,
            "packaging_latency_ms": round(t_pkg, 3),
            "packaging_latency_ms_std": round(statistics.stdev(pkg_times), 3) if repeats > 1 else 0.0,
            "packaging_excludes_merkle_build": True,
            "merkle_tree_build_ms": round(t_merkle, 3),
            "merkle_tree_build_ms_std": round(statistics.stdev(merkle_times), 3) if repeats > 1 else 0.0,
            "merkle_tree_depth": len(levels),
            "bundle_size_kb": round(statistics.mean(sizes), 2),
            "packaging_overhead_pct": round((t_pkg / (count * 1.5)) * 100.0, 4)
        })

    return results


def measure_parallel_throughput(repeats: int = 5) -> Dict[str, Any]:
    policy_path = str(Path(__file__).parent.parent / "governance" / "release_policy.yaml")

    workers_list = [1, 2, 4, 8, 16]
    total_evals = 1000
    parallel_results = {}

    # N14: each evaluation is an honest gate check. We generate `total_evals`
    # DISTINCT, freshly signed bundles up front (unique nonce each) so the
    # timed region measures steady-state policy evaluation, not evidence
    # creation; no evaluation replays another's nonce. The engine itself is
    # warm (loaded once per worker process). Replay-path cost is exercised
    # separately in the tamper suite (V4), not conflated with throughput.
    unique_bundles = [
        create_evidence_pack(use_ed25519=True, signed=True).to_dict()
        for _ in range(total_evals)
    ]
    assert len({b["nonce"] for b in unique_bundles}) == total_evals, "bundles must carry distinct nonces"

    for num_workers in workers_list:
        tasks = [(policy_path, b_dict) for b_dict in unique_bundles]
        rates = []
        elapsed_s = 0.0
        for _ in range(repeats):
            t0 = time.perf_counter()

            with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
                list(executor.map(_eval_worker, tasks))

            elapsed_s = time.perf_counter() - t0
            rates.append(total_evals / elapsed_s if elapsed_s > 0 else 0.0)

        ops_per_sec = statistics.mean(rates)

        parallel_results[f"workers_{num_workers}"] = {
            "num_workers": num_workers,
            "total_evaluations": total_evals,
            "elapsed_seconds": round(elapsed_s, 4),
            "throughput_ops_sec": round(ops_per_sec, 2),
            "throughput_ops_sec_std": round(statistics.stdev(rates), 2) if repeats > 1 else 0.0,
            "mean_latency_per_eval_ms": round((elapsed_s / total_evals) * 1000.0, 4),
            "distinct_nonce_bundles": True,
            "warm_engine": True,
        }

    return parallel_results


def measure_sparse_proof(n_traces: int = 1_000_000, repeats: int = 5) -> Dict[str, Any]:
    """Sparse Merkle inclusion proof generation/verification cost at scale.

    Proof sizes and node counts are deterministic (fixed tree geometry); the
    generation and verification latencies are means over `repeats` runs.
    """
    traces = [
        ExecutionTraceRecord(
            trace_id=f"TR-{i:06d}", agent_id="agent-worker", action="execute_step",
            status="SUCCESS", duration_ms=1.5, output_hash=hash_sha256(f"OUTPUT_{i}")
        )
        for i in range(n_traces)
    ]
    leaves = [t.to_hash() for t in traces]
    root, levels = build_merkle_tree(leaves)

    gen_ms, ver_ms, sizes_kb = [], [], []
    for _ in range(repeats):
        for idx in (0, n_traces // 2, n_traces - 1):
            t0 = time.perf_counter()
            proof = generate_merkle_proof(idx, levels)
            gen_ms.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            ok = verify_merkle_proof(leaves[idx], proof, root,
                                     expected_depth=max(len(levels) - 1, 0))
            ver_ms.append((time.perf_counter() - t0) * 1000.0)
            assert ok, "inclusion proof failed verification"

            sizes_kb.append(len(json.dumps(proof)) / 1024.0)

    return {
        "trace_count": n_traces,
        "tree_depth": len(levels),
        "proof_nodes": len(proof),
        "proof_size_kb": round(statistics.mean(sizes_kb), 3),
        "gen_latency_ms": round(statistics.mean(gen_ms), 4),
        "gen_latency_ms_std": round(statistics.stdev(gen_ms), 4) if repeats > 1 else 0.0,
        "verify_latency_ms": round(statistics.mean(ver_ms), 4),
        "verify_latency_ms_std": round(statistics.stdev(ver_ms), 4) if repeats > 1 else 0.0,
        "repeats": repeats,
    }


def measure_blinding_overhead(n_traces: int = 10_000, repeats: int = 5) -> Dict[str, Any]:
    """Per-record cost of salted HMAC parameter blinding (blind_payload)."""
    salt = "s" * 32
    records = [
        ExecutionTraceRecord(
            trace_id=f"T{i}", agent_id="agent-worker", action="execute_step",
            status="SUCCESS", duration_ms=1.0, output_hash=hash_sha256(f"PII_PAYLOAD_{i}")
        )
        for i in range(n_traces)
    ]
    totals = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        blinded = [r.blind_payload(salt) for r in records]
        totals.append((time.perf_counter() - t0) * 1000.0)

    total_ms = statistics.mean(totals)

    return {
        "trace_count": n_traces,
        "total_ms": round(total_ms, 2),
        "total_ms_std": round(statistics.stdev(totals), 2) if repeats > 1 else 0.0,
        "per_record_ms": round(total_ms / n_traces, 5),
        "repeats": repeats,
    }


def measure_ui_attestation_hashing(n_steps: int = 1_000, repeats: int = 5) -> Dict[str, Any]:
    """Cost of the DOM serialization digest and screenshot digest per UI step.

    Mirrors specimens/web_app_runner.py: deterministic HTML serialization is
    SHA-256 hashed for DOM state, and the screenshot digest is computed over
    the canonical render reference string.
    """
    dom_steps, shot_steps = [], []
    for _ in range(repeats):
        t0 = time.perf_counter()
        for i in range(n_steps):
            dom = _realistic_dom_fragment(i)
            hash_sha256(dom)
        dom_steps.append(((time.perf_counter() - t0) * 1000.0) / n_steps)

        t0 = time.perf_counter()
        for i in range(n_steps):
            hash_sha256(f"SCREENSHOT_PNG_CLICK_btn-{i}")
        shot_steps.append(((time.perf_counter() - t0) * 1000.0) / n_steps)

    return {
        "ui_steps": n_steps,
        "dom_hash_ms_per_step": round(statistics.mean(dom_steps), 5),
        "dom_hash_ms_per_step_std": round(statistics.stdev(dom_steps), 5) if repeats > 1 else 0.0,
        "screenshot_digest_ms_per_step": round(statistics.mean(shot_steps), 5),
        "screenshot_digest_ms_per_step_std": round(statistics.stdev(shot_steps), 5) if repeats > 1 else 0.0,
        "repeats": repeats,
    }


def evaluate_ablation() -> Dict[str, Any]:
    """Per-check ablation: disable one enforcement at a time and count how
    many of the 12 vectors escape. Marginal contribution of each check.
    """
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    suite = generate_tampered_evidence_suite()

    variants = [
        ("full_gate", {}, None),
        ("no_signature_check", {"require_signed_evidence": False}, None),
        ("no_key_registry", {"require_trusted_key": False}, None),
        ("no_crl", {}, "empty_crl"),
        ("no_kms_arn_bound", {"kms_key_arn_pattern": None}, None),
        ("no_merkle_check", {"verify_merkle_root": False}, None),
        ("no_count_binding", {"enforce_trace_count": False}, None),
        ("no_quality_gate", {"min_passing_tests_pct": 0.0}, None),
        ("no_drift_gate", {"allowed_drift_findings": 999}, None),
        ("no_freshness", {"max_evidence_age_seconds": 10**9,
                           "max_future_clock_skew_seconds": 10**9}, None),
        ("no_replay_cache", {}, "no_nonce_state"),
    ]

    rows = []
    for label, conds, attr in variants:
        # from_yaml so every variant carries the real trusted-key registry
        engine = ReleasePolicyEngine.from_yaml(policy_path)
        engine.release_conditions.update(conds)
        if attr == "empty_registry":
            engine.trusted_keys = {}
        elif attr == "empty_crl":
            engine.revoked_key_ids = set()

        blocked = 0
        escaped = []
        seen_nonces = set()
        for vid, meta, ev in suite:
            test_nonces = seen_nonces.copy()
            if vid == "V4_REPLAYED_NONCE":
                test_nonces.add(ev["nonce"])
            use_nonces = None if attr == "no_nonce_state" else test_nonces
            passed, _, _ = engine.evaluate(ev, seen_nonces=use_nonces)
            if not passed:
                blocked += 1
            else:
                escaped.append(meta["id"])
        rows.append({"variant": label, "blocked": blocked, "escaped_vectors": escaped})

    return {"note": "one enforcement disabled per row; full_gate is the configured gate",
            "rows": rows}


def evaluate_tamper_resilience() -> Dict[str, Any]:
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)
    suite = generate_tampered_evidence_suite()

    vector_results = []
    blocked_count = 0

    seen_nonces = set()

    for vector_id, meta, tampered_evidence in suite:
        test_seen_nonces = seen_nonces.copy()
        if vector_id == "V4_REPLAYED_NONCE":
            test_seen_nonces.add(tampered_evidence["nonce"])

        t0 = time.perf_counter()
        passed, violations, details = policy_engine.evaluate(
            evidence=tampered_evidence,
            seen_nonces=test_seen_nonces
        )
        eval_ms = (time.perf_counter() - t0) * 1000.0

        if not passed:
            blocked_count += 1

        vector_results.append({
            "id": meta["id"],
            "name": meta["name"],
            "category": meta["category"],
            "passed": passed,
            "blocked": not passed,
            "violations": violations,
            "eval_latency_ms": round(eval_ms, 3)
        })

    block_rate = (blocked_count / len(suite)) * 100.0

    return {
        "total_vectors": len(suite),
        "blocked_vectors": blocked_count,
        "fail_closed_block_rate_pct": round(block_rate, 2),
        "vector_details": vector_results
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5,
                        help="number of repetition runs for timed measurements "
                             "(deterministic checks such as the tamper suite run once)")
    args = parser.parse_args()
    repeats = max(1, args.repeats)

    print(f"=== Running USENIX Security Release Assurance Empirical Benchmark "
          f"(repeats={repeats}) ===")

    print("\n1. Measuring Merkle Tree & Packaging Scaling (up to N=100,000)...")
    merkle_scaling = measure_merkle_scaling(repeats)
    for row in merkle_scaling:
        print(f"   Traces: {row['trace_count']:6d} | Pkg Latency: {row['packaging_latency_ms']:7.2f} ms | Merkle Build: {row['merkle_tree_build_ms']:6.2f} ms | Bundle: {row['bundle_size_kb']:8.2f} KB | Overhead: {row['packaging_overhead_pct']:.4f}%")

    print("\n2. Measuring Multi-Process Parallel Verifier Throughput...")
    parallel_throughput = measure_parallel_throughput(repeats)
    for k, v in parallel_throughput.items():
        print(f"   Workers: {v['num_workers']:2d} | Total Evals: {v['total_evaluations']} | Time: {v['elapsed_seconds']}s | Throughput: {v['throughput_ops_sec']} ops/sec")

    print("\n3. Measuring Sparse Merkle Inclusion Proof Costs (N=1,000,000)...")
    sparse_proof = measure_sparse_proof(repeats=repeats)

    print("\n4. Measuring Salted Parameter Blinding Overhead (N=10,000)...")
    blinding = measure_blinding_overhead(repeats=repeats)

    print("\n5. Measuring Browser UI Attestation Hashing Costs (1,000 steps)...")
    ui_hashing = measure_ui_attestation_hashing(repeats=repeats)

    print("\n6. Evaluating 12-Vector Adversarial Release Tamper Resilience Suite...")
    tamper_res = evaluate_tamper_resilience()
    print(f"   Fail-Closed Block Rate: {tamper_res['fail_closed_block_rate_pct']}% ({tamper_res['blocked_vectors']}/{tamper_res['total_vectors']} blocked)")
    for v in tamper_res["vector_details"]:
        status_str = "PASS (BLOCKED)" if v["blocked"] else "FAIL (UNBLOCKED)"
        print(f"   [{v['id']:3s}] {v['name']:45s} -> {status_str}")

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {
            "python_version": sys.version.split()[0],
            "logical_cores": __import__("os").cpu_count(),
            "cpu_model": _cpu_model(),
        },
        "benchmark_params": {
            "synthetic_step_duration_ms": 1.5,
            "throughput_evals_per_worker": 1000,
            "repeats": repeats,
        },
        "disclosures": {
            "packaging_latency_excludes_merkle_build": (
                "packaging_latency_ms times the post-Merkle packaging path "
                "(bundle construction, signing, serialization); Merkle tree "
                "construction is reported separately as merkle_tree_build_ms "
                "from the same single build (N15)."),
            "packaging_overhead_pct": (
                "synthetic ratio: packaging_latency_ms divided by the assumed "
                "1.5 ms/step trace execution time (count * 1.5 ms); it is an "
                "order-of-magnitude illustration, not a production cost model "
                "(N11)."),
            "throughput": (
                "each evaluation is a distinct fresh-nonce bundle against a "
                "warm policy engine; replay-state cost is measured separately "
                "in the tamper suite, not here (N14)."),
            "ui_attestation_hashing": (
                "DOM hashing uses a realistic multi-node HTML fragment with "
                "attributes and per-step dynamic content, mirroring the web "
                "specimen; it is not the empty stub from the earlier "
                "prototype (N8)."),
        },
        "merkle_scaling": merkle_scaling,
        "parallel_throughput": parallel_throughput,
        "sparse_proof": sparse_proof,
        "blinding_overhead": blinding,
        "ui_attestation_hashing": ui_hashing,
        "tamper_resilience": tamper_res,
        "ablation": evaluate_ablation()
    }

    out_file = Path(__file__).parent.parent / "results" / "benchmark_summary.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Empirical benchmark summary saved to: {out_file}")


if __name__ == "__main__":
    main()
