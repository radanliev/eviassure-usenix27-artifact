#!/usr/bin/env python3
"""
USENIX Security Paper PDF Builder & Multi-Plot Figure Generator for Demo 5.
"""

import sys
import shutil
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.run_release_benchmark import main as run_benchmark
from scripts.run_comparative_eval import main as run_comparative_eval


def generate_benchmark_figures(docs_dir: Path):
    import matplotlib.pyplot as plt
    import json

    res_dir = docs_dir.parent / "results"
    b_file = res_dir / "benchmark_summary.json"
    c_file = res_dir / "comparative_evaluation.json"

    if not b_file.exists():
        run_benchmark()
    if not c_file.exists():
        run_comparative_eval()

    with open(b_file, 'r', encoding='utf-8') as f:
        data_b = json.load(f)
    with open(c_file, 'r', encoding='utf-8') as f:
        data_c = json.load(f)

    fig_dir = docs_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    # Figure 1: Merkle Tree Scaling up to 100K traces
    scaling = data_b["merkle_scaling"]
    traces = [s["trace_count"] for s in scaling]
    pkg_lat = [s["packaging_latency_ms"] for s in scaling]
    merkle_build = [s["merkle_tree_build_ms"] for s in scaling]
    pkg_err = [s.get("packaging_latency_ms_std", 0.0) for s in scaling]
    merkle_err = [s.get("merkle_tree_build_ms_std", 0.0) for s in scaling]

    plt.figure(figsize=(3.4, 2.6))
    plt.errorbar(traces, pkg_lat, yerr=pkg_err, fmt='o-', color='#1f77b4',
                 linewidth=1.5, capsize=2, label='Packaging Latency (ms)')
    plt.errorbar(traces, merkle_build, yerr=merkle_err, fmt='s--', color='#d62728',
                 linewidth=1.5, capsize=2, label='Merkle Build Time (ms)')
    plt.xscale('log')
    plt.yscale('log')
    plt.tick_params(labelsize=8)
    plt.xlabel('Trace Count N (log scale)', fontsize=9)
    plt.ylabel('Time (ms, log scale)', fontsize=9)
    plt.title('Attestation Scaling up to N=1,000,000 Traces', fontsize=8.5, fontweight='bold')
    plt.grid(True, which="both", ls="--", alpha=0.5)
    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(fig_dir / "merkle_scaling.png", dpi=300)
    plt.close()

    # Figure 2: Multi-Process Parallel Throughput
    p_tp = data_b["parallel_throughput"]
    workers = [v["num_workers"] for v in p_tp.values()]
    ops = [v["throughput_ops_sec"] for v in p_tp.values()]
    ops_err = [v.get("throughput_ops_sec_std", 0.0) for v in p_tp.values()]

    plt.figure(figsize=(3.4, 2.6))
    plt.bar([str(w) + 'w' for w in workers], ops, yerr=ops_err, capsize=2,
            color='#2ca02c', width=0.5, edgecolor='black', linewidth=0.8)
    plt.tick_params(labelsize=8)
    plt.xlabel('Process Pool Size (workers)', fontsize=9)
    plt.ylabel('Verifier Throughput (ops/sec)', fontsize=9)
    plt.title('Multi-Core Parallel Verification Throughput', fontsize=9, fontweight='bold')
    plt.ylim(0, max(ops) * 1.25)
    plt.grid(axis='y', ls="--", alpha=0.5)
    for i, v in enumerate(ops):
        plt.text(i, v + 100, f"{int(v)}/s", ha='center', fontweight='bold', fontsize=8)
    plt.tight_layout()
    plt.savefig(fig_dir / "parallel_throughput.png", dpi=300)
    plt.close()

    # Figure 3: Comparative Tamper Detection Block Rates
    comp_sum = data_c["summary"]
    systems = ['Standard CI Gate', 'OPA Schema Gate', 'Sigstore / Cosign', 'EviAssure']
    block_rates = [
        comp_sum["ci_exit_code_block_rate_pct"],
        comp_sum["opa_schema_block_rate_pct"],
        comp_sum["sigstore_cosign_block_rate_pct"],
        comp_sum["demo5_assurance_block_rate_pct"]
    ]
    colors = ['#d62728', '#ff7f0e', '#bcbd22', '#1f77b4']

    plt.figure(figsize=(3.4, 2.6))
    bars = plt.bar(systems, block_rates, color=colors, edgecolor='black', linewidth=1.0, width=0.5)
    hatches = ['//', '\\\\', 'xx', '..']
    for bar, hatch in zip(bars, hatches):
        bar.set_hatch(hatch)
    plt.tick_params(labelsize=7)
    plt.xticks(rotation=20, ha='right')
    plt.ylabel('Fail-Closed Block Rate (%)', fontsize=9)
    plt.title('Adversarial Release Tamper Detection (12 Vectors)', fontsize=9, fontweight='bold')
    plt.ylim(0, 115)
    plt.grid(axis='y', ls="--", alpha=0.5)
    for bar, rate in zip(bars, block_rates):
        plt.text(bar.get_x() + bar.get_width() / 2.0, rate + 2.0, f"{rate:.1f}%", ha='center', fontweight='bold', fontsize=8)
    plt.tight_layout()
    plt.savefig(fig_dir / "comparative_block_rate.png", dpi=300)
    plt.close()

    print(f"[+] Benchmark figures saved to: {fig_dir}")



def write_frozen_metrics(res_dir, docs_dir):
    """Emit the headline numbers as LaTeX macros the manuscript \\input{}s.

    The benchmark re-runs on every build, so any figure typed into the abstract
    by hand is stale the moment the next build finishes. Three different values
    for the same throughput measurement were in circulation before this existed.
    Defining them here means the number in the paper IS the number in the
    artifact, by construction, and cannot drift.
    """
    import json
    b = json.loads((res_dir / "benchmark_summary.json").read_text())
    tp = b["parallel_throughput"]
    best_k = max(tp, key=lambda k: tp[k]["throughput_ops_sec"])
    best = tp[best_k]
    single = tp["workers_1"]
    n1m = next(r for r in b["merkle_scaling"] if r["trace_count"] == 1000000)
    n100 = next(r for r in b["merkle_scaling"] if r["trace_count"] == 100000)
    sp = b["sparse_proof"]
    bl = b["blinding_overhead"]
    ui = b["ui_attestation_hashing"]
    peak_ratio = best["throughput_ops_sec"] / single["throughput_ops_sec"]
    out = docs_dir / "frozen_metrics.tex"
    out.write_text(
        "% GENERATED by scripts/generate_paper_pdf.py -- do not edit by hand.\n"
        "% Regenerated from results/benchmark_summary.json on every build.\n"
        "% Every benchmark-derived numeral cited in the prose is a macro here,\n"
        "% so a benchmark re-run can never leave a stale number in the text.\n"
        f"\\newcommand{{\\benchRepeats}}{{{b['benchmark_params'].get('repeats', 5)}}}\n"
        f"\\newcommand{{\\peakThroughput}}{{{best['throughput_ops_sec']:,.0f}}}\n"
        f"\\newcommand{{\\peakThroughputStd}}{{{best.get('throughput_ops_sec_std', 0):,.0f}}}\n"
        f"\\newcommand{{\\peakWorkers}}{{{best['num_workers']}}}\n"
        f"\\newcommand{{\\singleWorkerThroughput}}{{{single['throughput_ops_sec']:,.0f}}}\n"
        f"\\newcommand{{\\peakRatio}}{{{peak_ratio:.1f}}}\n"
        f"\\newcommand{{\\merkleBuildMs}}{{{n100['merkle_tree_build_ms']:.1f}}}\n"
        f"\\newcommand{{\\merkleBuildOneMMs}}{{{n1m['merkle_tree_build_ms']:.2f}}}\n"
        f"\\newcommand{{\\merkleBuildOneMStd}}{{{n1m.get('merkle_tree_build_ms_std', 0):.2f}}}\n"
        f"\\newcommand{{\\packagingOverhead}}{{{n100['packaging_overhead_pct']:.4f}}}\n"
        f"\\newcommand{{\\sparseProofNodes}}{{{sp['proof_nodes']}}}\n"
        f"\\newcommand{{\\sparseProofSizeKb}}{{{sp['proof_size_kb']:.2f}}}\n"
        f"\\newcommand{{\\sparseProofGenMs}}{{{sp['gen_latency_ms']:.3f}}}\n"
        f"\\newcommand{{\\sparseProofVerifyMs}}{{{sp['verify_latency_ms']:.3f}}}\n"
        f"\\newcommand{{\\blindingPerRecordMs}}{{{bl['per_record_ms']:.4f}}}\n"
        f"\\newcommand{{\\blindingTotalMs}}{{{bl['total_ms']:.1f}}}\n"
        f"\\newcommand{{\\domHashMs}}{{{ui['dom_hash_ms_per_step']:.4f}}}\n"
        f"\\newcommand{{\\shotDigestMs}}{{{ui['screenshot_digest_ms_per_step']:.4f}}}\n"
        f"\\newcommand{{\\benchTimestamp}}{{{b.get('timestamp', 'unknown')}}}\n")
    print(f"[*] Froze headline metrics -> {out.name} "
          f"(throughput={best['throughput_ops_sec']:,.0f}, "
          f"overhead={n100['packaging_overhead_pct']:.3f}%)")
    return out

def compile_latex_pdf(docs_dir: Path) -> Path:
    tex_file = docs_dir / "usenix_paper_manuscript.tex"
    pdflatex_bin = (shutil.which("pdflatex") or (shutil.which("pdflatex") or "/Library/TeX/texbin/pdflatex"))
    bibtex_bin = (shutil.which("bibtex") or "/Library/TeX/texbin/bibtex")

    print(f"[*] Compiling LaTeX manuscript: {tex_file.name} using pdflatex...")

    # First pdflatex pass
    subprocess.run(
        [pdflatex_bin, "-interaction=nonstopmode", tex_file.name],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # BibTeX pass
    subprocess.run(
        [bibtex_bin, "usenix_paper_manuscript"],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Second & Third pdflatex passes
    subprocess.run(
        [pdflatex_bin, "-interaction=nonstopmode", tex_file.name],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    subprocess.run(
        [pdflatex_bin, "-interaction=nonstopmode", tex_file.name],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    pdf_path = docs_dir / "usenix_paper_manuscript.pdf"
    if pdf_path.exists():
        print(f"[SUCCESS] Compiled USENIX Security paper PDF: {pdf_path}")
        return pdf_path
    else:
        raise RuntimeError("PDF compilation failed to produce output file.")


def main():
    docs_dir = Path(__file__).parent.parent / "docs"
    
    print("=== USENIX Security Paper PDF Builder & Figure Generator ===")
    
    try:
        generate_benchmark_figures(docs_dir)
    except Exception as e:
        print(f"[!] Warning: Figure generation error ({e})")

    write_frozen_metrics(Path(__file__).parent.parent / "results", docs_dir)
    pdf_path = compile_latex_pdf(docs_dir)
    print(f"\n[+] PDF generation complete: {pdf_path}")


if __name__ == "__main__":
    main()
