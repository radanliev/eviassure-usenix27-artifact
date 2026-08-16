# EviAssure: Reproduction & Artifact Evaluation Guide

This artifact package provides full reproduction materials for the paper **"EviAssure: Evidence-Backed Release Assurance for Autonomous Agent Deployments"** (USENIX Security 2027 Submission ID: `EVI-227`).

---

## 1. System Requirements & Environment Setup

- **Python**: Python >= 3.10 (tested on Python 3.13)
- **LaTeX Distribution**: `pdflatex` & `bibtex` (e.g., TeX Live / MacTeX)
- **Dependencies**: `pytest`, `pyyaml`, `matplotlib`, `cryptography`

### Installation Commands

```bash
# Clone or extract artifact archive
cd demo-5-evidence-release-assurance-usenix

# Install Python dependencies
pip install -e .
```

---

## 2. Test Suite & Cryptographic Attestation Verification

To execute the unit and integration test suite (18 tests covering Ed25519 signing, Merkle tree inclusion, SLSA predicate formatting, privacy blinding, and 12-vector tamper resilience):

```bash
pytest tests/ -v
```

Expected output: `18 passed in ~0.3s`.

---

## 3. Empirical Benchmarks & Figure Generation

To re-run the empirical microbenchmarks ($N=1,000,000$ trace scaling, 16-worker multi-core parallel verifier throughput, and 12-vector tamper resilience evaluation):

```bash
# Step 1: Run release assurance scaling and throughput benchmarks
python3 scripts/run_release_benchmark.py

# Step 2: Run comparative baseline evaluations (CI exit codes, OPA, Sigstore/Cosign vs EviAssure)
python3 scripts/run_comparative_eval.py

# Step 3: Generate paper figures and compile PDF manuscript
python3 scripts/generate_paper_pdf.py
```

---

## 4. Deterministic Gate & Anonymization Audit

To run the deterministic USENIX paper loop gates and verify page geometry, font sizes, and metric consistency:

```bash
python3 .paperloop/run_gates.py --build --render
```

Output:
- Gate report saved to `.paperloop/state/FINDINGS.md`.
- PDF manuscript compiled to `docs/usenix_paper_manuscript.pdf`.
