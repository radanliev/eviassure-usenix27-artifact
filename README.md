# Demo 5: Evidence-Backed Release Assurance for Agentic Systems

[![USENIX Security Target](https://img.shields.io/badge/Research--Target-USENIX%20Security%202027-blue.svg)](https://www.usenix.org/conference/usenixsecurity27)
[![Paper PDF](https://img.shields.io/badge/Paper-USENIX%20Security%20PDF-red.svg)](docs/usenix_paper_manuscript.pdf)
[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen.svg)]()
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

> **Blind-Verification Research & Teaching Portfolio**  
> *Target Venue:* USENIX Security Symposium (USENIX Security 2027)  
> *Primary Focus:* Cryptographic trace attestation (SHA-256 Merkle trees), Ed25519/HMAC digital evidence packaging, fail-closed zero-trust policy gate verification, and tamper resilience audit infrastructure.

---

## 📌 Executive Summary

Autonomous agentic deployments require reproducible, cryptographically verifiable evidence before releasing model updates, expanding tool execution privileges, or authorizing automated workflow triggers in production. Relying on unauthenticated CI build logs or self-reported status labels exposes release pipelines to runner tampering, trace forgery, and evidence replay attacks.

**Demo 5** delivers a complete **USENIX Security 2027 Systems Security Framework**:
- **Cryptographic Attestation Engine** (`assurance/crypto.py`): Condenses $N$ agent execution traces into a SHA-256 Merkle tree root with $O(\log N)$ audit inclusion proof verification.
- **Sealed Evidence Bundler** (`assurance/evidence.py`, `scripts/package_evidence.py`): Generates Ed25519/HMAC-signed `EvidenceBundle` instances with nonces and timestamps for replay protection.
- **Fail-Closed Policy Engine** (`assurance/policy.py`, `scripts/verify_release_gate.py`): Enforces multi-factor release conditions against `governance/release_policy.yaml`.
- **Adversarial Release Tamper Suite** (`benchmark/tamper_vectors.py`, `tests/test_tamper_resilience.py`): Evaluates 8 distinct release tamper attack vectors.
- **Empirical Benchmark & Paper Generator** (`scripts/run_release_benchmark.py`, `scripts/generate_paper_pdf.py`): Measures packaging latency, verifier throughput, and compiles the official USENIX Security 2027 paper manuscript to PDF (`docs/usenix_paper_manuscript.pdf`).

---

## 📊 Measured Benchmark Results

| Metric / Experiment | Result | Benchmark Details |
| :--- | :---: | :--- |
| **Fail-Closed Block Rate** | **100.0%** | **8 / 8** adversarial tamper vectors blocked (`V1` to `V8`) |
| **Verifier Throughput** | **79,546 ops/sec** | Mean evaluation latency **0.0126 ms** (P95: 0.0156 ms) |
| **Merkle Tree Packaging ($N=10,000$)** | **3.94 ms** | Scalable trace attestation for enterprise agent workloads |
| **Test Suite Coverage** | **10/10 PASS** | 100% pass rate across cryptographic, policy, and tamper tests |

---

## 🎓 Course Integration Runbooks

### Newcastle University — Practical 5
- **Practical Title:** Evidence-Backed Release Assurance & Deployment Gates
- **Learning Outcome:** Package evidence bundles, evaluate policy gates, and enforce fail-closed release controls.
- **Runbook Command:**
  ```bash
  python3 scripts/verify_release_gate.py --policy governance/release_policy.yaml --format text
  ```

### O'Reilly Bootcamp — Session 5
- **Session Title:** Release Gates & Cryptographic Evidence Bundling for AI Agents
- **Bootcamp Goal:** Generate sealed evidence packs, execute release policy validation, and verify audit compliance.
- **Live Specimen:**
  ```bash
  python3 scripts/package_evidence.py --output evidence_pack.json
  ```

### Pearson Video Course — Module 5
- **Module Title:** Module 5 — End-to-End Release Assurance & Policy Gates
- **Lab Exercise:** Execute the USENIX Security release gate suite and confirm release gate passes.
- **On-Screen Command:**
  ```bash
  pytest tests/ -v
  ```

---

## 🚀 Quickstart & Reproduction

1. **Install Dependencies:**
   ```bash
   pip install -r pyproject.toml
   ```

2. **Run Test Suite:**
   ```bash
   pytest tests/ -v
   ```

3. **Run Empirical Benchmark Suite:**
   ```bash
   python3 scripts/run_release_benchmark.py
   ```

4. **Verify Release Gate (Fail-Closed Default):**
   ```bash
   python3 scripts/verify_release_gate.py
   ```

5. **Generate Benchmark Figures & Paper PDF:**
   ```bash
   python3 scripts/generate_paper_pdf.py
   # Outputs compiled PDF to docs/usenix_paper_manuscript.pdf
   ```

## 🤝 Multi-Agent Paper Workflow

The paperloop can run a read-only evaluator and an independent analytical
auditor in parallel before the writer receives their combined work order. The
role contracts, Antigravity copy/paste prompts, human data handoff, and stopping
criteria are in [`docs/AGENT_WORKFLOW.md`](docs/AGENT_WORKFLOW.md).

---

## 📄 Academic Citation & Paper

Manuscript PDF: [`docs/usenix_paper_manuscript.pdf`](docs/usenix_paper_manuscript.pdf)

```bibtex
@inproceedings{radanliev2027usenix,
  title={Evidence-Backed Release Assurance for Autonomous Agent Deployments: Cryptographic Attestation, Fail-Closed Gates, and Tamper-Resilient Audit Infrastructure},
  author={Radanliev, Petar and Gross, Thomas and Hossain, Md Jakir},
  booktitle={USENIX Security Symposium (USENIX Security 2027)},
  year={2027}
}
```
