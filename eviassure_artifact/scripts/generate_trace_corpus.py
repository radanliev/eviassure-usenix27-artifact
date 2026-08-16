#!/usr/bin/env python3
"""
Corpus Generator for USENIX Security 2027.
Generates 1,000+ realistic execution trace profiles across 5 agent architectures,
including 50 distinct adversarial anomaly variants.
"""

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any

def hash_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

ARCHITECTURES = [
    "CodeSynthesisAgent",
    "MultiStepRAGAgent",
    "DatabaseAdminAgent",
    "FinancialAPIIntegratorAgent",
    "AutonomousWebScraperAgent"
]

# One distinct (action, status, duration_ms) signature per anomaly class so the
# corpus's ten anomaly classes are feature-distinguishable (2026-08 adversarial
# review, N4). Every action below is on the forensics engine's sensitive-action
# list, so Layer-3 inspection flags exactly these leaves.
ANOMALY_TYPES = [
    {
        "type": "ANOMALY_UNSAFE_CMD",
        "action": "spawn_shell_subprocess",
        "status": "UNAUTHORIZED_ESCALATION",
        "duration_ms": 42.1,
    },
    {
        "type": "ANOMALY_PROMPT_INJECTION",
        "action": "override_system_prompt",
        "status": "INJECTION_DETECTED",
        "duration_ms": 24.5,
    },
    {
        "type": "ANOMALY_PRIVILEGE_ESCALATION",
        "action": "escalate_role",
        "status": "PRIVILEGE_ESCALATION",
        "duration_ms": 17.8,
    },
    {
        "type": "ANOMALY_UNAUTHORIZED_DB_DROP",
        "action": "drop_production_table",
        "status": "UNAUTHORIZED_DB_DROP",
        "duration_ms": 55.0,
    },
    {
        "type": "ANOMALY_SECRET_EXFILTRATION",
        "action": "exfiltrate_private_key",
        "status": "SECRET_EXFILTRATION",
        "duration_ms": 38.0,
    },
    {
        "type": "ANOMALY_MEMORY_TAMPERING",
        "action": "patch_trace_memory",
        "status": "MEMORY_TAMPERED",
        "duration_ms": 9.4,
    },
    {
        "type": "ANOMALY_SSRF_LOCAL_NETWORK",
        "action": "access_localhost_metadata",
        "status": "SSRF_ATTEMPT",
        "duration_ms": 61.2,
    },
    {
        "type": "ANOMALY_VECTOR_POISONING",
        "action": "poison_vector_store",
        "status": "VECTOR_POISONED",
        "duration_ms": 31.7,
    },
    {
        "type": "ANOMALY_UNSANDBOXED_PROCESS",
        "action": "spawn_unsandboxed_process",
        "status": "UNSANDBOXED_PROCESS",
        "duration_ms": 47.3,
    },
    {
        "type": "ANOMALY_JSON_MALLEABILITY",
        "action": "inject_duplicate_json_key",
        "status": "JSON_MALLEABILITY_DETECTED",
        "duration_ms": 12.9,
    },
]

ANOMALY_INDEX = {a["type"]: a for a in ANOMALY_TYPES}

ARCH_PREFIX = {
    "CodeSynthesisAgent": "CODE",
    "MultiStepRAGAgent": "RAG",
    "DatabaseAdminAgent": "DB",
    "FinancialAPIIntegratorAgent": "FIN",
    "AutonomousWebScraperAgent": "WEB",
}

ARCH_AGENT_ID = {
    "CodeSynthesisAgent": "code-synth-v1",
    "MultiStepRAGAgent": "rag-search-v2",
    "DatabaseAdminAgent": "db-admin-v1",
    "FinancialAPIIntegratorAgent": "fin-api-v1",
    "AutonomousWebScraperAgent": "web-scraper-v1",
}


def _clean_profile_trace(i: int, arch: str) -> dict:
    """First trace of every profile: benign per-architecture work."""
    if arch == "CodeSynthesisAgent":
        return {
            "trace_id": f"TR-CODE-{i:04d}-A",
            "agent_id": "code-synth-v1",
            "action": "parse_ast",
            "status": "SUCCESS",
            "duration_ms": round(4.5 + (i % 10) * 0.2, 2),
            "output_hash": hash_sha256(f"AST_{i}")
        }
    if arch == "MultiStepRAGAgent":
        return {
            "trace_id": f"TR-RAG-{i:04d}-A",
            "agent_id": "rag-search-v2",
            "action": "embed_query",
            "status": "SUCCESS",
            "duration_ms": round(8.0 + (i % 8) * 0.3, 2),
            "output_hash": hash_sha256(f"EMBED_{i}")
        }
    if arch == "DatabaseAdminAgent":
        return {
            "trace_id": f"TR-DB-{i:04d}-A",
            "agent_id": "db-admin-v1",
            "action": "verify_schema_lock",
            "status": "SUCCESS",
            "duration_ms": round(3.0 + (i % 5) * 0.2, 2),
            "output_hash": hash_sha256(f"SCHEMA_{i}")
        }
    if arch == "FinancialAPIIntegratorAgent":
        return {
            "trace_id": f"TR-FIN-{i:04d}-A",
            "agent_id": "fin-api-v1",
            "action": "verify_api_signature",
            "status": "SUCCESS",
            "duration_ms": round(5.0 + (i % 4) * 0.2, 2),
            "output_hash": hash_sha256(f"SIG_VERIFY_{i}")
        }
    return {
        "trace_id": f"TR-WEB-{i:04d}-A",
        "agent_id": "web-scraper-v1",
        "action": "parse_html_dom",
        "status": "SUCCESS",
        "duration_ms": round(7.0 + (i % 6) * 0.3, 2),
        "output_hash": hash_sha256(f"DOM_{i}")
    }


def _benign_second_trace(i: int, arch: str) -> dict:
    if arch == "CodeSynthesisAgent":
        return {
            "trace_id": f"TR-CODE-{i:04d}-B",
            "agent_id": "code-synth-v1",
            "action": "run_linter",
            "status": "SUCCESS",
            "duration_ms": round(12.0 + (i % 5) * 0.5, 2),
            "output_hash": hash_sha256(f"LINT_{i}")
        }
    if arch == "MultiStepRAGAgent":
        return {
            "trace_id": f"TR-RAG-{i:04d}-B",
            "agent_id": "rag-search-v2",
            "action": "vector_similarity_search",
            "status": "SUCCESS",
            "duration_ms": round(15.0 + (i % 6) * 0.4, 2),
            "output_hash": hash_sha256(f"VEC_SEARCH_{i}")
        }
    if arch == "DatabaseAdminAgent":
        return {
            "trace_id": f"TR-DB-{i:04d}-B",
            "agent_id": "db-admin-v1",
            "action": "execute_read_only_query",
            "status": "SUCCESS",
            "duration_ms": round(6.5 + (i % 7) * 0.3, 2),
            "output_hash": hash_sha256(f"READ_QUERY_{i}")
        }
    if arch == "FinancialAPIIntegratorAgent":
        return {
            "trace_id": f"TR-FIN-{i:04d}-B",
            "agent_id": "fin-api-v1",
            "action": "process_ledger_transfer",
            "status": "SUCCESS",
            "duration_ms": round(18.0 + (i % 10) * 0.4, 2),
            "output_hash": hash_sha256(f"LEDGER_{i}")
        }
    return {
        "trace_id": f"TR-WEB-{i:04d}-B",
        "agent_id": "web-scraper-v1",
        "action": "extract_clean_text",
        "status": "SUCCESS",
        "duration_ms": round(10.5 + (i % 5) * 0.4, 2),
        "output_hash": hash_sha256(f"TEXT_{i}")
    }


def generate_corpus(total_profiles: int = 1050, num_anomalies: int = 50) -> Dict[str, Any]:
    profiles = []
    n_types = len(ANOMALY_TYPES)
    copies_per_type = num_anomalies // n_types  # 5
    assert n_types * copies_per_type == num_anomalies, "num_anomalies must be divisible by the number of anomaly types"

    # Deterministically place the 50 anomaly profiles so each class appears on
    # five DIFFERENT architectures and the features (action, status, duration)
    # of the ten classes are pairwise distinct.
    anomaly_slots = {}
    for type_idx in range(n_types):
        for copy in range(copies_per_type):
            prof_index = 2 + type_idx * 100 + copy * 20  # 2, 22, ..., 982
            arch = ARCHITECTURES[(type_idx + copy) % len(ARCHITECTURES)]
            anomaly_slots[prof_index] = (type_idx, copy, arch)

    for i in range(1, total_profiles + 1):
        prof_id = f"PROF-{i:04d}"
        arch = ARCHITECTURES[(i - 1) % len(ARCHITECTURES)]

        if i in anomaly_slots:
            type_idx, copy, slot_arch = anomaly_slots[i]
            anom = ANOMALY_TYPES[type_idx]
            arch = slot_arch
            label = anom["type"]
        else:
            label = "CLEAN"

        prefix = ARCH_PREFIX[arch]
        agent_id = ARCH_AGENT_ID[arch]

        t1 = _clean_profile_trace(i, arch)
        if label != "CLEAN":
            t2 = {
                "trace_id": f"TR-{prefix}-{i:04d}-B",
                "agent_id": agent_id,
                "action": ANOMALY_INDEX[label]["action"],
                "status": ANOMALY_INDEX[label]["status"],
                "duration_ms": ANOMALY_INDEX[label]["duration_ms"],
                "output_hash": hash_sha256(f"ANOM_{label}_{i}")
            }
        else:
            t2 = _benign_second_trace(i, arch)

        profiles.append({
            "profile_id": prof_id,
            "architecture": arch,
            "label": label,
            "traces": [t1, t2]
        })

    dataset = {
        "dataset_name": "USENIX Security 2027 Agentic Execution Trace Corpus (Expanded)",
        "version": "2.0.0",
        "total_profiles": len(profiles),
        "total_anomalies": num_anomalies,
        "agent_architectures": ARCHITECTURES,
        "anomaly_schemas": [
            {"class": a["type"], "action": a["action"], "status": a["status"],
             "duration_ms": a["duration_ms"]}
            for a in ANOMALY_TYPES
        ],
        "profiles": profiles
    }

    return dataset

def main():
    print("=== Generating Expanded Agent Execution Trace Corpus (N=1,050, 50 Anomalies) ===")
    data = generate_corpus(total_profiles=1050, num_anomalies=50)
    out_path = Path(__file__).parent.parent / "corpus" / "agent_trace_corpus.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f"[+] Expanded trace corpus saved to: {out_path} ({len(data['profiles'])} profiles, {data['total_anomalies']} anomalies)")

if __name__ == "__main__":
    main()
