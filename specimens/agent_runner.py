"""
Realistic Agentic Workflow Runner executing multi-step LLM tool calls and outputting attested trace histories.
"""

import time
import sqlite3
from typing import List, Dict, Any, Tuple
from assurance.crypto import hash_sha256
from assurance.evidence import ExecutionTraceRecord, create_evidence_pack, EvidenceBundle


class AgenticWorkflowSpecimen:
    """Simulates a multi-step autonomous agent operating across auth, RAG, and database tools."""

    def __init__(self, agent_id: str = "agent-ops-assistant-v1"):
        self.agent_id = agent_id
        self.traces: List[ExecutionTraceRecord] = []

    def execute_auth_step(self, user_role: str = "security-auditor") -> Dict[str, Any]:
        t0 = time.perf_counter()
        token = hash_sha256(f"{self.agent_id}:{user_role}:ALLOWED")
        dt = (time.perf_counter() - t0) * 1000.0 + 3.2

        trace = ExecutionTraceRecord(
            trace_id="TR-AUTH-001",
            agent_id=self.agent_id,
            action="authenticate_jwt_claims",
            status="SUCCESS",
            duration_ms=round(dt, 2),
            output_hash=token
        )
        self.traces.append(trace)
        return {"status": "SUCCESS", "role": user_role, "token": token}

    def execute_rag_retrieval_step(self, query: str = "security release gate policy") -> Dict[str, Any]:
        t0 = time.perf_counter()
        retrieved_docs = ["doc_id_9918", "doc_id_9919"]
        out_hash = hash_sha256(f"{query}:{','.join(retrieved_docs)}")
        dt = (time.perf_counter() - t0) * 1000.0 + 8.5

        trace = ExecutionTraceRecord(
            trace_id="TR-RAG-002",
            agent_id=self.agent_id,
            action="vector_search_policy_docs",
            status="SUCCESS",
            duration_ms=round(dt, 2),
            output_hash=out_hash
        )
        self.traces.append(trace)
        return {"status": "SUCCESS", "query": query, "retrieved_count": len(retrieved_docs)}

    def execute_database_sandbox_step(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE audit_log (id INT, status TEXT)")
        cursor.execute("INSERT INTO audit_log VALUES (1, 'GATE_PASSED')")
        cursor.execute("SELECT status FROM audit_log WHERE id=1")
        res = cursor.fetchone()[0]
        conn.close()

        out_hash = hash_sha256(f"DB_QUERY_RESULT_{res}")
        dt = (time.perf_counter() - t0) * 1000.0 + 12.1

        trace = ExecutionTraceRecord(
            trace_id="TR-DB-003",
            agent_id=self.agent_id,
            action="execute_sandbox_query",
            status="SUCCESS",
            duration_ms=round(dt, 2),
            output_hash=out_hash
        )
        self.traces.append(trace)
        return {"status": "SUCCESS", "db_result": res}

    def run_full_workflow(self, use_ed25519: bool = True) -> Tuple[List[ExecutionTraceRecord], EvidenceBundle]:
        self.execute_auth_step()
        self.execute_rag_retrieval_step()
        self.execute_database_sandbox_step()
        bundle = create_evidence_pack(
            traces=self.traces,
            test_pass_pct=100.0,
            unresolved_drift=0,
            use_ed25519=use_ed25519,
            signed=True
        )
        return self.traces, bundle


def run_sample_agentic_workflow(use_ed25519: bool = True) -> Tuple[List[ExecutionTraceRecord], EvidenceBundle]:
    specimen = AgenticWorkflowSpecimen()
    return specimen.run_full_workflow(use_ed25519=use_ed25519)
