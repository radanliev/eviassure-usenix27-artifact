"""
Web & UI Action Runner Specimen.
Simulates a web browser agent executing UI action sequences (navigate, click, type, screenshot),
attesting DOM state hashes and screenshot digests into SHA-256 Merkle evidence packs.
"""

import time
import hashlib
from typing import List, Dict, Any, Tuple
from assurance.crypto import hash_sha256
from assurance.evidence import (BrowserActionTraceRecord, ExecutionTraceRecord,
                                create_evidence_pack, EvidenceBundle, realistic_dom_fragment)


class WebBrowserAgentSpecimen:
    """Simulates a browser-based agent performing UI action sequences and generating attested trace bundles."""

    def __init__(self, agent_id: str = "web-browser-agent-v1"):
        self.agent_id = agent_id
        self.browser_traces: List[BrowserActionTraceRecord] = []
        self.exec_traces: List[ExecutionTraceRecord] = []

    def navigate(self, url: str = "http://localhost:8080/dashboard") -> Dict[str, Any]:
        t0 = time.perf_counter()
        dom_content = realistic_dom_fragment(1)
        dom_hash = hash_sha256(dom_content)
        screenshot_hash = hash_sha256(f"SCREENSHOT_PNG_{url}_{dom_hash[:8]}")
        dt = (time.perf_counter() - t0) * 1000.0 + 15.0

        trace = BrowserActionTraceRecord(
            trace_id="TR-UI-001",
            agent_id=self.agent_id,
            action="navigate",
            status="SUCCESS",
            duration_ms=round(dt, 2),
            url=url,
            element_selector="window",
            dom_state_hash=dom_hash,
            screenshot_sha256=screenshot_hash
        )
        self.browser_traces.append(trace)
        
        # Convert to execution trace for evidence bundle compatibility
        self.exec_traces.append(ExecutionTraceRecord(
            trace_id=trace.trace_id,
            agent_id=trace.agent_id,
            action=f"ui_{trace.action}",
            status=trace.status,
            duration_ms=trace.duration_ms,
            output_hash=trace.to_hash()
        ))
        return {"status": "SUCCESS", "url": url, "dom_hash": dom_hash}

    def click_button(self, selector: str = "button#deploy-release") -> Dict[str, Any]:
        t0 = time.perf_counter()
        dom_content = realistic_dom_fragment(2)
        dom_hash = hash_sha256(dom_content)
        screenshot_hash = hash_sha256(f"SCREENSHOT_PNG_CLICK_{selector}")
        dt = (time.perf_counter() - t0) * 1000.0 + 8.2

        trace = BrowserActionTraceRecord(
            trace_id="TR-UI-002",
            agent_id=self.agent_id,
            action="click",
            status="SUCCESS",
            duration_ms=round(dt, 2),
            url="http://localhost:8080/dashboard",
            element_selector=selector,
            dom_state_hash=dom_hash,
            screenshot_sha256=screenshot_hash
        )
        self.browser_traces.append(trace)
        
        self.exec_traces.append(ExecutionTraceRecord(
            trace_id=trace.trace_id,
            agent_id=trace.agent_id,
            action=f"ui_{trace.action}",
            status=trace.status,
            duration_ms=trace.duration_ms,
            output_hash=trace.to_hash()
        ))
        return {"status": "SUCCESS", "selector": selector, "dom_hash": dom_hash}

    def run_full_ui_sequence(self, tampered_dom: bool = False) -> Tuple[List[ExecutionTraceRecord], EvidenceBundle]:
        self.navigate()
        self.click_button()

        if tampered_dom:
            # Simulate an attacker tampering with the DOM state hash of trace 1
            self.exec_traces[0].output_hash = hash_sha256("TAMPERED_DOM_STATE_MALICIOUS_INJECTION")

        bundle = create_evidence_pack(
            traces=self.exec_traces,
            test_pass_pct=100.0,
            unresolved_drift=0,
            signed=True
        )
        return self.exec_traces, bundle


def run_web_agent_attestation_demo(tampered: bool = False) -> Tuple[List[ExecutionTraceRecord], EvidenceBundle]:
    specimen = WebBrowserAgentSpecimen()
    return specimen.run_full_ui_sequence(tampered_dom=tampered)
