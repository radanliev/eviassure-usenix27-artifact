"""
Meta-test: the manuscript's claims about the repository must match reality.

The test-count claim in the reproduction appendix drifted twice while tests
were being added; this test fails the suite the moment prose and code
disagree, so the number can never silently rot again.
"""

import re
from pathlib import Path

import pytest


def test_manuscript_test_count_matches_collection():
    tex = (Path(__file__).parent.parent / "docs" / "usenix_paper_manuscript.tex").read_text()
    m = re.search(r"execute all (\d+) unit", tex)
    assert m, "test-count claim not found in manuscript appendix"

    collected = 0
    for f in (Path(__file__).parent).glob("test_*.py"):
        if f.name == "test_docs_consistency.py":
            continue  # this guard is not part of the suite the paper describes
        collected += len(re.findall(r"^def (test_\w+)", f.read_text(), re.M))

    claimed = int(m.group(1))
    assert claimed == collected, (
        f"Manuscript claims {claimed} tests but the suite collects {collected}; "
        "update the appendix (and any prose counts) to match."
    )
