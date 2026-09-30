"""Characterization golden for the Python taint interpreter.

Pins the full ``analyze_project`` result over a Python-only corpus that walks
every statement and expression kind the interpreter handles (and several it
deliberately ignores) at each end of the taint depth range, so refactors of the
interpreter stay byte-identical in findings and emission order.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

from agent_bom.ast_analyzer import analyze_project

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = FIXTURES / "taint_characterization"
GOLDEN = FIXTURES / "taint_characterization_golden.json"
DEPTHS = ("2", "4", "8")


def _characterize(monkeypatch: pytest.MonkeyPatch) -> dict:
    results = {}
    for depth in DEPTHS:
        monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", depth)
        results[f"depth_{depth}"] = json.loads(json.dumps(asdict(analyze_project(CORPUS)), default=repr))
    return results


def test_taint_corpus_matches_golden(monkeypatch: pytest.MonkeyPatch) -> None:
    actual = _characterize(monkeypatch)
    if os.environ.get("AGENT_BOM_UPDATE_GOLDENS") == "1":
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    assert actual == json.loads(GOLDEN.read_text())


def test_golden_exercises_every_taint_sink_and_depth_cutoff() -> None:
    golden = json.loads(GOLDEN.read_text())
    categories = {finding["category"] for finding in golden["depth_8"]["flow_findings"]}
    assert {
        "tainted_path_access",
        "tainted_ssrf_sink",
        "tainted_command_execution",
        "tainted_dangerous_sink",
        "tainted_dynamic_code_execution",
        "tainted_xss_sink",
        "tainted_sql_query",
        "tainted_llm_prompt",
    } <= categories
    entrypoints = {finding["entrypoint"] for finding in golden["depth_8"]["flow_findings"]}
    assert {"web_search", "read_item", "flask_route", "method_tool"} <= entrypoints

    def deep_chain_hits(depth: str) -> list[dict]:
        return [
            finding
            for finding in golden[f"depth_{depth}"]["flow_findings"]
            if finding["entrypoint"] == "deep_chain" and finding["category"].startswith("tainted_")
        ]

    assert not deep_chain_hits("2")
    assert not deep_chain_hits("4")
    assert deep_chain_hits("8")
