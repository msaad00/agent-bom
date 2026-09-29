"""Characterization golden for project-level AST, taint and reach analysis.

Pins the full ``analyze_project`` result (every field, in emission order) over
a multi-language corpus so staged refactors stay byte-identical.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

import agent_bom.ast_analyzer as ast_analyzer
from agent_bom.ast_analyzer import analyze_project

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = FIXTURES / "analysis_characterization"
GOLDEN = FIXTURES / "analysis_characterization_golden.json"
PROJECTS = {
    "python_agent": CORPUS / "python_agent",
    "multilang": CORPUS / "multilang",
    "combined": CORPUS,
    "ordinary_python_app": FIXTURES / "ordinary-python-app",
}


def _serialize(project: Path | str) -> dict:
    return json.loads(json.dumps(asdict(analyze_project(project)), default=repr))


def _characterize(monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", "4")
    results = {name: _serialize(path) for name, path in PROJECTS.items()}
    results["missing"] = _serialize("does-not-exist")
    with monkeypatch.context() as budget:
        budget.setattr(ast_analyzer, "_MAX_FILES", 5)
        results["file_budget"] = _serialize(CORPUS)
    return results


def test_analyze_project_matches_golden(monkeypatch: pytest.MonkeyPatch) -> None:
    actual = _characterize(monkeypatch)
    if os.environ.get("AGENT_BOM_UPDATE_GOLDENS") == "1":
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    assert actual == json.loads(GOLDEN.read_text())


def test_golden_exercises_taint_reach_and_every_language() -> None:
    golden = json.loads(GOLDEN.read_text())
    combined = golden["combined"]
    assert combined["files_analyzed"] >= 12
    assert combined["flow_findings"] and combined["call_edges"] and combined["cfg_edges"]
    assert combined["dependency_symbol_reach"] and combined["application_entrypoints"]
    assert golden["file_budget"]["analysis_coverage"]["status"] == "partial"
    assert golden["missing"]["warnings"] == ["does-not-exist is not a directory"]
