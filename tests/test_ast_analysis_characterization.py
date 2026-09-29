"""Characterization golden for project-level AST, taint and reach analysis.

Pins the full ``analyze_project`` result (every field, in emission order) over
a multi-language corpus so staged refactors stay byte-identical.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path

import pytest

import agent_bom.ast_analyzer as ast_analyzer
from agent_bom.ast_analyzer import analyze_project

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = FIXTURES / "analysis_characterization"
GOLDEN = FIXTURES / "analysis_characterization_golden.json"


def _materialize(root: Path) -> Path:
    """Copy the corpus, restoring dependency manifests committed as ``*.fixture``.

    The manifests pin deliberately old versions; committing them under their real
    names would put known-vulnerable dependencies in the repository's own scan.
    """
    corpus = root / "analysis_characterization"
    shutil.copytree(CORPUS, corpus)
    for manifest in corpus.rglob("*.fixture"):
        manifest.rename(manifest.with_suffix(""))
    return corpus


def _serialize(project: Path | str) -> dict:
    return json.loads(json.dumps(asdict(analyze_project(project)), default=repr))


def _characterize(monkeypatch: pytest.MonkeyPatch, root: Path) -> dict:
    monkeypatch.setenv("AGENT_BOM_TAINT_MAX_DEPTH", "4")
    corpus = _materialize(root)
    projects = {
        "python_agent": corpus / "python_agent",
        "multilang": corpus / "multilang",
        "combined": corpus,
        "ordinary_python_app": FIXTURES / "ordinary-python-app",
    }
    results = {name: _serialize(path) for name, path in projects.items()}
    results["missing"] = _serialize("does-not-exist")
    with monkeypatch.context() as budget:
        budget.setattr(ast_analyzer, "_MAX_FILES", 5)
        results["file_budget"] = _serialize(corpus)
    return results


def test_analyze_project_matches_golden(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    actual = _characterize(monkeypatch, tmp_path)
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
