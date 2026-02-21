"""Tests for Jupyter notebook scanner."""

import json
from pathlib import Path

from agent_bom.jupyter import scan_jupyter_notebooks


def _make_notebook(cells: list[dict]) -> dict:
    """Build a minimal .ipynb JSON structure."""
    return {
        "cells": cells,
        "metadata": {"kernelspec": {"display_name": "Python 3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def _code_cell(source: str | list[str]) -> dict:
    if isinstance(source, str):
        source = [source]
    return {"cell_type": "code", "source": source, "metadata": {}, "outputs": []}


def _markdown_cell(source: str) -> dict:
    return {"cell_type": "markdown", "source": [source], "metadata": {}}


def test_scan_empty_directory(tmp_path: Path):
    """Empty directory returns empty results."""
    agents, warnings = scan_jupyter_notebooks(tmp_path)
    assert agents == []
    assert warnings == []


def test_scan_basic_import(tmp_path: Path):
    """Detect import openai in a code cell."""
    nb = _make_notebook([_code_cell("import openai\nclient = openai.Client()")])
    (tmp_path / "test.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert len(agents) == 1
    assert agents[0].name == "jupyter:test"
    pkgs = agents[0].mcp_servers[0].packages
    assert any(p.name == "openai" for p in pkgs)


def test_scan_from_import(tmp_path: Path):
    """Detect from anthropic import Anthropic."""
    nb = _make_notebook([_code_cell("from anthropic import Anthropic")])
    (tmp_path / "chat.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert len(agents) == 1
    pkgs = agents[0].mcp_servers[0].packages
    assert any(p.name == "anthropic" for p in pkgs)


def test_scan_pip_install(tmp_path: Path):
    """Detect !pip install langchain==0.1.0."""
    nb = _make_notebook([_code_cell("!pip install langchain==0.1.0 openai")])
    (tmp_path / "setup.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert len(agents) == 1
    pkgs = agents[0].mcp_servers[0].packages
    pkg_names = {p.name for p in pkgs}
    assert "langchain" in pkg_names
    assert "openai" in pkg_names
    lc = next(p for p in pkgs if p.name == "langchain")
    assert lc.version == "0.1.0"


def test_scan_percent_pip(tmp_path: Path):
    """Detect %pip install transformers."""
    nb = _make_notebook([_code_cell("%pip install transformers")])
    (tmp_path / "ml.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert len(agents) == 1
    pkgs = agents[0].mcp_servers[0].packages
    assert any(p.name == "transformers" for p in pkgs)


def test_scan_credential_detection(tmp_path: Path):
    """Detect os.environ credential access."""
    nb = _make_notebook([_code_cell('import os\napi_key = os.environ["OPENAI_API_KEY"]')])
    (tmp_path / "creds.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert len(agents) == 1
    server = agents[0].mcp_servers[0]
    assert "OPENAI_API_KEY" in server.env


def test_scan_hardcoded_key_warning(tmp_path: Path):
    """Hardcoded API key should produce a warning."""
    nb = _make_notebook([_code_cell('api_key = "sk-1234567890abcdefghijklmnop"')])
    (tmp_path / "keys.ipynb").write_text(json.dumps(nb))
    _, warnings = scan_jupyter_notebooks(tmp_path)
    assert any("hardcoded API key" in w for w in warnings)


def test_scan_markdown_cells_ignored(tmp_path: Path):
    """Markdown cells should not trigger detection."""
    nb = _make_notebook([
        _markdown_cell("# Setup\nimport openai  <!-- this is markdown -->"),
        _code_cell("x = 1 + 1"),
    ])
    (tmp_path / "readme.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert agents == []


def test_scan_multiple_notebooks(tmp_path: Path):
    """Multiple notebooks each produce their own agent."""
    nb1 = _make_notebook([_code_cell("import openai")])
    nb2 = _make_notebook([_code_cell("import torch")])
    (tmp_path / "a.ipynb").write_text(json.dumps(nb1))
    (tmp_path / "b.ipynb").write_text(json.dumps(nb2))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert len(agents) == 2
    names = {a.name for a in agents}
    assert "jupyter:a" in names
    assert "jupyter:b" in names


def test_scan_deduplication(tmp_path: Path):
    """Same package imported twice should appear once."""
    nb = _make_notebook([
        _code_cell("import openai"),
        _code_cell("from openai import ChatCompletion"),
    ])
    (tmp_path / "dup.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    pkgs = agents[0].mcp_servers[0].packages
    openai_pkgs = [p for p in pkgs if p.name == "openai"]
    assert len(openai_pkgs) == 1


def test_scan_checkpoint_excluded(tmp_path: Path):
    """Files in .ipynb_checkpoints should be skipped."""
    cp_dir = tmp_path / ".ipynb_checkpoints"
    cp_dir.mkdir()
    nb = _make_notebook([_code_cell("import openai")])
    (cp_dir / "test-checkpoint.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    assert agents == []


def test_scan_not_a_directory(tmp_path: Path):
    """Non-directory path returns warning."""
    fake_path = tmp_path / "nonexistent"
    agents, warnings = scan_jupyter_notebooks(fake_path)
    assert agents == []
    assert len(warnings) == 1
    assert "not a directory" in warnings[0]


def test_scan_invalid_json_notebook(tmp_path: Path):
    """Malformed notebook JSON should be skipped gracefully."""
    (tmp_path / "bad.ipynb").write_text("{not valid json")
    agents, warnings = scan_jupyter_notebooks(tmp_path)
    assert agents == []
    assert warnings == []


def test_scan_agent_attributes(tmp_path: Path):
    """Verify agent attributes are set correctly."""
    nb = _make_notebook([_code_cell("import openai")])
    nb_path = tmp_path / "analysis.ipynb"
    nb_path.write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    agent = agents[0]
    assert agent.agent_type.value == "custom"
    assert agent.config_path == str(nb_path)
    assert agent.source == "jupyter"
    assert agent.mcp_servers[0].command == "jupyter"
    assert agent.mcp_servers[0].name == "notebook:analysis"


def test_scan_ecosystem_is_pypi(tmp_path: Path):
    """All detected packages should have ecosystem=pypi."""
    nb = _make_notebook([_code_cell("!pip install torch transformers")])
    (tmp_path / "train.ipynb").write_text(json.dumps(nb))
    agents, _ = scan_jupyter_notebooks(tmp_path)
    for pkg in agents[0].mcp_servers[0].packages:
        assert pkg.ecosystem == "pypi"
