"""First-run checks for optional CLI runtime surfaces."""

from __future__ import annotations

import importlib.util

from click.testing import CliRunner

from agent_bom.cli import main


def _hide_module(monkeypatch, module_name: str) -> None:
    original_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str, *args, **kwargs):
        if name == module_name:
            return None
        return original_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)


def test_api_missing_fastapi_prints_api_extra_hint(monkeypatch):
    _hide_module(monkeypatch, "fastapi")

    result = CliRunner().invoke(main, ["api"])

    assert result.exit_code == 1
    assert "FastAPI required for `agent-bom api`" in result.output
    assert "pip install 'agent-bom[api]'" in result.output


def test_serve_missing_uvicorn_prints_ui_extra_hint(monkeypatch):
    _hide_module(monkeypatch, "uvicorn")

    result = CliRunner().invoke(main, ["serve"])

    assert result.exit_code == 1
    assert "Uvicorn required for `agent-bom serve`" in result.output
    assert "pip install 'agent-bom[ui]'" in result.output


def test_mcp_server_missing_sdk_prints_mcp_extra_hint(monkeypatch):
    _hide_module(monkeypatch, "mcp")

    result = CliRunner().invoke(main, ["mcp", "server"])

    assert result.exit_code == 1
    assert "MCP SDK required for `agent-bom mcp server`" in result.output
    assert "pip install 'agent-bom[mcp-server]'" in result.output
