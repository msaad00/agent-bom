"""Release gates must exercise MCP from an unlocked wheel install."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts/smoke_mcp_wheel.py"


def test_mcp_wheel_smoke_is_real_jsonrpc_and_syntax_valid() -> None:
    body = SMOKE.read_text(encoding="utf-8")
    ast.parse(body)
    assert 'importlib.import_module("agent_bom.mcp_server")' in body
    assert "session.initialize()" in body
    assert "session.list_tools()" in body
    assert "EXPECTED_TOOL_COUNT = 77" in body


def test_ci_and_release_use_a_clean_unlocked_wheel_install() -> None:
    for workflow in (".github/workflows/ci.yml", ".github/workflows/release.yml"):
        body = (ROOT / workflow).read_text(encoding="utf-8")
        assert "python -m venv" in body
        assert 'bin/pip" install --disable-pip-version-check dist/*.whl' in body
        assert "scripts/smoke_mcp_wheel.py" in body
