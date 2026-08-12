"""Release gates must exercise MCP from an unlocked wheel install.

This file previously asserted the smoke script contained the literal
``EXPECTED_TOOL_COUNT = 77``, which pinned exactly the thing that goes stale.
It now pins the properties that keep the check honest instead: the expectation
is derived from the shipped server card, all three JSON-RPC list surfaces are
exercised, and names are compared rather than counts.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts/smoke_mcp_wheel.py"


def _load():
    spec = importlib.util.spec_from_file_location("smoke_mcp_wheel", SMOKE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


smoke = _load()


def test_mcp_wheel_smoke_is_real_jsonrpc_and_syntax_valid() -> None:
    body = SMOKE.read_text(encoding="utf-8")
    ast.parse(body)
    assert 'importlib.import_module("agent_bom.mcp_server")' in body
    assert "session.initialize()" in body
    assert "session.list_tools()" in body
    # The two surfaces that had no live coverage at all before.
    assert "session.list_resources()" in body
    assert "session.list_prompts()" in body


def test_expected_surface_is_derived_from_the_shipped_server_card() -> None:
    """A typed-in count is the defect class; the card is the source of truth."""
    code = SMOKE.read_text(encoding="utf-8").split('"""', 2)[-1]
    assert "EXPECTED_TOOL_COUNT" not in code
    expected = smoke._expected_surface()
    from agent_bom import mcp_server_metadata

    assert expected["tools"] == {str(t["name"]) for t in mcp_server_metadata._SERVER_CARD_TOOLS}
    assert expected["resources"] == {str(r["uri"]) for r in mcp_server_metadata._SERVER_CARD_RESOURCES}
    assert expected["prompts"] == {str(p["name"]) for p in mcp_server_metadata._SERVER_CARD_PROMPTS}


class TestSurfaceComparison:
    def test_a_card_entry_never_registered_live_is_caught(self) -> None:
        problems = smoke._compare("resources", ["a://x"], {"a://x", "a://ghost"})
        assert any("not registered live" in p for p in problems)

    def test_a_live_entry_missing_from_the_card_is_caught(self) -> None:
        problems = smoke._compare("tools", ["scan", "undocumented"], {"scan"})
        assert any("missing from the server card" in p for p in problems)

    def test_duplicates_are_caught(self) -> None:
        problems = smoke._compare("tools", ["scan", "scan"], {"scan"})
        assert any("duplicate" in p for p in problems)

    def test_matching_sets_pass(self) -> None:
        assert smoke._compare("prompts", ["a", "b"], {"b", "a"}) == []

    def test_equal_counts_with_different_names_still_fail(self) -> None:
        """Counting was never enough — two sets can be the same size and differ."""
        problems = smoke._compare("tools", ["a", "b"], {"a", "c"})
        assert problems


def test_ci_and_release_use_a_clean_unlocked_wheel_install() -> None:
    for workflow in (".github/workflows/ci.yml", ".github/workflows/release.yml"):
        body = (ROOT / workflow).read_text(encoding="utf-8")
        assert "python -m venv" in body
        assert 'bin/pip" install --disable-pip-version-check dist/*.whl' in body
        assert "scripts/smoke_mcp_wheel.py" in body
