"""Tests for agent_bom.cli._common to improve coverage."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# _make_console
# ---------------------------------------------------------------------------


def test_make_console_quiet():
    from agent_bom.cli._common import _make_console

    con = _make_console(quiet=True)
    assert con.quiet is True


def test_make_console_json_format():
    from agent_bom.cli._common import _make_console

    con = _make_console(output_format="json")
    # Should route to stderr for JSON — just verify it was created
    assert con is not None


def test_make_console_no_color():
    from agent_bom.cli._common import _make_console

    con = _make_console(no_color=True)
    assert con.no_color is True


def test_make_console_default():
    from agent_bom.cli._common import _make_console

    con = _make_console()
    assert con.quiet is False


# ---------------------------------------------------------------------------
# _build_agents_from_inventory
# ---------------------------------------------------------------------------


def test_build_agents_basic():
    from agent_bom.cli._common import _build_agents_from_inventory

    inventory = {
        "agents": [
            {
                "name": "test-agent",
                "agent_type": "custom",
                "config_path": "/test",
                "mcp_servers": [
                    {
                        "name": "server1",
                        "command": "npx",
                        "args": ["@mcp/test"],
                        "transport": "stdio",
                        "packages": [
                            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
                            "express@4.18.0",
                        ],
                        "tools": [
                            "simple_tool",
                            {"name": "complex_tool", "description": "desc", "input_schema": {}},
                        ],
                    }
                ],
            }
        ]
    }
    agents = _build_agents_from_inventory(inventory, "/source")
    assert len(agents) == 1
    agent = agents[0]
    assert agent.name == "test-agent"
    assert len(agent.mcp_servers) == 1
    srv = agent.mcp_servers[0]
    assert len(srv.packages) == 2
    assert srv.packages[0].name == "lodash"
    assert srv.packages[1].name == "express"
    assert srv.packages[1].version == "4.18.0"
    assert len(srv.tools) == 2
    assert srv.tools[0].name == "simple_tool"
    assert srv.tools[1].name == "complex_tool"


def test_build_agents_from_inventory_empty():
    from agent_bom.cli._common import _build_agents_from_inventory

    agents = _build_agents_from_inventory({}, "/source")
    assert agents == []


def test_build_agents_from_inventory_package_no_at():
    from agent_bom.cli._common import _build_agents_from_inventory

    inventory = {
        "agents": [
            {
                "name": "a",
                "agent_type": "custom",
                "mcp_servers": [
                    {
                        "name": "s",
                        "command": "test",
                        "packages": ["no-version-pkg"],
                    }
                ],
            }
        ]
    }
    agents = _build_agents_from_inventory(inventory, "/src")
    assert agents[0].mcp_servers[0].packages[0].version == "unknown"


# ---------------------------------------------------------------------------
# _check_optional_dep
# ---------------------------------------------------------------------------


def test_check_optional_dep_not_installed():
    from agent_bom.cli._common import _check_optional_dep

    with patch("shutil.which", return_value=None):
        result = _check_optional_dep("nonexistent-tool-xyz")
    assert result == "not installed"


def test_check_optional_dep_found_with_version():
    from agent_bom.cli._common import _check_optional_dep

    mock_result = MagicMock()
    mock_result.stdout = "tool version 1.0.0\n"
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/tool"), patch("subprocess.run", return_value=mock_result):
        result = _check_optional_dep("tool")
    assert "found" in result
    assert "1.0.0" in result


def test_check_optional_dep_found_exception():
    from agent_bom.cli._common import _check_optional_dep

    with patch("shutil.which", return_value="/usr/bin/tool"), patch("subprocess.run", side_effect=Exception("fail")):
        result = _check_optional_dep("tool")
    assert result == "found"


# ---------------------------------------------------------------------------
# _check_for_update_bg / _print_update_notice
# ---------------------------------------------------------------------------


def test_print_update_notice_no_result():
    import agent_bom.cli._common as mod
    from agent_bom.cli._common import _print_update_notice

    old_result = mod._update_check_result
    old_done = mod._update_check_done

    mod._update_check_result = None
    mod._update_check_done = threading.Event()
    mod._update_check_done.set()

    con = MagicMock()
    _print_update_notice(con)
    # Should not print anything
    con.print.assert_not_called()

    mod._update_check_result = old_result
    mod._update_check_done = old_done


def test_print_update_notice_with_result():
    import agent_bom.cli._common as mod
    from agent_bom.cli._common import _print_update_notice

    old_result = mod._update_check_result
    old_done = mod._update_check_done

    mod._update_check_result = "Update available!"
    mod._update_check_done = threading.Event()
    mod._update_check_done.set()

    con = MagicMock()
    _print_update_notice(con)
    assert con.print.call_count == 2  # blank line + message

    mod._update_check_result = old_result
    mod._update_check_done = old_done


# ---------------------------------------------------------------------------
# SEVERITY_ORDER / BANNER
# ---------------------------------------------------------------------------


def test_severity_order():
    from agent_bom.cli._common import SEVERITY_ORDER

    assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"]
    assert SEVERITY_ORDER["high"] > SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] > SEVERITY_ORDER["low"]
    assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["none"]
    assert SEVERITY_ORDER["none"] > SEVERITY_ORDER["unknown"]
    assert "unknown" in SEVERITY_ORDER, "UNKNOWN must be in SEVERITY_ORDER"


def test_banner_is_string():
    from agent_bom.cli._common import BANNER

    assert isinstance(BANNER, str)
    assert "agent" in BANNER.lower() or "bom" in BANNER.lower() or "security" in BANNER.lower()
