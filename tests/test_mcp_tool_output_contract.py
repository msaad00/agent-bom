"""Output contract for every registered MCP tool.

ONE parametrized test over all ~63 registered tools. Each tool is invoked
through the real ``_tool_manager.call_tool`` boundary with minimal VALID args
and must satisfy the headless-agent output contract:

* returns without raising (the tool layer is expected to catch and serialize
  its own errors, never bubble an exception to the MCP client);
* the returned payload is a JSON string that round-trips through ``json.loads``
  (well-formed, JSON-serializable);
* it leaks no Python stack trace (``Traceback (most recent call last)`` /
  ``File "...", line`` framing) into the response — a regression that would
  expose host paths and internals to an agent.

Network/filesystem-touching tools are driven with throwaway temp paths and
harmless inputs; the tool layer's own try/except converts any downstream
failure into a structured ``{"error": ...}`` payload, which still satisfies
the contract. A tool is skipped (with a reason) only if it genuinely cannot be
driven in-process.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from agent_bom.mcp_server import create_mcp_server

_TRACEBACK_MARKERS = ("Traceback (most recent call last)", 'File "', '  File "')


@pytest.fixture(scope="module")
def mcp_server() -> Any:
    return create_mcp_server()


@pytest.fixture(scope="module")
def workdir() -> Any:
    """A populated work directory UNDER ``$HOME``.

    Several scanning tools confine path arguments to the operator's home
    directory via ``_safe_path`` (anti directory-traversal). A pytest tmp dir
    lives outside ``$HOME``, so we materialize the fixture under home and clean
    it up afterwards. The contents give path-driven tools real targets.
    """
    base = Path.home() / ".agent_bom_test_mcp_contract"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    (base / "requirements.txt").write_text("requests==2.31.0\n")
    (base / "pyproject.toml").write_text("[project]\nname='x'\nversion='0'\n")
    (base / "Dockerfile").write_text("FROM python:3.12\n")
    (base / "skill.md").write_text("# Example skill\nDo a thing.\n")
    (base / "app.py").write_text("import os\nprint(os.getcwd())\n")
    (base / "empty_config.json").write_text("{}\n")
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _minimal_args(name: str, workdir: Path) -> dict[str, Any]:
    """Minimal VALID args for each tool. Path args point at the temp workdir;
    write tools use a non-admin role so they exercise the fail-closed path
    (the response is still a well-formed JSON payload, satisfying the contract).
    """
    p = str(workdir)
    file_target = str(workdir / "skill.md")
    per_tool: dict[str, dict[str, Any]] = {
        # Point scan at the throwaway workdir so it inspects the fixture, not
        # the host's real MCP configs (which would error in offline mode).
        "scan": {"config_path": p, "offline": True},
        "ai_inventory_scan": {"directory": p},
        "analytics_query": {"query_type": "summary"},
        "blast_radius": {"cve_id": "CVE-2026-0001"},
        "check": {"package": "requests", "ecosystem": "pypi"},
        "cis_benchmark": {"provider": "aws"},
        "code_scan": {"path": p},
        "dataset_card_scan": {"directory": p},
        "firewall_check": {"source_agent": "a", "target_agent": "b"},
        "fleet_scan": {"servers": "[]"},
        "identity_grant_jit": {"identity_id": "id-x", "tool_name": "search"},
        "identity_issue": {"agent_id": "agent-x"},
        "identity_revoke": {"identity_id": "id-x"},
        "identity_revoke_jit": {"grant_id": "grant-x"},
        "identity_rotate": {"identity_id": "id-x"},
        "ingest_external_scan": {"scan_json": "{}", "parse_only": True},
        "intel_lookup": {"advisory_id": "GHSA-xxxx-xxxx-xxxx"},
        "inventory_asset": {"asset_id": "asset-does-not-exist"},
        "license_compliance_scan": {"scan_json": "{}"},
        "marketplace_check": {"package": "requests"},
        "model_file_scan": {"directory": p},
        "model_provenance_scan": {"model_id": "bert-base-uncased"},
        "policy_check": {"policy_json": "{}"},
        "prompt_scan": {"directory": p},
        "registry_sweep_scan": {"provider": "ecr"},
        "runtime_blueprint_drift": {"blueprint_id": "bp-x"},
        "should_i_deploy": {"candidate": "requests==2.31.0"},
        "skill_trust": {"skill_path": file_target},
        "skill_scan": {"path": p},
        "skill_verify": {"path": p},
        "training_pipeline_scan": {"directory": p},
        "verify": {"package": "requests", "ecosystem": "pypi"},
    }
    return per_tool.get(name, {})


# Tools that cannot be exercised in-process without an external binary on PATH.
# code_scan shells out to semgrep; absent it the tool (correctly) raises before
# any output is produced, so there is nothing to assert about its payload.
_REQUIRES_BINARY = {"code_scan": "semgrep"}


def _tool_names() -> list[str]:
    server = create_mcp_server()
    return sorted(server._tool_manager._tools.keys())


@pytest.mark.parametrize("tool_name", _tool_names())
def test_tool_output_contract(tool_name: str, mcp_server: Any, workdir: Path) -> None:
    required_binary = _REQUIRES_BINARY.get(tool_name)
    if required_binary and shutil.which(required_binary) is None:
        pytest.skip(f"{tool_name} requires '{required_binary}' on PATH (not installed)")

    args = _minimal_args(tool_name, workdir)

    async def call() -> Any:
        return await mcp_server._tool_manager.call_tool(tool_name, args)

    try:
        raw = asyncio.run(call())
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{tool_name} raised instead of returning a structured payload: {exc!r}")

    # FastMCP may return the tool's str payload directly, or wrap it in a
    # content list — normalize to the underlying JSON text.
    text = _extract_text(raw)
    assert isinstance(text, str), f"{tool_name} returned non-string payload: {type(raw)}"

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        pytest.fail(f"{tool_name} returned non-JSON payload: {exc}\npayload head: {text[:300]!r}")

    # Round-trips => JSON-serializable.
    json.dumps(parsed)

    for marker in _TRACEBACK_MARKERS:
        assert marker not in text, f"{tool_name} leaked a stack trace into its output (marker {marker!r})"


def _extract_text(raw: Any) -> str:
    if isinstance(raw, str):
        return raw
    # FastMCP content-list shape: [TextContent(type="text", text=...), ...]
    if isinstance(raw, list | tuple) and raw:
        first = raw[0]
        text = getattr(first, "text", None)
        if isinstance(text, str):
            return text
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            return first["text"]
    # (content, structured) tuple shape used by some FastMCP versions
    if isinstance(raw, tuple) and len(raw) == 2:
        return _extract_text(raw[0])
    return str(raw)
