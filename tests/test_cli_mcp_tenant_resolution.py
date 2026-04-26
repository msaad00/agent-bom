"""Tenant-resolution tests for the CLI and MCP surfaces (#1964).

Two layers:

1. Behavioural: ``resolve_cli_tenant_id`` and ``resolve_mcp_tenant_id``
   honour explicit > env > default with the right precedence, and the
   strict variant refuses to default when multi-tenant signals are
   present.

2. Static guardrail: scan ``src/agent_bom/cli/`` and the MCP modules for
   any ad-hoc ``os.environ.get("AGENT_BOM_TENANT_ID"...)`` call outside
   the central modules. New ad-hoc reads silently re-introduce the very
   drift this PR closed; CI fails on them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_bom.cli._tenant import (
    DEFAULT_TENANT_ID,
    TENANT_ENV_VAR,
    resolve_cli_tenant_id,
    resolve_cli_tenant_id_strict,
)
from agent_bom.mcp_tenant import MCP_TENANT_ENV_VAR, resolve_mcp_tenant_id

ROOT = Path(__file__).resolve().parents[1]
CLI_TENANT_MODULE = ROOT / "src" / "agent_bom" / "cli" / "_tenant.py"
MCP_TENANT_MODULE = ROOT / "src" / "agent_bom" / "mcp_tenant.py"


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TENANT_ENV_VAR, raising=False)
    monkeypatch.delenv(MCP_TENANT_ENV_VAR, raising=False)
    monkeypatch.delenv("AGENT_BOM_REQUIRE_TENANT_BOUNDARY", raising=False)
    monkeypatch.delenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", raising=False)


# ── CLI ─────────────────────────────────────────────────────────────────────


def test_cli_explicit_argument_wins() -> None:
    assert resolve_cli_tenant_id("tenant-a") == "tenant-a"


def test_cli_strips_whitespace_on_explicit() -> None:
    assert resolve_cli_tenant_id("  tenant-a  ") == "tenant-a"


def test_cli_env_used_when_no_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TENANT_ENV_VAR, "tenant-from-env")
    assert resolve_cli_tenant_id() == "tenant-from-env"


def test_cli_falls_back_to_default_when_nothing_set() -> None:
    assert resolve_cli_tenant_id() == DEFAULT_TENANT_ID


def test_cli_strict_refuses_default_against_multi_tenant_replicas(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "3")
    with pytest.raises(RuntimeError, match="multi-tenant"):
        resolve_cli_tenant_id_strict()


def test_cli_strict_refuses_default_when_boundary_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_REQUIRE_TENANT_BOUNDARY", "1")
    with pytest.raises(RuntimeError, match="multi-tenant"):
        resolve_cli_tenant_id_strict()


def test_cli_strict_passes_with_explicit_against_multi_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "3")
    assert resolve_cli_tenant_id_strict("tenant-a") == "tenant-a"


# ── MCP ─────────────────────────────────────────────────────────────────────


def test_mcp_specific_env_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MCP_TENANT_ENV_VAR, "mcp-tenant")
    monkeypatch.setenv(TENANT_ENV_VAR, "shared-tenant")
    assert resolve_mcp_tenant_id() == "mcp-tenant"


def test_mcp_falls_back_to_shared_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TENANT_ENV_VAR, "shared-tenant")
    assert resolve_mcp_tenant_id() == "shared-tenant"


def test_mcp_falls_back_to_default() -> None:
    assert resolve_mcp_tenant_id() == DEFAULT_TENANT_ID


# ── Static guardrail: no ad-hoc readers ─────────────────────────────────────

_ADHOC_RE = re.compile(r'os\.environ\.get\(\s*["\']AGENT_BOM_TENANT_ID["\']')
_MCP_ADHOC_RE = re.compile(r'os\.environ\.get\(\s*["\']AGENT_BOM_MCP_TENANT_ID["\']')


def _python_files_under(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def test_no_ad_hoc_tenant_env_reads_in_cli_or_mcp() -> None:
    """Only ``src/agent_bom/cli/_tenant.py`` and ``mcp_tenant.py`` may read
    the tenant env vars directly. Every other CLI / MCP code path must go
    through ``resolve_cli_tenant_id`` / ``resolve_mcp_tenant_id``.
    """
    cli_dir = ROOT / "src" / "agent_bom" / "cli"
    mcp_files = sorted((ROOT / "src" / "agent_bom").glob("mcp_*.py"))
    mcp_tools_dir = ROOT / "src" / "agent_bom" / "mcp_tools"

    candidates: list[Path] = _python_files_under(cli_dir) + list(mcp_files)
    if mcp_tools_dir.is_dir():
        candidates.extend(_python_files_under(mcp_tools_dir))

    sanctioned = {CLI_TENANT_MODULE.resolve(), MCP_TENANT_MODULE.resolve()}
    violations: list[str] = []
    for path in candidates:
        if path.resolve() in sanctioned:
            continue
        text = path.read_text(encoding="utf-8")
        if _ADHOC_RE.search(text) or _MCP_ADHOC_RE.search(text):
            rel = path.relative_to(ROOT).as_posix()
            violations.append(rel)
    assert not violations, (
        "Ad-hoc AGENT_BOM_TENANT_ID/AGENT_BOM_MCP_TENANT_ID env reads found in CLI/MCP code:\n  - "
        + "\n  - ".join(violations)
        + "\nRoute these through agent_bom.cli._tenant.resolve_cli_tenant_id "
        "or agent_bom.mcp_tenant.resolve_mcp_tenant_id (#1964)."
    )
