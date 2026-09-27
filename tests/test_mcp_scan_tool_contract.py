"""MCP ``scan`` tool contract: truthful defaults, bounded valid JSON, honest isError.

Locks four properties an agent calling ``scan`` over MCP depends on:

1. ``offline`` is not silently on. Omitted, it resolves from the operator's
   offline configuration (``AGENT_BOM_OFFLINE`` / ``AGENT_BOM_VULN_DB_OFFLINE``)
   and otherwise queries the vulnerability sources the description promises.
2. Every response is parseable JSON inside the transport budget. The default is
   a summary (counts, top findings, affected paths) plus a ``result_id`` whose
   sections are paged by follow-up calls — never a sliced JSON document.
3. A scan that could not evaluate vulnerabilities is reported with
   ``isError=True`` while keeping its structured JSON body.
4. The path sandbox accepts explicitly configured workspace roots in addition
   to HOME, without weakening traversal or symlink protection.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")

from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402
from mcp.types import CallToolResult  # noqa: E402


def _call(args: dict[str, Any] | None = None) -> CallToolResult:
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")

    async def _run() -> CallToolResult:
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            return await client.call_tool("scan", args or {})

    return asyncio.run(_run())


def _body(result: CallToolResult) -> dict[str, Any]:
    text = result.content[0].text  # type: ignore[union-attr]
    return json.loads(text)


def _one_agent() -> Any:
    from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

    return Agent(
        name="agent-under-test",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/agent-under-test",
        mcp_servers=[
            MCPServer(
                name="server-under-test",
                command="npx",
                args=[],
                env={},
                transport=TransportType.STDIO,
                packages=[Package(name="left-pad", version="1.0.0", ecosystem="npm")],
            )
        ],
    )


_SEVERITIES = ("critical", "high", "medium", "low")


def _huge_report(n_findings: int = 1500) -> dict[str, Any]:
    """A report shaped like ``to_json`` output that is far over the response budget."""
    findings = []
    blast = []
    paths = []
    for i in range(n_findings):
        sev = _SEVERITIES[i % 4]
        risk = round(10 - (i % 97) / 10, 1)
        findings.append(
            {
                "id": f"finding-{i:05d}",
                "finding_type": "CVE",
                "finding_category": "secret" if i % 50 == 0 else "vulnerability",
                "severity": sev,
                "title": f"CVE-2099-{i:05d}: pkg-{i % 40}@1.0.{i % 7}",
                "cve_id": f"CVE-2099-{i:05d}",
                "risk_score": risk,
                "cvss_score": 7.5,
                "epss_score": 0.1,
                "is_kev": i % 11 == 0,
                "fixed_version": "9.9.9",
                "affected_agents": ["agent-under-test"],
                "affected_servers": ["server-under-test"],
                "reachability": "unknown",
                "asset": {"name": f"pkg-{i % 40}", "version": f"1.0.{i % 7}", "ecosystem": "npm"},
                "controls": [{"framework": "x", "control": "y" * 40, "note": '"quoted"\\n' * 20}] * 20,
                "evidence": {"blob": "e" * 1500},
            }
        )
        blast.append({"vulnerability_id": f"CVE-2099-{i:05d}", "severity": sev, "payload": "b" * 1500})
        paths.append(
            {
                "id": f"blast:cve-2099-{i:05d}",
                "rank": i + 1,
                "label": f"pkg-{i % 40}@1.0.{i % 7} -> CVE-2099-{i:05d}",
                "severity": sev,
                "riskScore": risk,
                "fix": "Upgrade pkg to 9.9.9",
                "affectedAgents": ["agent-under-test"],
                "hops": ["a", "b"] * 30,
            }
        )
    return {
        "schema_version": "1",
        "document_type": "AI-BOM",
        "scan_id": "scan-huge",
        "generated_at": "2026-09-26T00:00:00Z",
        "summary": {
            "total_agents": 1,
            "total_mcp_servers": 1,
            "total_packages": 40,
            "unique_packages": 40,
            "total_vulnerabilities": n_findings,
            "total_findings": n_findings,
        },
        "finding_summary": {
            "total": n_findings,
            "by_severity": {s: n_findings // 4 for s in _SEVERITIES} | {"unknown": 0},
            "by_type": {"CVE": n_findings},
        },
        "agents": [{"name": "agent-under-test", "agent_type": "claude-desktop", "mcp_servers": [{"name": "s"}], "blob": "a" * 5000}],
        "packages": [{"name": f"pkg-{i}", "version": "1.0.0"} for i in range(40)],
        "findings": findings,
        "blast_radius": blast,
        "exposure_paths": {"schema_version": "1", "path_count": n_findings, "paths": paths},
        "posture_scorecard": {"grade": "D", "score": 50.0},
    }


# ── 1. offline default ───────────────────────────────────────────────────────


@pytest.fixture
def _clean_offline_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_OFFLINE", raising=False)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)


@pytest.mark.usefixtures("_clean_offline_env")
@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_defaults_to_online_lookups_when_no_offline_config(mock_pipeline) -> None:
    mock_pipeline.return_value = ([], [], [], [])
    result = _call({"no_discover": True})
    assert result.isError is False
    assert mock_pipeline.call_args.kwargs["offline"] is False


@pytest.mark.parametrize("env_key", ["AGENT_BOM_OFFLINE", "AGENT_BOM_VULN_DB_OFFLINE"])
@pytest.mark.usefixtures("_clean_offline_env")
@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_default_honors_operator_offline_config(mock_pipeline, env_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(env_key, "1")
    mock_pipeline.return_value = ([], [], [], [])
    _call({"no_discover": True})
    assert mock_pipeline.call_args.kwargs["offline"] is True


@pytest.mark.usefixtures("_clean_offline_env")
@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_explicit_offline_argument_wins(mock_pipeline, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_pipeline.return_value = ([], [], [], [])
    _call({"no_discover": True, "offline": True})
    assert mock_pipeline.call_args.kwargs["offline"] is True
    monkeypatch.setenv("AGENT_BOM_OFFLINE", "1")
    _call({"no_discover": True, "offline": False})
    assert mock_pipeline.call_args.kwargs["offline"] is False


def test_scan_schema_advertises_the_real_offline_default() -> None:
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    schema = tools["scan"].inputSchema["properties"]
    assert schema["offline"].get("default") is None
    description = schema["offline"]["description"].lower()
    assert "agent_bom_offline" in description
    for param in ("detail", "result_id", "section", "offset", "limit"):
        assert param in schema, f"scan must expose {param} for bounded follow-up retrieval"


# ── 3. isError for incomplete scans ──────────────────────────────────────────


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_incomplete_scan_sets_is_error_and_keeps_json_body(mock_pipeline) -> None:
    from agent_bom.scanners import IncompleteScanError

    mock_pipeline.side_effect = IncompleteScanError("Offline mode requires a populated local vulnerability DB.")
    result = _call({"no_discover": True, "offline": True})
    assert result.isError is True
    body = _body(result)
    assert body["status"] == "incomplete_scan"
    assert body["warnings"]


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_unresolved_package_spec_sets_is_error(mock_pipeline) -> None:
    agent = _one_agent()
    agent.mcp_servers[0].packages = []
    mock_pipeline.return_value = ([agent], [], [], ["mcp_package"])
    with patch("agent_bom.mcp_server_scan.package_spec_extracted_count", return_value=0):
        result = _call({"package": "totally::unparseable", "offline": True})
    assert result.isError is True
    assert _body(result)["status"] == "incomplete_scan"


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_empty_project_is_not_an_error(mock_pipeline) -> None:
    mock_pipeline.return_value = ([], [], [], [])
    result = _call({"no_discover": True, "offline": True})
    assert result.isError is False
    body = _body(result)
    assert body["status"] == "no_agents_found"


# ── 2. bounded, valid, summary-first responses ───────────────────────────────


@pytest.fixture
def huge_scan(monkeypatch: pytest.MonkeyPatch):
    report = _huge_report()
    monkeypatch.setattr("agent_bom.output.to_json", lambda _report: json.loads(json.dumps(report)))
    monkeypatch.setattr("agent_bom.graph.scan_findings.surface_graph_derived_findings", lambda *a, **k: None)
    with patch("agent_bom.mcp_server._run_scan_pipeline") as mock_pipeline:
        mock_pipeline.return_value = ([_one_agent()], [], [], ["agent_discovery"])
        yield report


def test_huge_default_scan_returns_bounded_valid_summary(huge_scan) -> None:
    from agent_bom.mcp_server import _MAX_RESPONSE_CHARS

    full_len = len(json.dumps(huge_scan, indent=2))
    assert full_len > _MAX_RESPONSE_CHARS, "fixture must exceed the transport budget"

    result = _call({"no_discover": True, "offline": True})
    text = result.content[0].text  # type: ignore[union-attr]
    assert result.isError is False
    assert len(text) <= _MAX_RESPONSE_CHARS
    body = json.loads(text)
    assert "_truncated" not in body
    assert body["detail"] == "summary"
    assert body["document_type"] == "AI-BOM"
    assert body["result_id"]

    counts = body["counts"]
    assert counts["findings"] == 1500
    assert counts["findings_by_severity"]["critical"] == 375
    assert counts["findings_by_category"]["secret"] == 30
    assert counts["packages"] == 40
    assert counts["agents"] == 1
    assert counts["mcp_servers"] == 1
    assert counts["exposure_paths"] == 1500
    assert counts["kev"] == len([i for i in range(1500) if i % 11 == 0])

    top = body["top_findings"]
    assert 0 < len(top) <= 10
    risks = [row["risk_score"] for row in top]
    assert risks == sorted(risks, reverse=True)
    assert set(top[0]) >= {"id", "severity", "title", "risk_score", "fixed_version", "affected_agents"}
    assert "controls" not in top[0] and "evidence" not in top[0]

    affected = body["affected_paths"]
    assert 0 < len(affected) <= 10
    assert affected[0]["label"]

    sections = body["sections"]
    assert sections["findings"]["total"] == 1500
    assert sections["blast_radius"]["total"] == 1500
    assert sections["exposure_paths"]["total"] == 1500
    assert "result_id" in body["next"]


def test_follow_up_pages_through_a_section(huge_scan) -> None:
    from agent_bom.mcp_server import _MAX_RESPONSE_CHARS, create_mcp_server

    server = create_mcp_server(profile="full")

    async def _run() -> tuple[CallToolResult, CallToolResult, CallToolResult]:
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            first = await client.call_tool("scan", {"no_discover": True, "offline": True})
            rid = json.loads(first.content[0].text)["result_id"]  # type: ignore[union-attr]
            page = await client.call_tool("scan", {"result_id": rid, "section": "findings", "offset": 10, "limit": 5})
            paths = await client.call_tool("scan", {"result_id": rid, "section": "exposure_paths", "offset": 0, "limit": 3})
            return first, page, paths

    _first, page, paths = asyncio.run(_run())
    text = page.content[0].text  # type: ignore[union-attr]
    assert page.isError is False
    assert len(text) <= _MAX_RESPONSE_CHARS
    body = json.loads(text)
    assert body["section"] == "findings"
    assert body["total"] == 1500
    assert body["offset"] == 10
    assert [item["id"] for item in body["items"]] == [f"finding-{i:05d}" for i in range(10, 15)]
    assert body["next_offset"] == 15
    # Paged items are full-fidelity, not the compact summary rows.
    assert "controls" in body["items"][0]

    paths_body = json.loads(paths.content[0].text)  # type: ignore[union-attr]
    assert paths_body["total"] == 1500
    assert [item["id"] for item in paths_body["items"]] == ["blast:cve-2099-00000", "blast:cve-2099-00001", "blast:cve-2099-00002"]


def test_last_page_has_no_next_offset(huge_scan) -> None:
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")

    async def _run() -> CallToolResult:
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            first = await client.call_tool("scan", {"no_discover": True, "offline": True})
            rid = json.loads(first.content[0].text)["result_id"]  # type: ignore[union-attr]
            return await client.call_tool("scan", {"result_id": rid, "section": "packages", "offset": 35, "limit": 25})

    body = json.loads(asyncio.run(_run()).content[0].text)  # type: ignore[union-attr]
    assert len(body["items"]) == 5
    assert body["next_offset"] is None


def test_unknown_result_id_is_an_error() -> None:
    result = _call({"result_id": "does-not-exist", "section": "findings"})
    assert result.isError is True


def test_unknown_section_is_an_error(huge_scan) -> None:
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")

    async def _run() -> CallToolResult:
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            first = await client.call_tool("scan", {"no_discover": True, "offline": True})
            rid = json.loads(first.content[0].text)["result_id"]  # type: ignore[union-attr]
            return await client.call_tool("scan", {"result_id": rid, "section": "no_such_section"})

    result = asyncio.run(_run())
    assert result.isError is True


def test_full_detail_is_bounded_valid_json_with_truncation_metadata(huge_scan) -> None:
    from agent_bom.mcp_server import _MAX_RESPONSE_CHARS

    result = _call({"no_discover": True, "offline": True, "detail": "full"})
    text = result.content[0].text  # type: ignore[union-attr]
    assert len(text) <= _MAX_RESPONSE_CHARS
    body = json.loads(text)
    assert body["_truncated"] is True
    assert body["document_type"] == "AI-BOM"
    assert body["summary"]["total_findings"] == 1500
    assert 0 < len(body["findings"]) < 1500
    lists = body["_truncation"]["lists"]
    assert lists["$.findings"]["total"] == 1500
    assert lists["$.findings"]["returned"] == len(body["findings"])
    assert body["result_id"], "full-detail responses still offer paged follow-up"


def test_result_store_is_bound_to_the_caller() -> None:
    from agent_bom.mcp_tools.scan_response import ScanResultStore

    store = ScanResultStore(max_entries=2, ttl_seconds=60)
    rid = store.put("caller-a", {"findings": [1, 2, 3]})
    assert store.get("caller-a", rid) == {"findings": [1, 2, 3]}
    assert store.get("caller-b", rid) is None
    store.put("caller-a", {})
    store.put("caller-a", {})
    assert store.get("caller-a", rid) is None, "bounded store evicts the oldest result"


def test_result_store_expires_entries() -> None:
    from agent_bom.mcp_tools.scan_response import ScanResultStore

    now = [1000.0]
    store = ScanResultStore(max_entries=4, ttl_seconds=10, clock=lambda: now[0])
    rid = store.put("c", {"a": 1})
    now[0] += 11
    assert store.get("c", rid) is None


# ── structure-aware truncation (all tools) ───────────────────────────────────


def test_truncate_json_object_keeps_structure_and_parses() -> None:
    from agent_bom.mcp_server_runtime import truncate_response

    doc = {"meta": {"id": "x"}, "items": [{"n": i, "text": '"q"\\' * 50} for i in range(5000)], "tail": "end"}
    raw = json.dumps(doc, indent=2)
    out = truncate_response(raw, 50_000)
    assert len(out) <= 50_000
    parsed = json.loads(out)
    assert parsed["_truncated"] is True
    assert parsed["meta"] == {"id": "x"}
    assert parsed["tail"] == "end"
    assert parsed["items"][0] == doc["items"][0]
    assert parsed["_truncation"]["lists"]["$.items"] == {"total": 5000, "returned": len(parsed["items"])}
    assert parsed["_truncation"]["original_length"] == len(raw)


def test_truncate_json_array_is_wrapped_and_parses() -> None:
    from agent_bom.mcp_server_runtime import truncate_response

    raw = json.dumps([{"i": i, "pad": "p" * 100} for i in range(10_000)])
    out = truncate_response(raw, 20_000)
    assert len(out) <= 20_000
    parsed = json.loads(out)
    assert parsed["_truncated"] is True
    assert isinstance(parsed["data"], list) and parsed["data"][0]["i"] == 0


def test_pretty_printed_json_that_fits_compactly_is_not_marked_truncated() -> None:
    from agent_bom.mcp_server_runtime import truncate_response

    doc = {"rows": [{"a": i, "b": [i, i + 1]} for i in range(200)]}
    raw = json.dumps(doc, indent=40)
    budget = len(json.dumps(doc, separators=(",", ":"))) + 10
    assert len(raw) > 2 * budget
    out = truncate_response(raw, budget)
    assert json.loads(out) == doc


def test_truncate_json_with_giant_string_parses() -> None:
    from agent_bom.mcp_server_runtime import truncate_response

    raw = json.dumps({"name": "x", "blob": "z" * 200_000})
    out = truncate_response(raw, 10_000)
    assert len(out) <= 10_000
    parsed = json.loads(out)
    assert parsed["name"] == "x"
    assert parsed["blob"].startswith("zzz") and len(parsed["blob"]) < 200_000


# ── 4. workspace roots ───────────────────────────────────────────────────────


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "workspaces"
    (ws / "proj").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", raising=False)
    return ws


def test_workspace_path_rejected_without_configured_root(workspace: Path) -> None:
    from agent_bom.mcp_server_runtime import safe_path

    with pytest.raises(ValueError):
        safe_path(str(workspace / "proj"))


def test_configured_workspace_root_is_accepted(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_server_runtime import safe_path

    other = workspace.parent / "other-root"
    other.mkdir()
    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", os.pathsep.join([str(other), str(workspace)]))
    assert safe_path(str(workspace / "proj")) == (workspace / "proj").resolve()
    assert safe_path(str(workspace)) == workspace.resolve()
    home_proj = Path(os.environ["HOME"]) / "p"
    assert safe_path(str(home_proj)) == home_proj.resolve(), "HOME stays allowed"


def test_workspace_root_does_not_open_siblings_or_traversal(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_server_runtime import safe_path

    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", str(workspace))
    sibling = workspace.parent / "workspaces-evil"
    sibling.mkdir()
    with pytest.raises(ValueError):
        safe_path(str(sibling))
    with pytest.raises(ValueError):
        safe_path(str(workspace / ".." / "workspaces-evil"))
    with pytest.raises(ValueError):
        safe_path(str(workspace / "proj" / ".." / "proj"))


def test_symlink_escaping_workspace_root_is_rejected(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_server_runtime import safe_path

    outside = workspace.parent / "outside"
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", str(workspace))
    with pytest.raises(ValueError):
        safe_path(str(workspace / "escape"))


@pytest.mark.parametrize("bad_root", ["/", "relative/dir", ""])
def test_unsafe_workspace_roots_are_ignored(workspace: Path, monkeypatch: pytest.MonkeyPatch, bad_root: str) -> None:
    from agent_bom.mcp_server_runtime import mcp_workspace_roots, safe_path

    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", bad_root)
    assert Path("/") not in mcp_workspace_roots()
    with pytest.raises(ValueError):
        safe_path("/etc")


def test_scan_tool_accepts_path_under_workspace_root(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", str(workspace))
    with patch("agent_bom.mcp_server_scan.run_scan_pipeline") as pipeline:

        async def _fake(*, safe_path, config_path=None, **_kwargs):
            safe_path(config_path)
            return [], [], [], []

        pipeline.side_effect = _fake
        result = _call({"config_path": str(workspace / "proj"), "no_discover": True, "offline": True})
    assert result.isError is False
    assert _body(result)["status"] == "no_agents_found"

    outside = _call({"config_path": str(workspace.parent), "no_discover": True, "offline": True})
    assert outside.isError is True


def test_mcp_server_cli_workspace_root_flag_sets_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from click.testing import CliRunner

    from agent_bom.cli._server import mcp_server_cmd

    captured: dict[str, str | None] = {}

    class _Server:
        def run(self, **_kwargs: Any) -> None:
            captured["roots"] = os.environ.get("AGENT_BOM_MCP_WORKSPACE_ROOTS")

    monkeypatch.setattr("agent_bom.mcp_server.create_mcp_server", lambda **_kwargs: _Server())
    other = workspace.parent / "ws2"
    other.mkdir()
    result = CliRunner().invoke(mcp_server_cmd, ["--workspace-root", str(workspace), "--workspace-root", str(other)])
    assert result.exit_code == 0, result.output
    assert captured["roots"] == os.pathsep.join([str(workspace.resolve()), str(other.resolve())])
