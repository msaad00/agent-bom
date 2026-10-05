"""Explicit SBOM evidence must not expand to neighboring dependency manifests."""

import json

import pytest
from click.testing import CliRunner

from agent_bom.models import MCPServer, Package, ServerSurface
from agent_bom.parsers import extract_packages


@pytest.fixture
def sbom_with_sibling(tmp_path):
    sbom = tmp_path / "bom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"}],
            }
        )
    )
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "5.1.0", "sibling-only": "1.0.0"}}))
    return sbom


@pytest.mark.parametrize("populated", [True, False])
def test_sbom_extraction_never_reads_neighbor_manifests(sbom_with_sibling, populated):
    packages = [Package(name="express", version="4.18.2", ecosystem="npm")] if populated else []
    server = MCPServer(name="sbom", command="sbom", args=[str(sbom_with_sibling)], surface=ServerSurface.SBOM, packages=packages)
    assert extract_packages(server, resolve_transitive=True) == packages


def test_cli_sbom_preserves_imported_packages_and_versions(sbom_with_sibling, tmp_path):
    from agent_bom.cli import main

    output = tmp_path / "result.json"
    result = CliRunner().invoke(
        main, ["scan", "--sbom", str(sbom_with_sibling), "--offline", "--no-scan", "--no-auto-update-db", "-f", "json", "-o", str(output)]
    )
    assert result.exit_code == 1, result.output
    report = json.loads(output.read_text())
    assert report["scan_run"]["outcome"] == "partial"
    packages = [p for a in report["agents"] for s in a["mcp_servers"] for p in s["packages"]]
    assert [(p["name"], p["version"]) for p in packages] == [("express", "4.18.2")]
    assert report["summary"]["total_packages"] == 1


@pytest.mark.asyncio
async def test_mcp_sbom_retains_only_imported_inventory(sbom_with_sibling, monkeypatch):
    from agent_bom.mcp_server_scan import run_scan_pipeline

    async def scan(agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", scan)
    agents, _, warnings, sources = await run_scan_pipeline(
        safe_path=lambda value: value, sbom_path=str(sbom_with_sibling), no_discover=True, offline=True
    )
    assert warnings == []
    assert sources == ["sbom"]
    packages = [p for a in agents for s in a.mcp_servers for p in s.packages]
    assert [(p.name, p.version) for p in packages] == [("express", "4.18.2")]


def test_api_sbom_retains_only_imported_inventory(sbom_with_sibling, monkeypatch):
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _run_scan_sync
    from agent_bom.api.store import InMemoryJobStore

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: InMemoryJobStore())
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("agent_bom.api.pipeline._persist_graph_snapshot", lambda *_args, **_kwargs: None)
    job = ScanJob(
        job_id="sbom-scope",
        created_at="2026-09-27T00:00:00Z",
        request=ScanRequest(sbom=str(sbom_with_sibling), no_scan=True, offline=True, enrich=False),
    )
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE, job.error
    packages = [p for a in job.result["agents"] for s in a["mcp_servers"] for p in s["packages"]]
    assert [(p["name"], p["version"]) for p in packages] == [("express", "4.18.2")]
