"""``ScanRequest.format`` must actually change what the scan job returns.

The field is published in the OpenAPI contract with a six-value enum, but no
code read it: a caller asking for ``sarif`` got a job that reported ``done``,
echoed ``request.format: sarif`` back, and returned the plain AI-BOM JSON. SARIF
worked on the CLI and over MCP but not on the API, so headless parity was
broken and the published contract was false.

These tests lock the contract in both directions:

* every declared enum value renders a real document of that format, and
* the default (``json``) path is untouched — no second document, ``result``
  still carries the canonical AI-BOM JSON every other read surface parses.
"""

from __future__ import annotations

import json
from typing import get_args

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync

DECLARED_FORMATS = get_args(ScanRequest.model_fields["format"].annotation)


def _inventory(tmp_path) -> str:
    path = tmp_path / "inv.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "source": "test",
                "agents": [
                    {
                        "name": "inv-agent",
                        "agent_type": "custom",
                        "mcp_servers": [{"name": "inv-server"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def _patch_scan(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [])
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, **k: [])
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)


def _completed_job(tmp_path, monkeypatch, output_format: str) -> ScanJob:
    _patch_scan(monkeypatch)
    job = ScanJob(
        job_id=f"format-contract-{output_format}",
        created_at="2026-08-04T00:00:00Z",
        request=ScanRequest(inventory=_inventory(tmp_path), enrich=False, offline=True, format=output_format),
    )
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE, job.error
    return job


def test_declared_format_enum_matches_the_renderer() -> None:
    """The published enum and the renderer must not drift apart."""
    from agent_bom.output.scan_document import SCAN_DOCUMENT_FORMATS

    assert set(DECLARED_FORMATS) == {"json", "cyclonedx", "sarif", "spdx", "html", "text"}
    assert set(DECLARED_FORMATS) == set(SCAN_DOCUMENT_FORMATS)


def test_renderer_rejects_a_format_it_cannot_produce() -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.scan_document import render_scan_document

    with pytest.raises(ValueError):
        render_scan_document(AIBOMReport(agents=[], blast_radii=[]), "pdf")


def test_sarif_request_returns_a_sarif_document(tmp_path, monkeypatch) -> None:
    job = _completed_job(tmp_path, monkeypatch, "sarif")

    assert job.result_format == "sarif"
    document = job.result_document
    assert isinstance(document, dict), f"expected a SARIF object, got {type(document).__name__}"
    assert "sarif-schema-2.1.0" in str(document.get("$schema", "")), document.get("$schema")
    assert document.get("version") == "2.1.0"
    assert isinstance(document.get("runs"), list) and document["runs"], "SARIF must carry at least one run"


def test_cyclonedx_request_returns_a_cyclonedx_document(tmp_path, monkeypatch) -> None:
    job = _completed_job(tmp_path, monkeypatch, "cyclonedx")

    assert job.result_format == "cyclonedx"
    document = job.result_document
    assert isinstance(document, dict)
    assert document.get("bomFormat") == "CycloneDX"
    assert str(document.get("specVersion", "")).startswith("1.")


def test_spdx_request_returns_an_spdx_document(tmp_path, monkeypatch) -> None:
    job = _completed_job(tmp_path, monkeypatch, "spdx")

    assert job.result_format == "spdx"
    document = job.result_document
    assert isinstance(document, dict)
    # ``--format spdx`` on the CLI emits SPDX 3.0.1 JSON-LD; the API must match it.
    assert "spdx.org" in str(document.get("@context", "")), document.get("@context")
    assert isinstance(document.get("@graph"), list) and document["@graph"]


def test_html_request_returns_an_html_document(tmp_path, monkeypatch) -> None:
    job = _completed_job(tmp_path, monkeypatch, "html")

    assert job.result_format == "html"
    document = job.result_document
    assert isinstance(document, str), f"expected an HTML string, got {type(document).__name__}"
    assert document.lstrip().lower().startswith("<!doctype html")


def test_text_request_returns_a_plain_text_document(tmp_path, monkeypatch) -> None:
    job = _completed_job(tmp_path, monkeypatch, "text")

    assert job.result_format == "text"
    document = job.result_document
    assert isinstance(document, str)
    assert document.startswith("agent-bom ")
    assert "agents=" in document


def test_json_request_leaves_the_canonical_result_untouched(tmp_path, monkeypatch) -> None:
    """The default path must not grow a redundant second copy of the report."""
    job = _completed_job(tmp_path, monkeypatch, "json")

    assert job.result_format == "json"
    assert job.result_document is None
    assert isinstance(job.result, dict)
    assert job.result.get("document_type") == "AI-BOM"


@pytest.mark.parametrize("output_format", DECLARED_FORMATS)
def test_every_declared_format_is_honoured(tmp_path, monkeypatch, output_format: str) -> None:
    """No half-working enum: each published value must produce its own document.

    ``json`` is served by ``result`` itself; every other value must produce a
    distinct rendering rather than silently falling back to the AI-BOM JSON.
    """
    job = _completed_job(tmp_path, monkeypatch, output_format)

    assert job.result_format == output_format
    if output_format == "json":
        assert job.result_document is None
        return
    assert job.result_document is not None, f"format={output_format} was accepted but produced no document"
    if isinstance(job.result_document, dict):
        assert job.result_document.get("document_type") != "AI-BOM", f"format={output_format} silently returned plain AI-BOM JSON"


def test_result_document_survives_a_job_store_round_trip(tmp_path, monkeypatch) -> None:
    """A persisted job must carry the rendered document back, not drop it."""
    from agent_bom.api.store import InMemoryJobStore

    job = _completed_job(tmp_path, monkeypatch, "sarif")
    store = InMemoryJobStore()
    store.put(job)

    reloaded = store.get(job.job_id, tenant_id=job.tenant_id)
    assert reloaded is not None
    assert reloaded.result_format == "sarif"
    assert isinstance(reloaded.result_document, dict)
    assert "sarif-schema-2.1.0" in str(reloaded.result_document.get("$schema", ""))


def test_rendered_sarif_drops_replay_only_evidence() -> None:
    """The rendered document is subject to the same evidence tiering as ``result``.

    ``result["findings"]`` is redacted on the API read path; a SARIF rendering
    that echoed raw scanner evidence would route around that control.
    """
    from agent_bom.models import (
        Agent,
        AgentType,
        AIBOMReport,
        BlastRadius,
        MCPServer,
        Package,
        Severity,
        TransportType,
        Vulnerability,
    )
    from agent_bom.output.scan_document import render_scan_document

    vuln = Vulnerability(id="CVE-2026-4242", summary="RCE", severity=Severity.CRITICAL, cvss_score=9.8)
    pkg = Package(name="demo-lib", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="srv", command="python", transport=TransportType.STDIO, packages=[pkg])
    agent = Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/tmp/a.json", mcp_servers=[server])
    blast = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[blast])
    for finding in report.to_findings():
        finding.evidence = {"raw_request_body": "authorization: Bearer super-secret-token"}

    rendered = json.dumps(render_scan_document(report, "sarif"))
    assert "super-secret-token" not in rendered
    assert "raw_request_body" not in rendered


def test_scan_read_endpoint_serves_the_requested_document(tmp_path, monkeypatch) -> None:
    """The HTTP read path — not just the pipeline — must carry the document."""
    from starlette.testclient import TestClient

    from agent_bom.api.server import _jobs, app, set_job_store
    from agent_bom.api.store import InMemoryJobStore

    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()
    _patch_scan(monkeypatch)

    def _run_inline(job: ScanJob) -> None:
        _run_scan_sync(job)
        store.put(job)

    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", _run_inline)

    client = TestClient(app, raise_server_exceptions=False)
    created = client.post("/v1/scan", json={"offline": True, "format": "sarif"})
    assert created.status_code == 202, created.text
    job_id = created.json()["job_id"]

    fetched = client.get(f"/v1/scan/{job_id}")
    assert fetched.status_code == 200, fetched.text
    body = fetched.json()
    assert body["status"] == JobStatus.DONE.value, body.get("error")
    assert body["result_format"] == "sarif"
    document = body["result_document"]
    assert isinstance(document, dict), f"expected a SARIF object over HTTP, got {type(document).__name__}"
    assert "sarif-schema-2.1.0" in str(document.get("$schema", ""))
    assert document.get("version") == "2.1.0"
