"""Exported cloud context survives an explicit SBOM scan as imported evidence."""

import json

import pytest
from click.testing import CliRunner

from agent_bom.models import AIBOMReport
from agent_bom.output import to_cyclonedx, to_spdx, to_spdx2

EXPORTERS = {"cyclonedx": to_cyclonedx, "spdx": to_spdx, "spdx2": to_spdx2}
KEY = "agent-bom:cloud-inventory:v1"


def cloud_inventory():
    return [
        {
            "provider": "azure",
            "status": "ok",
            "subscription_id": "example-subscription",
            "key_vaults": [
                {
                    "name": "shared",
                    "id": "/subscriptions/example-subscription/providers/Microsoft.KeyVault/vaults/shared",
                    "tags": {"environment": "test"},
                }
            ],
            "warnings": ["Compute inventory denied"],
        },
        {"provider": "gcp", "project_id": "example-project", "status": "access_denied", "instances": []},
    ]


@pytest.mark.parametrize("fmt", EXPORTERS)
def test_cli_cloud_only_sbom_retains_context_and_marks_imported_evidence(fmt, tmp_path):
    from agent_bom.cli import main

    source, result = tmp_path / "bom.json", tmp_path / "result.json"
    source.write_text(json.dumps(EXPORTERS[fmt](AIBOMReport(cloud_inventory_data=cloud_inventory()))))
    response = CliRunner().invoke(
        main, ["scan", "--sbom", str(source), "--offline", "--no-scan", "--no-auto-update-db", "-f", "json", "-o", str(result)]
    )
    assert response.exit_code == 0, response.output
    restored = json.loads(result.read_text())["cloud_inventory"]
    for original, imported in zip(cloud_inventory(), restored, strict=True):
        assert {k: v for k, v in imported.items() if k != "import_provenance"} == original
        assert imported["import_provenance"]["source"] == "sbom"
        assert imported["import_provenance"]["coverage"] == "not_assessed"


@pytest.mark.parametrize("fmt", EXPORTERS)
def test_api_import_retains_cloud_only_inventory(fmt, tmp_path, monkeypatch):
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _run_scan_sync
    from agent_bom.api.store import InMemoryJobStore

    source = tmp_path / "bom.json"
    source.write_text(json.dumps(EXPORTERS[fmt](AIBOMReport(cloud_inventory_data=cloud_inventory()))))
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: InMemoryJobStore())
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda *_a, **_kw: None)
    monkeypatch.setattr("agent_bom.api.pipeline._persist_graph_snapshot", lambda *_a, **_kw: None)
    job = ScanJob(
        job_id="cloud-import",
        created_at="2026-10-04T00:00:00Z",
        request=ScanRequest(sbom=str(source), no_scan=True, offline=True, enrich=False),
    )
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE, job.error
    assert job.result["cloud_inventory"][0]["key_vaults"] == cloud_inventory()[0]["key_vaults"]
    assert job.result["cloud_inventory"][1]["status"] == "access_denied"


@pytest.mark.asyncio
@pytest.mark.parametrize("fmt", EXPORTERS)
async def test_mcp_scan_reexports_imported_context(fmt, tmp_path, monkeypatch):
    from agent_bom.mcp_server_scan import run_scan_pipeline
    from agent_bom.mcp_tools.scanning import scan_impl
    from agent_bom.parsers.sbom_context import read_cloud_context

    source = tmp_path / "bom.json"
    source.write_text(json.dumps(EXPORTERS[fmt](AIBOMReport(cloud_inventory_data=cloud_inventory()))))

    async def scan(*_args, **_kwargs):
        return []

    async def pipeline(config_path, image, sbom_path, package, enrich, **kwargs):
        return await run_scan_pipeline(safe_path=lambda p: p, sbom_path=sbom_path, enrich=enrich, **kwargs)

    monkeypatch.setattr("agent_bom.scanners.scan_agents", scan)
    result = await scan_impl(
        sbom_path=str(source),
        no_discover=True,
        offline=True,
        output_format="cyclonedx",
        _run_scan_pipeline=pipeline,
        _truncate_response=lambda s: s,
    )
    inventory = read_cloud_context(json.loads(result))
    assert inventory[0]["key_vaults"] == cloud_inventory()[0]["key_vaults"]
    assert inventory[0]["import_provenance"]["source"] == "sbom"


def envelope(inventory=None):
    return {
        "schema_version": 1,
        "source": "cloud_inventory",
        "coverage": "not_assessed",
        "inventory": cloud_inventory() if inventory is None else inventory,
    }


def document(evidence):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [],
        "metadata": {"properties": [{"name": KEY, "value": json.dumps(evidence)}]},
    }


@pytest.mark.parametrize(
    "case", ["future", "boolean-version", "complete", "bad-root", "bad-list", "duplicate", "bad-json", "duplicate-keys"]
)
def test_import_rejects_ambiguous_or_invalid_extensions(case, tmp_path):
    from agent_bom.parsers.sbom_context import load_sbom_agent

    evidence = envelope()
    if case == "future":
        evidence["schema_version"] = 2
    if case == "boolean-version":
        evidence["schema_version"] = True
    if case == "complete":
        evidence["coverage"] = "complete"
    if case == "bad-root":
        evidence["inventory"] = "not-inventory"
    if case == "bad-list":
        evidence["inventory"] = ["not-inventory"]
    doc = document(evidence)
    props = doc["metadata"]["properties"]
    if case == "duplicate":
        props.append(dict(props[0]))
    if case == "bad-json":
        props[0]["value"] = "{broken"
    if case == "duplicate-keys":
        props[0]["value"] = '{"schema_version":1,"schema_version":2}'
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        load_sbom_agent(str(source))


def test_spdx_annotation_must_target_document_and_json_keys_can_be_escaped():
    from agent_bom.parsers.sbom_context import read_cloud_context

    doc = to_spdx(AIBOMReport(cloud_inventory_data=cloud_inventory()))
    annotation = next(a for a in doc["@graph"] if a.get("contentType") == "application/json")
    annotation["statement"] = annotation["statement"].replace("agent-bom", "\\u0061gent-bom")
    assert read_cloud_context(doc) == cloud_inventory()
    annotation["subject"] = "https://example.invalid/package"
    with pytest.raises(ValueError, match="SPDX document"):
        read_cloud_context(doc)


@pytest.mark.parametrize("payload", [{}, [], {"status": "disabled"}])
def test_empty_and_disabled_context_survives_import_and_json_export(payload, tmp_path):
    from agent_bom.output.json_fmt import to_redacted_json
    from agent_bom.parsers.sbom_context import imported_cloud_inventory, load_sbom_agent

    source = tmp_path / "bom.json"
    source.write_text(json.dumps(document(envelope(payload))))
    agent, _ = load_sbom_agent(str(source))
    report = AIBOMReport(agents=[agent], cloud_inventory_data=imported_cloud_inventory([agent]))
    restored = to_redacted_json(report)["cloud_inventory"]
    assert restored == payload or {k: v for k, v in restored.items() if k != "import_provenance"} == payload


def test_import_redacts_secrets_retains_native_ids_and_graph_source(tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.output.json_fmt import to_redacted_json
    from agent_bom.parsers.sbom_context import imported_cloud_inventory, load_sbom_agent

    evidence = envelope()
    evidence["inventory"][0]["password"] = "sensitive-test-value"
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(document(evidence)))
    agent, _ = load_sbom_agent(str(source))
    report = to_redacted_json(AIBOMReport(agents=[agent], cloud_inventory_data=imported_cloud_inventory([agent])))
    assert "sensitive-test-value" not in json.dumps(report)
    graph = build_unified_graph_from_report(report)
    resource = next(n for n in graph.nodes.values() if n.attributes.get("resource_name") == "shared")
    assert "sbom-import" in resource.data_sources
    assert resource.attributes["resource_id"] == cloud_inventory()[0]["key_vaults"][0]["id"]


def test_live_enrichment_does_not_overwrite_imported_inventory(monkeypatch):
    from agent_bom.scan_enrichment import enrich_report_with_estate_discovery

    report = AIBOMReport(cloud_inventory_data=cloud_inventory())
    fresh = {"provider": "aws", "status": "ok", "account_id": "fresh-account"}
    monkeypatch.setattr("agent_bom.scan_enrichment.collect_cloud_inventory", lambda **_: [fresh])
    monkeypatch.setattr("agent_bom.scan_enrichment.collect_identity_discovery", lambda: None)
    enrich_report_with_estate_discovery(report)
    assert report.cloud_inventory_data == cloud_inventory() + [fresh]


@pytest.mark.parametrize("input_format", EXPORTERS)
@pytest.mark.parametrize("output_format", EXPORTERS)
def test_cross_format_roundtrip_retains_native_cloud_scope(input_format, output_format, tmp_path):
    from agent_bom.parsers.sbom_context import imported_cloud_inventory, load_sbom_agent, read_cloud_context

    source = tmp_path / "bom.json"
    source.write_text(json.dumps(EXPORTERS[input_format](AIBOMReport(cloud_inventory_data=cloud_inventory()))))
    agent, _ = load_sbom_agent(str(source))
    report = AIBOMReport(agents=[agent], cloud_inventory_data=imported_cloud_inventory([agent]))
    restored = read_cloud_context(EXPORTERS[output_format](report))
    assert restored[0]["key_vaults"] == cloud_inventory()[0]["key_vaults"]
    assert restored[1]["status"] == "access_denied"


@pytest.mark.parametrize("bad", ['{"bomFormat":"CycloneDX","components":[],"x":NaN}', "[]", '{"x":1,"x":2}'])
def test_rejects_invalid_outer_document(bad, tmp_path):
    from agent_bom.parsers.sbom_context import load_sbom_agent

    source = tmp_path / "bom.json"
    source.write_text(bad)
    with pytest.raises(ValueError):
        load_sbom_agent(str(source))


def test_bounded_file_read_rejects_oversize_before_json_parse(tmp_path, monkeypatch):
    from agent_bom.parsers import sbom_context

    monkeypatch.setattr(sbom_context, "_MAX_BYTES", 64)
    source = tmp_path / "bom.json"
    source.write_bytes(b" " * 65)
    with pytest.raises(ValueError, match="import limit"):
        sbom_context.load_sbom_agent(str(source))


@pytest.mark.asyncio
async def test_mcp_invalid_extension_raises_validation_error(tmp_path):
    from agent_bom.mcp_server_scan import McpScanValidationError, run_scan_pipeline

    source = tmp_path / "bom.json"
    source.write_text(json.dumps(document({**envelope(), "schema_version": 2})))
    with pytest.raises(McpScanValidationError):
        await run_scan_pipeline(safe_path=lambda p: p, sbom_path=str(source), no_discover=True, offline=True)
