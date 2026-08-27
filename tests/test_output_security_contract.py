"""Regression coverage for untrusted data crossing output boundaries."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output import to_csv, to_html, to_markdown
from agent_bom.output.graph import export_graph_html
from agent_bom.output.mermaid import to_mermaid_supply_chain
from agent_bom.output.parquet_fmt import _row_dict
from agent_bom.output.pdf import _build_report_lines
from agent_bom.output.scan_document import to_text
from agent_bom.output.svg import to_svg


def _finding(
    *,
    finding_type: FindingType = FindingType.COMBINATION,
    title: str = "Graph finding",
    description: str = "Evidence description",
    cve_id: str | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        source=FindingSource.GRAPH_ANALYSIS if not cve_id else FindingSource.SBOM,
        asset=Asset(name="attacker-controlled", asset_type="agent"),
        severity="high",
        title=title,
        description=description,
        cve_id=cve_id,
    )


def _report(findings: list[Finding]) -> AIBOMReport:
    return AIBOMReport(
        agents=[],
        blast_radii=[],
        findings=findings,
        generated_at=datetime(2026, 1, 1),
        tool_version="0.96.5",
    )


def test_csv_neutralizes_formula_cells_and_keeps_non_cve_cve_id_blank():
    report = _report(
        [
            _finding(
                title="=1+1",
                description="@SUM(1+1)",
            )
        ]
    )
    row = next(csv.DictReader(io.StringIO(to_csv(report).lstrip("\ufeff"))))

    assert row["cve_id"] == ""
    assert row["title"] == "'=1+1"
    assert row["summary"] == "'@SUM(1+1)"


def test_flat_exports_reconcile_legacy_and_unified_cve_streams():
    package = Package(name="legacy", version="1.0.0", ecosystem="pypi")
    vulnerability = Vulnerability(id="CVE-LEGACY-1", severity=Severity.HIGH, summary="legacy")
    legacy = BlastRadius(
        package=package,
        vulnerability=vulnerability,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = _report([_finding(finding_type=FindingType.CVE, title="Unified", cve_id="CVE-UNIFIED-2")])

    rows = list(csv.DictReader(io.StringIO(to_csv(report, [legacy]).lstrip("\ufeff"))))

    assert {row["cve_id"] for row in rows} == {"CVE-LEGACY-1", "CVE-UNIFIED-2"}


def test_graph_html_escapes_script_breakout_and_keeps_policy_findings_offline(tmp_path):
    payload = "</script><script>globalThis.PWNED=1</script>"
    report = _report([_finding(title=payload, description=payload)])
    interactive = tmp_path / "graph.html"
    offline = tmp_path / "offline.html"

    export_graph_html(report, [], str(interactive))
    export_graph_html(report, [], str(offline), offline_assets=True)

    interactive_html = interactive.read_text(encoding="utf-8")
    offline_html = offline.read_text(encoding="utf-8")
    assert payload not in interactive_html
    assert r"\u003c/script\u003e" in interactive_html
    assert "PWNED" in offline_html
    assert "high" in offline_html.lower()


def test_standard_html_escapes_script_breakout_from_embedded_graph_json():
    payload = "</script><script>globalThis.PWNED=1</script>"
    rendered = to_html(_report([_finding(title=payload, description=payload)]))

    assert payload not in rendered
    assert r"\u003c/script\u003e" in rendered


def test_graph_policy_priority_points_to_finding_node():
    from agent_bom.output.graph import _graph_priority_summary

    finding = _finding(title="Policy title")
    assert _graph_priority_summary([finding])[0]["nodeId"] == f"finding:{finding.id}"


def test_graph_element_redaction_preserves_distinct_nodes_and_edge_references():
    from agent_bom.output.graph import sanitize_graph_elements

    first = "ghp_" + "a" * 36
    second = "ghp_" + "b" * 36
    projected, _ = sanitize_graph_elements(
        [
            {"data": {"id": first, "label": first}},
            {"data": {"id": second, "label": second}},
            {"data": {"source": first, "target": second, "type": "reaches"}},
        ]
    )
    node_ids = [element["data"]["id"] for element in projected[:2]]
    edge = projected[2]["data"]

    assert first not in str(projected)
    assert second not in str(projected)
    assert len(set(node_ids)) == 2
    assert edge["source"] == node_ids[0]
    assert edge["target"] == node_ids[1]


def test_human_and_flat_exports_redact_secret_pii_and_credential_urls():
    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    finding = _finding(
        title=f"Exposed {secret}",
        description=f"Owner {email} configured {credential_url}",
    )
    finding.asset.location = credential_url
    finding.evidence = {
        "secret_value": secret,
        "owner_email": email,
        "connection_url": credential_url,
    }
    report = _report([finding])
    report.trust_assessment_data = {
        "verdict": "review",
        "skill_name": secret,
        "source_file": credential_url,
        "overall_recommendation": email,
    }

    for rendered in (to_csv(report), to_markdown(report), to_html(report)):
        assert secret not in rendered
        assert email not in rendered
        assert credential_url not in rendered

    # Rendering must never mutate the finding used by internal correlation.
    assert secret in finding.title


def test_graph_html_redacts_secret_pii_and_credential_urls(tmp_path):
    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    finding = _finding(
        title=f"Exposed {secret}",
        description=f"Owner {email} configured {credential_url}",
    )
    report = _report([finding])
    output = tmp_path / "graph.html"

    export_graph_html(report, [], str(output))

    rendered = output.read_text(encoding="utf-8")
    assert secret not in rendered
    assert email not in rendered
    assert credential_url not in rendered


def test_output_text_fast_path_matches_central_redaction_for_sensitive_shapes():
    from agent_bom.output.finding_views import sanitize_output_text
    from agent_bom.security import sanitize_text

    samples = [
        "ghp_" + "a" * 36,
        "alice.sentinel@example.invalid",
        "postgresql://admin:sentinel-password@db.internal/prod",
        "api_key: abcdefghijklmnop",
        "authorization_header: abcdefghijklmnopqrstuvwxyz",
        "private_key_material = abcdefghijklmnopqrstuvwxyz",
        "safe package label",
    ]
    assert [sanitize_output_text(value) for value in samples] == [sanitize_text(value, max_len=max(1_000, len(value))) for value in samples]


def test_diagram_lake_pdf_and_text_outputs_redact_sensitive_inventory_fields():
    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    package = Package(name=secret, version="1.0.0", ecosystem="pypi")
    server = MCPServer(name=email, command="python", args=[credential_url], packages=[package])
    agent = Agent(
        name=secret,
        agent_type=AgentType.CUSTOM,
        config_path=credential_url,
        mcp_servers=[server],
        source=email,
    )
    finding = _finding(
        finding_type=FindingType.CVE,
        title=f"CVE sentinel {secret}",
        description=f"Owner {email} configured {credential_url}",
        cve_id="CVE-SENTINEL-1",
    )
    finding.asset.name = secret
    finding.asset.identifier = credential_url
    finding.fixed_version = credential_url
    finding.affected_agents = [email]
    finding.affected_servers = [secret]
    finding.exposed_credentials = [secret]
    report = _report([finding])
    report.agents = [agent]
    report.scan_id = secret
    report.executive_summary = f"Contact {email} about {credential_url} and {secret}"

    rendered_outputs = (
        to_mermaid_supply_chain(report),
        to_svg(report, []),
        "\n".join(_build_report_lines(report)),
        to_text(report),
        str(_row_dict(finding, report)),
    )
    for rendered in rendered_outputs:
        assert secret not in rendered
        assert email not in rendered
        assert credential_url not in rendered


def test_ocsf_events_redact_secret_pii_and_credential_urls():
    from agent_bom.output.ocsf import alert_to_ocsf, finding_to_ocsf

    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    alert = {
        "severity": "high",
        "detector": secret,
        "message": f"{secret} {email} {credential_url}",
        "details": {"tool": secret, "connection_url": credential_url},
    }
    finding = _finding(title=f"{secret} {email}", description=credential_url)
    finding.affected_agents = [email]
    finding.exposed_credentials = [secret]

    for event in (alert_to_ocsf(alert), finding_to_ocsf(finding)):
        encoded = json.dumps(event)
        assert secret not in encoded
        assert email not in encoded
        assert credential_url not in encoded


def test_console_attack_flow_and_inventory_redact_sensitive_labels(monkeypatch):
    from rich.console import Console

    import agent_bom.output.console_render as console_render

    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    package = Package(name=secret, version="1.0.0", ecosystem="pypi")
    server = MCPServer(name=secret, command="python", args=[credential_url], packages=[package])
    agent = Agent(
        name=email,
        agent_type=AgentType.CUSTOM,
        config_path=credential_url,
        mcp_servers=[server],
    )
    finding = _finding(finding_type=FindingType.CVE, cve_id="CVE-SENTINEL-1")
    finding.affected_agents = [email]
    finding.affected_servers = [secret]
    finding.exposed_credentials = [credential_url]
    report = _report([finding])
    report.agents = [agent]
    output = io.StringIO()
    monkeypatch.setattr(console_render, "console", Console(file=output, force_terminal=False, color_system=None))

    console_render.print_agent_tree(report)
    console_render.print_attack_flow_tree(report)

    rendered = output.getvalue()
    assert secret not in rendered
    assert email not in rendered
    assert credential_url not in rendered


def test_linked_machine_exports_redact_sensitive_inventory_without_collapsing_ids():
    from agent_bom.output import to_cyclonedx, to_sarif, to_spdx
    from agent_bom.output.interop_security import sanitize_linked_document
    from agent_bom.output.spdx2_fmt import to_spdx2, to_spdx2_tagvalue

    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    vulnerability = Vulnerability(
        id="CVE-SENTINEL-1",
        severity=Severity.HIGH,
        summary=f"{secret} {email} {credential_url}",
    )
    package = Package(name=secret, version="1.0.0", ecosystem="pypi", vulnerabilities=[vulnerability])
    server = MCPServer(name=email, command="python", args=[credential_url], packages=[package])
    agent = Agent(
        name=secret,
        agent_type=AgentType.CUSTOM,
        config_path=credential_url,
        mcp_servers=[server],
        source=email,
    )
    report = _report([])
    report.agents = [agent]

    rendered = (
        json.dumps(to_cyclonedx(report)),
        json.dumps(to_spdx(report)),
        json.dumps(to_spdx2(report)),
        to_spdx2_tagvalue(report),
        json.dumps(to_sarif(report)),
    )
    for output in rendered:
        assert secret not in output
        assert email not in output
        assert credential_url not in output

    first = "ghp_" + "a" * 36
    second = "ghp_" + "b" * 36
    linked = sanitize_linked_document(
        {
            "components": [{"bom-ref": first}, {"bom-ref": second}],
            "dependencies": [{"ref": first, "dependsOn": [second]}],
        }
    )
    ids = [component["bom-ref"] for component in linked["components"]]
    assert len(set(ids)) == 2
    assert linked["dependencies"][0] == {"ref": ids[0], "dependsOn": [ids[1]]}

    sarif_linked = sanitize_linked_document(
        {
            "rules": [{"id": first}, {"id": second}],
            "results": [{"ruleId": first}, {"ruleId": second}],
        }
    )
    rule_ids = [rule["id"] for rule in sarif_linked["rules"]]
    assert len(set(rule_ids)) == 2
    assert [result["ruleId"] for result in sarif_linked["results"]] == rule_ids
