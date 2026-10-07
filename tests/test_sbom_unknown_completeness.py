"""Unassessed imported inventory cannot produce an unqualified complete outcome."""

import json

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.evidence.scan_run import effective_scan_run
from agent_bom.models import Agent, AgentType, AIBOMReport


def test_spdx_without_completeness_reports_a_coverage_gap(tmp_path):
    source, output = tmp_path / "input.spdx.json", tmp_path / "report.json"
    source.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "inventory",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-library",
                        "name": "library",
                        "versionInfo": "1.0.0",
                        "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/library@1.0.0"}],
                    }
                ],
            }
        )
    )
    result = CliRunner().invoke(
        main, ["scan", "--sbom", str(source), "--offline", "--no-scan", "--no-auto-update-db", "-f", "json", "-o", str(output)]
    )
    assert result.exit_code == 1, result.output
    report = json.loads(output.read_text())
    assert report["scan_run"]["outcome"] == "partial"
    assert any(issue["code"] == "sbom_inventory_unknown" for issue in report["scan_run"]["issues"])


def test_non_imported_agents_do_not_gain_a_spurious_completeness_gap():
    report = AIBOMReport(agents=[Agent(name="normal", agent_type=AgentType.CUSTOM, config_path="sample.json")])
    assert not any(issue.source == "sbom" for issue in effective_scan_run(report).issues)


def test_explicit_complete_and_incomplete_imports_keep_distinct_outcomes():
    for value, expected in [(True, []), (False, ["sbom_inventory_incomplete"]), (None, ["sbom_inventory_unknown"])]:
        agent = Agent(
            name="imported",
            agent_type=AgentType.CUSTOM,
            config_path="input.json",
            metadata={"sbom_import": {"composition_complete": value}},
        )
        issues = effective_scan_run(AIBOMReport(agents=[agent])).issues
        assert [issue.code for issue in issues if issue.source == "sbom"] == expected
