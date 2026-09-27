"""The compliance narrative tells the whole, countable truth about a saved scan.

* Non-advisory findings (committed credentials, personal data, code flaws) carry
  control tags in the saved report; the narrative must evaluate them instead of
  reading only the package blast-radius block.
* The "N of M framework mappings" sentence must count exactly the framework
  sections the markdown renders.
* The executive headline names the top risks, how many findings reach an AI
  agent, and each risk's owner/SLA ("unassigned" when nobody owns it) without
  claiming certification.
"""

from __future__ import annotations

import json
import re

from click.testing import CliRunner

from agent_bom.cli._history import compliance_narrative_cmd


def _saved_scan(tmp_path, *, owner: str | None = None):
    report = {
        "generated_at": "2026-09-20T10:00:00+00:00",
        "summary": {"total_agents": 2, "total_packages": 1},
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2023-32681",
                "severity": "medium",
                "package": "requests@2.28.0",
                "ecosystem": "pypi",
                "fixed_version": "2.31.0",
                "risk_score": 4.0,
                "affected_agents": ["claude-desktop"],
                "affected_servers": ["filesystem"],
                "nist_csf_tags": ["PR.AA-01"],
            }
        ],
        "findings": [
            {
                "finding_type": "CVE",
                "cve_id": "CVE-2023-32681",
                "severity": "medium",
                "asset": {"name": "filesystem", "asset_type": "mcp_server"},
                "evidence": {"package_name": "requests", "package_version": "2.28.0"},
                "owner": owner,
                "sla_due_at": "2026-12-19T10:00:00+00:00",
                "nist_csf_tags": ["PR.AA-01"],
            },
            {
                "finding_type": "CREDENTIAL_EXPOSURE",
                "id": "secret-1",
                "title": "Hardcoded credential: GitHub Token",
                "severity": "critical",
                "risk_score": 9.0,
                "asset": {"name": "GitHub Token in .mcp.json", "asset_type": "file", "location": ".mcp.json"},
                "affected_agents": ["claude-desktop", "cursor"],
                "owner": None,
                "sla_due_at": "2026-09-27T10:00:00+00:00",
                "nist_csf_tags": ["PR.AA-01"],
                "soc2_tags": ["CC6.1"],
                "owasp_mcp_tags": ["MCP01"],
            },
        ],
    }
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report))
    return path


def _run(path, *args):
    result = CliRunner().invoke(compliance_narrative_cmd, [str(path), *args])
    assert result.exit_code == 0, result.output
    return result.output


def test_credential_finding_is_evaluated_under_its_controls(tmp_path):
    payload = json.loads(_run(_saved_scan(tmp_path), "--format", "json"))
    csf = next(fn for fn in payload["framework_narratives"] if fn["slug"] == "nist-csf")
    pr_aa = next(c for c in csf["failing_controls"] if c["control_id"] == "PR.AA-01")
    assert "secret-1" in pr_aa["affected_findings"]
    assert pr_aa["status"] == "fail"
    soc2 = next(fn for fn in payload["framework_narratives"] if fn["slug"] == "soc2")
    assert any(c["control_id"] == "CC6.1" for c in soc2["failing_controls"])


def test_a_hardcoded_secret_is_not_offered_as_a_package_upgrade(tmp_path):
    payload = json.loads(_run(_saved_scan(tmp_path), "--format", "json"))
    packages = {impact["package"] for impact in payload["remediation_impact"]}
    assert packages == {"requests"}


def test_framework_count_matches_rendered_sections(tmp_path):
    out = _run(_saved_scan(tmp_path))
    match = re.search(r"(\d+) of (\d+) framework mappings", out)
    assert match, out
    rendered = [line for line in out.splitlines() if line.startswith("## ") and line != "## Remediation Impact"]
    rendered = [line for line in rendered if line != "## Executive headline"]
    assert int(match.group(2)) == len(rendered)
    # The catalog-backed NIST 800-53 view is part of the NIST 800-53 section, not a 16th framework.
    assert "### NIST SP 800-53 Rev 5 (vendor-asserted)" in out


def test_executive_summary_does_not_truncate_the_framework_list_silently(tmp_path):
    payload = json.loads(_run(_saved_scan(tmp_path), "--format", "json"))
    action = [fn for fn in payload["framework_narratives"] if fn["status"] == "action_required"]
    if len(action) > 3:
        assert f"and {len(action) - 3} more" in payload["executive_summary"]


def test_executive_headline_names_top_risk_reach_and_unassigned_owner(tmp_path):
    out = _run(_saved_scan(tmp_path))
    assert "## Executive headline" in out
    headline = out.split("## Executive headline", 1)[1].split("\n## ", 1)[0]
    assert "Hardcoded credential: GitHub Token" in headline
    assert "2 of 2 findings reach at least one AI agent" in headline
    assert "owner unassigned" in headline
    assert "SLA due 2026-09-27" in headline
    assert "not a compliance certification" in headline


def test_executive_headline_reports_a_named_owner(tmp_path):
    payload = json.loads(_run(_saved_scan(tmp_path, owner="appsec@example.test"), "--format", "json"))
    risks = payload["executive_headline"]["top_risks"]
    cve = next(risk for risk in risks if risk["id"] == "CVE-2023-32681")
    assert cve["owner"] == "appsec@example.test"
    secret = next(risk for risk in risks if risk["id"] == "secret-1")
    assert secret["owner"] is None


def test_executive_headline_with_no_findings_claims_nothing(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"summary": {"total_agents": 1, "total_packages": 3}, "blast_radius": [], "findings": []}))
    payload = json.loads(_run(path, "--format", "json"))
    headline = payload["executive_headline"]
    assert headline["top_risks"] == []
    assert "not a claim that unscanned" in headline["summary"]


def test_a_finding_about_an_agent_counts_as_reaching_that_agent(tmp_path):
    path = tmp_path / "agent.json"
    path.write_text(
        json.dumps(
            {
                "summary": {"total_agents": 1, "total_packages": 0},
                "blast_radius": [],
                "findings": [
                    {
                        "finding_type": "COMBINATION",
                        "id": "combo-1",
                        "title": "AI agent can reach a credential or privileged tool: support-copilot",
                        "severity": "critical",
                        "asset": {"name": "support-copilot", "asset_type": "agent"},
                        "affected_agents": [],
                        "owasp_tags": ["LLM06"],
                    }
                ],
            }
        )
    )
    payload = json.loads(_run(path, "--format", "json"))
    headline = payload["executive_headline"]
    assert "1 of 1 findings reach at least one AI agent" in headline["summary"]
    assert headline["top_risks"][0]["affected_agents"] == ["support-copilot"]
