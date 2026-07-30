"""E2E surface tests for #665 remediation field.

Verifies the CIS ``remediation`` dict reaches CLI, HTML report, and
SARIF output surfaces (JSON already covered by existing output tests).
"""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from agent_bom.cloud.cis_remediation import build_remediation
from agent_bom.models import AIBOMReport
from agent_bom.output import print_compact_cis_posture
from agent_bom.output.html import _cis_benchmark_section
from agent_bom.output.sarif import to_sarif


def _bundle_with_remediation(cloud: str = "aws") -> dict:
    """Minimal CIS bundle dict matching what ``<cloud>_CISReport.to_dict()``
    produces, with a failed check carrying a structured remediation
    dict."""
    return {
        "benchmark": f"CIS {cloud.upper()} Foundations",
        "benchmark_version": "3.0",
        "account_id": "123456789012" if cloud == "aws" else None,
        "pass_rate": 75.0,
        "passed": 3,
        "failed": 1,
        "total": 4,
        "checks": [
            {
                "check_id": "1.4",
                "title": "No root account access keys",
                "status": "fail",
                "severity": "high",
                "evidence": "Root access key present.",
                "resource_ids": ["root"],
                "recommendation": "Remove root access keys.",
                "remediation": {
                    "why": "Root account access keys allow full account takeover with no per-user audit trail.",
                    "fix_cli": None,
                    "fix_console": (
                        "AWS Organizations → Root access management, or approved break-glass root session → "
                        "IAM → Security credentials → Delete access key → sign out immediately"
                    ),
                    "effort": "manual",
                    "priority": 1,
                    "docs": "https://example/docs",
                    "guardrails": ["identity", "least-privilege", "priv-escalation", "zero-trust"],
                    "requires_human_review": True,
                },
                "cis_section": "1 - Identity and Access Management",
                "attack_techniques": [],
            },
            {
                "check_id": "1.8",
                "title": "Password policy",
                "status": "pass",
                "severity": "medium",
                "evidence": "policy configured",
                "resource_ids": [],
                "recommendation": "",
                "remediation": {
                    "why": "Failure indicates: password policy.",
                    "fix_cli": None,
                    "fix_console": "",
                    "effort": "manual",
                    "priority": 2,
                    "docs": "",
                    "guardrails": [],
                    "requires_human_review": True,
                },
                "cis_section": "1 - Identity and Access Management",
                "attack_techniques": [],
            },
        ],
    }


def _report_with_aws_cis() -> AIBOMReport:
    report = AIBOMReport(tool_version="0.77.1")
    report.cis_benchmark_data = _bundle_with_remediation("aws")
    return report


def _report_with_verified_aws_cis() -> tuple[AIBOMReport, str]:
    command = "aws cloudtrail update-trail --name <TRAIL_NAME_OR_ARN> --enable-log-file-validation"
    bundle = _bundle_with_remediation("aws")
    check = bundle["checks"][0]
    check.update(
        {
            "check_id": "3.2",
            "title": "CloudTrail log file validation enabled",
            "status": "fail",
            "severity": "medium",
            "evidence": "Trail has log file validation disabled.",
            "resource_ids": ["arn:aws:cloudtrail:us-east-1:123456789012:trail/audit"],
            "recommendation": "Enable log file validation on all CloudTrail trails.",
            "cis_section": "3 - Logging",
            "remediation": build_remediation(
                cloud="aws",
                benchmark_version="3.0",
                check_id="3.2",
                title="CloudTrail log file validation enabled",
                severity="medium",
                recommendation="Enable log file validation on all CloudTrail trails.",
                cis_section="3 - Logging",
            ),
        }
    )
    report = AIBOMReport(tool_version="0.98.2")
    report.cis_benchmark_data = bundle
    return report, command


# ── CLI ──────────────────────────────────────────────────────────────────


def test_cli_compact_cis_posture_renders_remediation():
    report = _report_with_aws_cis()
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=200)

    # Patch the module-level console with our capture console.
    import agent_bom.output as output_mod

    original = output_mod.console
    output_mod.console = con
    try:
        print_compact_cis_posture(report)
    finally:
        output_mod.console = original

    out = buf.getvalue()
    assert "Cloud Security Posture" in out
    assert "AWS" in out
    assert "1.4" in out  # check_id
    assert "Security credentials" in out  # manual console path surfaced
    assert "priv-escalation" in out or "least-privilege" in out  # guardrails surfaced
    assert "review" in out  # requires_human_review flag shown


def test_provider_verified_command_reaches_cli_html_and_sarif():
    report, command = _report_with_verified_aws_cis()
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=240)

    import agent_bom.output as output_mod

    original = output_mod.console
    output_mod.console = con
    try:
        print_compact_cis_posture(report)
    finally:
        output_mod.console = original

    cli = buf.getvalue()
    assert "update-trail" in cli
    assert "<TRAIL_NAME_OR_ARN>" in cli
    assert "review" in cli.lower()

    html = _cis_benchmark_section(report)
    assert "update-trail" in html
    assert "&lt;TRAIL_NAME_OR_ARN&gt;" in html

    sarif = to_sarif(report)
    result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "cis/aws/3.2")
    props = result["properties"]
    assert props["fix_cli"] == command
    assert props["remediation"]["fix_cli"] == command
    assert props["requires_human_review"] is True


def test_cli_compact_cis_posture_silent_without_cis_data():
    report = AIBOMReport(tool_version="0.77.1")
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=200)
    import agent_bom.output as output_mod

    original = output_mod.console
    output_mod.console = con
    try:
        print_compact_cis_posture(report)
    finally:
        output_mod.console = original

    assert buf.getvalue() == ""


def test_cli_error_only_cis_is_error_and_surfaces_unevaluable_detail():
    report = AIBOMReport(tool_version="0.77.1")
    report.snowflake_cis_benchmark_data = {
        "pass_rate": 0.0,
        "checks": [
            {
                "check_id": "1.1",
                "title": "MFA source preflight",
                "status": "error",
                "severity": "critical",
                "evidence": "ACCOUNT_USAGE heartbeat is stale",
            }
        ],
    }
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=200)
    import agent_bom.output as output_mod

    original = output_mod.console
    output_mod.console = con
    try:
        print_compact_cis_posture(report)
    finally:
        output_mod.console = original

    out = buf.getvalue()
    assert "ERROR" in out
    assert "1 unevaluable" in out
    assert "ACCOUNT_USAGE heartbeat is stale" in out
    assert " PASS " not in out
    assert "no failed checks" not in out


def test_mixed_provider_headings_do_not_claim_databricks_is_cis():
    report = AIBOMReport(tool_version="0.77.1")
    report.databricks_cis_benchmark_data = {
        "checks": [{"check_id": "db-1", "title": "Best practice", "status": "pass", "severity": "low"}],
        "passed": 1,
        "failed": 0,
        "pass_rate": 100.0,
    }
    html = _cis_benchmark_section(report)
    assert "Cloud Security Posture" in html
    assert "CIS Benchmark Posture" not in html


# ── HTML ─────────────────────────────────────────────────────────────────


def test_html_cis_section_emits_remediation():
    report = _report_with_aws_cis()
    html = _cis_benchmark_section(report)
    assert html, "expected non-empty section when CIS data is present"
    assert 'id="cisbenchmarks"' in html
    assert "AWS" in html
    assert "1.4" in html
    assert "Security credentials" in html  # manual console path
    assert "priv-escalation" in html or "least-privilege" in html
    assert "review" in html  # human-review flag rendered


def test_html_cis_section_empty_when_no_data():
    report = AIBOMReport(tool_version="0.77.1")
    assert _cis_benchmark_section(report) == ""


def test_html_error_only_cis_is_incomplete_not_pass_or_zero_of_zero():
    report = AIBOMReport(tool_version="0.77.1")
    report.snowflake_cis_benchmark_data = {
        "passed": 0,
        "failed": 0,
        "errored": 1,
        "evaluated": 0,
        "pass_rate": 0.0,
        "checks": [{"check_id": "1.1", "title": "MFA", "status": "error", "severity": "critical", "evidence": "source unavailable"}],
    }
    html = _cis_benchmark_section(report)
    assert "ERROR" in html
    assert "1 unevaluable" in html
    assert "0/0 checks" not in html
    assert "PASS" not in html


def test_html_mixed_cis_is_incomplete_and_counts_unevaluable():
    report = AIBOMReport(tool_version="0.77.1")
    report.snowflake_cis_benchmark_data = {
        "passed": 1,
        "failed": 0,
        "errored": 1,
        "evaluated": 1,
        "pass_rate": 100.0,
        "checks": [
            {"check_id": "1.1", "title": "MFA", "status": "pass", "severity": "critical"},
            {"check_id": "5.1", "title": "PUBLIC", "status": "error", "severity": "high", "evidence": "denied"},
        ],
    }
    html = _cis_benchmark_section(report)
    assert "INCOMPLETE" in html
    assert "1 unevaluable" in html
    assert "PASS" not in html


# ── SARIF ────────────────────────────────────────────────────────────────


def test_sarif_includes_cis_result_with_remediation_properties():
    report = _report_with_aws_cis()
    sarif = to_sarif(report)
    runs = sarif["runs"][0]
    rule_ids = {r["id"] for r in runs["tool"]["driver"]["rules"]}
    assert "cis/aws/1.4" in rule_ids

    cis_results = [r for r in runs["results"] if r["ruleId"] == "cis/aws/1.4"]
    assert len(cis_results) == 1
    props = cis_results[0].get("properties", {})
    # Structured remediation is preserved as a nested dict.
    assert props["remediation"]["fix_cli"] is None
    # Flat convenience keys are also present for SARIF consumers that
    # don't parse nested dicts.
    assert props["fix_cli"] is None
    assert "Security credentials" in props["fix_console"]
    assert props["priority"] == 1
    assert "priv-escalation" in props["guardrails"]
    assert props["requires_human_review"] is True


def test_sarif_skips_passing_cis_checks():
    report = _report_with_aws_cis()
    sarif = to_sarif(report)
    cis_result_ids = {r["ruleId"] for r in sarif["runs"][0]["results"] if r["ruleId"].startswith("cis/")}
    # 1.8 passed — must not appear as a SARIF result.
    assert "cis/aws/1.8" not in cis_result_ids
