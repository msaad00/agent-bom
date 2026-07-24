"""Advisory prose must survive SARIF export (regression for released 0.97.5).

Every exported SARIF rule carried a placeholder ``fullDescription`` of the form
``Vulnerability CVE-2020-14343``: the exporter routed advisory text through the
runtime-evidence tier-A allowlist, which drops any field name it does not know
— and ``description`` / ``recommendation`` are deliberately absent from that
allowlist. The result was a useless body on every GitHub code-scanning alert.

Public advisory prose (OSV/NVD summaries, CIS remediation guidance) is upstream
published data, not captured runtime evidence, so the exporter sanitizes it
directly instead of routing it through the persistence redactor. The split is
by provenance: scanner text that can quote the scanned repository stays behind
the allowlist, and the closing tests pin both halves — the workspace guard and
the unchanged runtime-evidence redactor.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output.sarif import to_sarif

_SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"

_CVE_SUMMARY = "PyYAML arbitrary code execution via yaml.full_load on untrusted input"
_CIS_RECOMMENDATION = "Remove the root account access key and use short-lived role credentials instead."
_IAC_MESSAGE = "No USER directive; the container runs as root."
_AI_INVENTORY_DESCRIPTION = "text-davinci-003 is deprecated and no longer receives security fixes."
_SECRET_DESCRIPTION = "An AWS secret access key was committed to the repository."


def _report(*, cve_summary: str = _CVE_SUMMARY) -> AIBOMReport:
    """A report spanning every SARIF rule family that carries advisory prose."""
    vuln = Vulnerability(
        id="CVE-2020-14343",
        summary=cve_summary,
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="5.4",
        cwe_ids=["CWE-94"],
    )
    pkg = Package(
        name="pyyaml",
        version="5.3.1",
        ecosystem="pypi",
        purl="pkg:pypi/pyyaml@5.3.1",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude-desktop.json",
        mcp_servers=[],
        version="1.0",
    )
    blast_radius = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    blast_radius.calculate_risk_score()

    secret_finding = Finding(
        finding_type=FindingType.CREDENTIAL_EXPOSURE,
        source=FindingSource.FILESYSTEM,
        asset=Asset(name="config.env", asset_type="package", location="/tmp/app/config.env"),
        severity="high",
        title="Hardcoded AWS secret key",
        description=_SECRET_DESCRIPTION,
        risk_score=8.0,
    )

    report = AIBOMReport(
        agents=[agent],
        blast_radii=[blast_radius],
        findings=[secret_finding],
        scan_sources=["agent_discovery"],
        scan_id="advisory-text-001",
    )
    report.iac_findings_data = {
        "findings": [
            {
                "rule_id": "DKR-001",
                "severity": "high",
                "file_path": "/tmp/app/Dockerfile",
                "line_number": 3,
                "title": "Container runs as root",
                "message": _IAC_MESSAGE,
                "category": "iac",
            }
        ]
    }
    report.cis_benchmark_data = {
        "checks": [
            {
                "check_id": "1.4",
                "status": "fail",
                "severity": "high",
                "title": "Ensure no root account access key exists",
                "recommendation": _CIS_RECOMMENDATION,
                "cis_section": "1.4",
                "resource_ids": ["arn:aws:iam::123456789012:root"],
                "remediation": {
                    "docs": "https://docs.aws.amazon.com/iam",
                    "fix_cli": "aws iam delete-access-key --user-name root",
                    "effort": "low",
                    "priority": 1,
                },
            }
        ]
    }
    report.ai_inventory_data = {
        "components": [
            {
                "type": "deprecated_model",
                "severity": "medium",
                "name": "text-davinci-003",
                "file": "/tmp/app/llm.py",
                "line": 12,
                "description": _AI_INVENTORY_DESCRIPTION,
            }
        ]
    }
    return report


def _rules(doc: dict) -> dict[str, dict]:
    return {rule["id"]: rule for rule in doc["runs"][0]["tool"]["driver"]["rules"]}


@pytest.fixture(scope="module")
def sarif_doc() -> dict:
    return to_sarif(_report())


@pytest.fixture(scope="module")
def rules(sarif_doc: dict) -> dict[str, dict]:
    return _rules(sarif_doc)


# ─── fullDescription carries real advisory prose, never the fallback ────────


def test_cve_rule_full_description_is_the_advisory_summary(rules: dict[str, dict]) -> None:
    """The headline defect: every CVE rule body was ``Vulnerability <id>``."""
    text = rules["CVE-2020-14343"]["fullDescription"]["text"]
    assert text == _CVE_SUMMARY
    assert text != "Vulnerability CVE-2020-14343"


def test_no_rule_falls_back_to_a_placeholder_body(rules: dict[str, dict]) -> None:
    placeholders = {
        rule_id: rule["fullDescription"]["text"]
        for rule_id, rule in rules.items()
        if rule.get("fullDescription", {}).get("text", "").startswith("Vulnerability ")
    }
    assert not placeholders, f"rules still emit placeholder bodies: {placeholders}"


def test_cis_rule_full_description_is_the_recommendation(rules: dict[str, dict]) -> None:
    assert rules["cis/aws/1.4"]["fullDescription"]["text"] == _CIS_RECOMMENDATION


def test_unified_finding_rule_falls_back_to_its_title(rules: dict[str, dict]) -> None:
    """SAST/secret descriptions can quote the scanned repository, so the unified
    finding path keeps the conservative allowlist and shows the title instead."""
    rule = rules["finding/CREDENTIAL_EXPOSURE"]
    assert rule["fullDescription"]["text"] == "Hardcoded AWS secret key"
    assert _SECRET_DESCRIPTION not in json.dumps(rule)


def test_iac_rule_full_description_is_the_message(rules: dict[str, dict]) -> None:
    assert rules["iac/DKR-001"]["fullDescription"]["text"] == _IAC_MESSAGE


def test_ai_inventory_rule_full_description_is_the_description(rules: dict[str, dict]) -> None:
    rule_id = "ai-inventory/deprecated_model/text-davinci-003"
    assert rules[rule_id]["fullDescription"]["text"] == _AI_INVENTORY_DESCRIPTION


def test_iac_result_message_is_the_advisory_message(sarif_doc: dict) -> None:
    [result] = [r for r in sarif_doc["runs"][0]["results"] if r["ruleId"] == "iac/DKR-001"]
    assert result["message"]["text"] == _IAC_MESSAGE


# ─── help: the GitHub alert detail pane (SARIF 2.1.0 §3.49.13) ──────────────


def test_every_rule_carries_a_help_object(rules: dict[str, dict]) -> None:
    missing = [rule_id for rule_id, rule in rules.items() if not rule.get("help", {}).get("text")]
    assert not missing, f"rules without a help body: {missing}"


def test_cve_rule_help_carries_description_and_remediation(rules: dict[str, dict]) -> None:
    help_obj = rules["CVE-2020-14343"]["help"]
    assert _CVE_SUMMARY in help_obj["text"]
    # ``_vulnerability_remediation`` derives "Upgrade pyyaml to 5.4." for a
    # fixable CVE; the detail pane must carry the fix, not just the problem.
    assert "5.4" in help_obj["text"]
    assert _CVE_SUMMARY in help_obj["markdown"]
    assert "https://osv.dev/vulnerability/CVE-2020-14343" in help_obj["markdown"]


def test_cis_rule_help_carries_remediation_command(rules: dict[str, dict]) -> None:
    help_obj = rules["cis/aws/1.4"]["help"]
    assert _CIS_RECOMMENDATION in help_obj["text"]
    assert "aws iam delete-access-key --user-name root" in help_obj["text"]


def test_help_reference_link_cannot_be_broken_out_of() -> None:
    """A CIS ``remediation.docs`` URI is upstream data, so it is not inlined blindly."""
    report = _report()
    report.cis_benchmark_data["checks"][0]["remediation"]["docs"] = "https://evil.example.test/a)[click](javascript:alert(1))"

    rule = _rules(to_sarif(report))["cis/aws/1.4"]

    assert "[click](javascript:" not in rule["help"]["markdown"]
    assert "evil.example.test" not in rule["help"]["markdown"]
    assert "evil.example.test" not in rule["help"]["text"]
    # The recommendation itself still renders.
    assert _CIS_RECOMMENDATION in rule["help"]["markdown"]


def test_document_with_help_is_schema_valid(sarif_doc: dict) -> None:
    """``help`` is a multiformatMessageString on reportingDescriptor."""
    validator = Draft7Validator(json.loads(_SCHEMA_PATH.read_text()))
    errors = sorted(validator.iter_errors(sarif_doc), key=lambda e: list(e.path))
    if errors:
        rendered = "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])
        pytest.fail(f"SARIF document is not schema-valid ({len(errors)} error(s)):\n{rendered}")


# ─── Export-side sanitization of hostile advisory prose ─────────────────────


def test_credential_shaped_advisory_text_is_redacted() -> None:
    hostile = "Exploit proof: authenticate with AKIAIOSFODNN7EXAMPLE against the metadata service"
    doc = to_sarif(_report(cve_summary=hostile))
    text = _rules(doc)["CVE-2020-14343"]["fullDescription"]["text"]
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "REDACTED" in text
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(doc)


def test_advisory_url_credentials_and_query_are_stripped() -> None:
    hostile = "Details at https://attacker:hunter2@evil.example.test/adv?token=abc123 for the writeup"
    text = _rules(to_sarif(_report(cve_summary=hostile)))["CVE-2020-14343"]["fullDescription"]["text"]
    assert "hunter2" not in text
    assert "token=abc123" not in text
    assert "evil.example.test" in text


def test_advisory_absolute_paths_are_reduced_to_a_label() -> None:
    hostile = "Reproduced by reading /Users/victim/.aws/credentials and /opt/app/settings.yml"
    text = _rules(to_sarif(_report(cve_summary=hostile)))["CVE-2020-14343"]["fullDescription"]["text"]
    assert "/Users/victim" not in text
    assert "/opt/app" not in text
    # A credential-shaped basename collapses further; a benign one keeps its name.
    assert "<path:path>" in text
    assert "<path:settings.yml>" in text


def test_advisory_relative_paths_and_urls_keep_their_shape() -> None:
    """Path scrubbing must not eat published advisory content."""
    summary = "Traversal via ../../etc/passwd; see https://osv.dev/vulnerability/CVE-2020-14343"
    text = _rules(to_sarif(_report(cve_summary=summary)))["CVE-2020-14343"]["fullDescription"]["text"]
    assert "../../etc/passwd" in text
    assert "https://osv.dev/vulnerability/CVE-2020-14343" in text


def test_advisory_control_characters_are_stripped() -> None:
    hostile = "Line one\r\nLine\x00two\x1b[31m red"
    text = _rules(to_sarif(_report(cve_summary=hostile)))["CVE-2020-14343"]["fullDescription"]["text"]
    assert "Line one" in text
    assert "\n" not in text
    assert "\x00" not in text
    assert "\x1b" not in text


def test_advisory_markdown_links_are_defanged() -> None:
    """A hostile advisory cannot render its own disguised link in the alert pane."""
    hostile = "Apply the [official patch](https://evil.example.test/payload) immediately"
    rule = _rules(to_sarif(_report(cve_summary=hostile)))["CVE-2020-14343"]
    assert "official patch" in rule["fullDescription"]["text"]
    assert "evil.example.test" not in rule["fullDescription"]["text"]
    assert "](https://evil.example.test/payload)" not in rule["help"]["markdown"]
    # agent-bom's own reference link is the only one the pane renders.
    assert "[Reference](https://osv.dev/vulnerability/CVE-2020-14343)" in rule["help"]["markdown"]


def test_advisory_text_is_length_capped() -> None:
    hostile = "A" * 20_000
    rule = _rules(to_sarif(_report(cve_summary=hostile)))["CVE-2020-14343"]
    assert len(rule["fullDescription"]["text"]) <= 1000
    assert len(rule["help"]["text"]) <= 4000
    assert len(rule["help"]["markdown"]) <= 4000


def test_advisory_email_addresses_are_masked() -> None:
    hostile = "Report issues to security@example.com for coordinated disclosure"
    text = _rules(to_sarif(_report(cve_summary=hostile)))["CVE-2020-14343"]["fullDescription"]["text"]
    assert "security@example.com" not in text
    assert "s***@e***.com" in text


# ─── Guard: workspace-quoting scanner text stays behind the allowlist ───────


def test_scanner_description_quoting_the_workspace_is_still_dropped() -> None:
    """The provenance split: published advisory text exports, scanner text does not."""
    workspace_quote = "Detected in app.py: secret = 'copied-workspace-token'"
    report = _report()
    report.findings[0].description = workspace_quote
    report.findings[0].remediation_guidance = f"Rotate {workspace_quote}"

    encoded = json.dumps(to_sarif(report))

    assert "copied-workspace-token" not in encoded
    assert "Detected in app.py" not in encoded
    # …while the CVE rule on the same report still carries its advisory prose.
    assert _CVE_SUMMARY in encoded


def test_runtime_evidence_redaction_still_drops_advisory_field_names() -> None:
    """The export fix must not loosen the runtime-capture persistence tier.

    ``description`` / ``recommendation`` stay off the tier-A allowlist: a proxy
    or gateway capture that shovels prompt text into a field with one of those
    names is still dropped before it reaches durable storage.
    """
    runtime_capture = {
        "tenant_id": "acme",
        "agent_id": "agent-7",
        "tool_name": "fs.read",
        "description": "user prompt text copied out of the workspace",
        "recommendation": "model output suggesting a fix",
        "prompt": "you are a helpful assistant",
        "tool_output": "root:x:0:0:root:/root:/bin/bash",
        "args": {"path": "/etc/passwd"},
    }

    redacted = redact_for_persistence(runtime_capture, EvidenceTier.SAFE_TO_STORE)

    assert redacted == {"tenant_id": "acme", "agent_id": "agent-7", "tool_name": "fs.read"}
    for dropped in ("description", "recommendation", "prompt", "tool_output", "args"):
        assert dropped not in redacted, f"{dropped} must stay replay-only"


def test_proxy_audit_chain_still_drops_runtime_payloads(tmp_path: Path) -> None:
    """An end-to-end runtime persistence path, not just the redactor helper."""
    from agent_bom.proxy_audit import RotatingAuditLog, write_audit_record

    log_path = str(tmp_path / "audit.jsonl")
    log = RotatingAuditLog(log_path)
    try:
        write_audit_record(
            log,
            {
                "ts": "2026-07-24T12:00:00Z",
                "type": "tools/call",
                "tool": "fs.read",
                "agent_id": "a-1",
                "tenant_id": "acme",
                "policy": "allowed",
                "description": "free text captured off the wire",
                "recommendation": "model-authored guidance",
                "prompt": "this must be dropped",
                "args": {"path": "/etc/passwd"},
            },
        )
    finally:
        log.close()

    record = json.loads(Path(log_path).read_text().splitlines()[0])
    for dropped in ("description", "recommendation", "prompt", "args"):
        assert dropped not in record, f"{dropped} leaked into the proxy audit chain"
    assert record["tool"] == "fs.read"
    assert record["policy"] == "allowed"


def test_sarif_property_bags_still_use_the_persistence_allowlist() -> None:
    """Nested evidence dicts keep the conservative allowlist on export."""
    from agent_bom.output.sarif import _sanitize_sarif_property

    cleaned = _sanitize_sarif_property(
        {
            "tool_name": "fs.read",
            "prompt": "captured runtime prompt",
            "stdout": "captured process output",
        }
    )
    assert cleaned == {"tool_name": "fs.read"}
