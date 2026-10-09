"""Control mappings for non-advisory findings: committed credentials, personal data, first-party code flaws.

These findings carry no package advisory, so the CVE taggers never see them. Before
the finding-shape mapping they reached the report with empty control lists, and the
compliance narrative left the most audit-relevant evidence (a hardcoded token in an
MCP config) out of every framework section.
"""

from __future__ import annotations

from agent_bom.constants import CWE_COMPLIANCE_MAP
from agent_bom.finding import ast_flow_dict_to_finding, secret_dict_to_finding


def _controls(finding) -> set[tuple[str, str]]:
    return {(tag.framework, tag.control) for tag in finding.normalized_controls()}


def _secret(**overrides):
    payload = {
        "file": "project/app/settings.py",
        "line": 7,
        "type": "GitHub Token",
        "category": "credential",
        "severity": "critical",
        "preview": "ghp_****",
    }
    payload.update(overrides)
    return secret_dict_to_finding(payload)


def test_hardcoded_credential_maps_to_identity_and_credential_controls() -> None:
    finding = _secret()
    assert "PR.AA-01" in finding.nist_csf_tags
    assert "CC6.1" in finding.soc2_tags
    assert "IA-5" in finding.nist_800_53_tags
    assert "LLM02" in finding.owasp_tags  # Sensitive Information Disclosure (2025)
    # ISO comes through NIST's published IA-5 crosswalk, never a vendor catch-all.
    assert "A.5.17" in finding.iso_27001_tags
    # A secret in an application settings file is not MCP token mismanagement.
    assert "MCP01" not in finding.owasp_mcp_tags
    controls = _controls(finding)
    assert ("nist_csf", "PR.AA-01") in controls
    assert ("soc2", "CC6.1") in controls


def test_credential_in_mcp_config_also_maps_to_mcp_token_mismanagement() -> None:
    finding = _secret(file="project/.mcp.json", line=3)
    assert "MCP01" in finding.owasp_mcp_tags
    assert "PR.AA-01" in finding.nist_csf_tags


def test_personal_data_maps_to_data_protection_not_credential_controls() -> None:
    finding = _secret(type="US SSN", category="pii", severity="medium")
    assert "PR.DS-01" in finding.nist_csf_tags
    assert "SC-28" in finding.nist_800_53_tags
    assert "LLM02" in finding.owasp_tags  # Sensitive Information Disclosure (2025)
    # Personal data is not a credential: no identity-management or rotation claim.
    assert "PR.AA-01" not in finding.nist_csf_tags
    assert "IA-5" not in finding.nist_800_53_tags


def test_first_party_code_flaw_maps_to_secure_development_controls() -> None:
    finding = ast_flow_dict_to_finding(
        {
            "category": "command_execution",
            "file": "app.py",
            "line": 12,
            "entrypoint": "run",
            "sink": "subprocess.call",
            "title": "Untrusted data reaches shell command execution",
        }
    )
    assert finding.cwe_ids == ["CWE-78"]
    assert "PR.PS-06" in finding.nist_csf_tags
    assert "A.8.28" in finding.iso_27001_tags
    assert "CC8.1" in finding.soc2_tags
    assert "6.2.4" in finding.pci_dss_tags
    assert "CIS-16.1" in finding.cis_tags
    # CWE-78 row: input validation + malicious-code controls.
    assert {"SI-10", "SI-3"} <= set(finding.nist_800_53_tags)
    assert "LLM05" in finding.owasp_tags  # Improper Output Handling (2025)


def test_code_flaw_without_a_cwe_still_maps_to_secure_development() -> None:
    finding = ast_flow_dict_to_finding({"category": "dynamic_code_execution_eval", "file": "app.py", "line": 3, "sink": "eval"})
    assert "PR.PS-06" in finding.nist_csf_tags
    assert "A.8.28" in finding.iso_27001_tags
    assert "CC8.1" in finding.soc2_tags


def test_mapping_is_idempotent() -> None:
    from agent_bom.compliance_hub import apply_hub_classification

    finding = _secret()
    before = {field: list(getattr(finding, field)) for field in ("nist_csf_tags", "soc2_tags", "iso_27001_tags", "nist_800_53_tags")}
    apply_hub_classification(finding)
    after = {field: list(getattr(finding, field)) for field in before}
    assert before == after


def test_every_mapped_control_exists_in_its_catalog() -> None:
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, control_key_for_tag
    from agent_bom.framework_mapping import nist_to_iso

    catalogs = {metadata.tag_field: dict(metadata.catalog) for metadata in TAG_MAPPED_FRAMEWORKS}
    crosswalk_iso = {iso for nist_id in catalogs["nist_800_53_tags"] for iso in nist_to_iso(nist_id)}
    findings = [
        _secret(),
        _secret(file="x/.mcp.json"),
        _secret(type="US SSN", category="pii"),
        ast_flow_dict_to_finding({"category": "command_execution", "file": "a.py", "line": 1}),
    ]
    for finding in findings:
        for field, catalog in catalogs.items():
            for control in getattr(finding, field, []):
                if field == "iso_27001_tags":
                    assert control in catalog or control in crosswalk_iso, (field, control)
                else:
                    assert control_key_for_tag(control, catalog) is not None, (field, control)


def test_client_side_web_flaws_are_not_data_at_rest_controls() -> None:
    # XSS / CSRF / open redirect act in the victim's browser; they are not
    # evidence against "Data-at-rest is protected".
    for cwe in ("CWE-79", "CWE-80", "CWE-352", "CWE-601"):
        assert "PR.DS-01" not in CWE_COMPLIANCE_MAP[cwe].get("nist_csf", []), cwe
