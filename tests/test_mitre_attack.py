"""Tests for mitre_attack.py — MITRE ATT&CK Enterprise technique mapping.

Technique IDs come from the shipped ATT&CK catalog and STIX-derived mappings.
Tests mock catalog helpers so they work offline and stay deterministic.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.mitre_attack import (
    ATTACK_TECHNIQUES,
    attack_label,
    attack_labels,
    tag_blast_radius,
    tag_cis_check,
    tag_provenance_finding,
)
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)

# ─── Minimal catalog fixture ──────────────────────────────────────────────────
#
# A small representative subset of MITRE ATT&CK Enterprise technique metadata
# used to mock mitre_fetch.get_techniques() in every test.
#
# Tactic phase names match the official STIX phase_name field.

_MOCK_TECHNIQUES: dict[str, dict] = {
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["execution"], "description": "", "platforms": []},
    "T1059.004": {"name": "Unix Shell", "tactics": ["execution"], "description": "", "platforms": []},
    # Initial Access
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["initial-access", "privilege-escalation", "defense-evasion", "persistence"],
        "description": "",
        "platforms": [],
    },
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "description": "", "platforms": []},
    "T1195": {"name": "Supply Chain Compromise", "tactics": ["initial-access"], "description": "", "platforms": []},
    "T1195.002": {"name": "Compromise Software Supply Chain", "tactics": ["initial-access"], "description": "", "platforms": []},
    # Credential Access
    "T1552": {"name": "Unsecured Credentials", "tactics": ["credential-access"], "description": "", "platforms": []},
    "T1556": {
        "name": "Modify Authentication Process",
        "tactics": ["credential-access", "defense-evasion", "persistence"],
        "description": "",
        "platforms": [],
    },
    # Defense Evasion
    "T1562": {"name": "Impair Defenses", "tactics": ["defense-evasion"], "description": "", "platforms": []},
    "T1562.008": {"name": "Disable Cloud Logs", "tactics": ["defense-evasion"], "description": "", "platforms": []},
    # Collection / Exfiltration
    "T1530": {"name": "Data from Cloud Storage", "tactics": ["collection"], "description": "", "platforms": []},
    "T1537": {"name": "Transfer Data to Cloud Account", "tactics": ["exfiltration"], "description": "", "platforms": []},
    # Privilege Escalation
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactics": ["privilege-escalation", "defense-evasion"],
        "description": "",
        "platforms": [],
    },
    # Command and Control
    "T1090": {"name": "Proxy", "tactics": ["command-and-control"], "description": "", "platforms": []},
    # Impact
    "T1485": {"name": "Data Destruction", "tactics": ["impact"], "description": "", "platforms": []},
    "T1499": {"name": "Endpoint Denial of Service", "tactics": ["impact"], "description": "", "platforms": []},
    # Discovery
    "T1083": {"name": "File and Directory Discovery", "tactics": ["discovery"], "description": "", "platforms": []},
}

# Minimal CWE → ATT&CK mappings derived from CAPEC for tests
_MOCK_CWE_TO_ATTACK: dict[str, list[str]] = {
    "CWE-78": ["T1059", "T1059.004"],
    "CWE-89": ["T1190"],
    "CWE-22": ["T1083"],
    "CWE-287": ["T1078"],
    "CWE-798": ["T1552"],
    "CWE-502": ["T1059", "T1190"],
    "CWE-400": ["T1499"],
    "CWE-494": ["T1195.002"],
}


def _mock_catalog():
    """Patches mitre_fetch functions with test catalog."""
    return patch.multiple(
        "agent_bom.mitre_fetch",
        get_techniques=lambda: _MOCK_TECHNIQUES,
        get_cwe_to_attack=lambda: _MOCK_CWE_TO_ATTACK,
        build_catalog=lambda **kw: {
            "techniques": _MOCK_TECHNIQUES,
            "cwe_to_attack": _MOCK_CWE_TO_ATTACK,
            "attack_version": "ATT&CK vTEST",
            "fetched_at": 9999999999,
        },
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _check(check_id: str, section: str, status: CheckStatus = CheckStatus.FAIL) -> CISCheckResult:
    return CISCheckResult(
        check_id=check_id,
        title=f"Check {check_id}",
        status=status,
        severity="medium",
        cis_section=section,
    )


def _br(
    *,
    severity: Severity = Severity.HIGH,
    cwe_ids: list[str] | None = None,
    creds: list[str] | None = None,
    tools: list[MCPTool] | None = None,
    pkg_name: str = "flask",
    is_kev: bool = False,
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-9999",
        summary="test vuln",
        severity=severity,
        cwe_ids=cwe_ids or [],
        is_kev=is_kev,
    )
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[MCPServer(name="srv")],
        affected_agents=[Agent(name="a1", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


# ─── Catalog accessors ────────────────────────────────────────────────────────


def test_get_attack_techniques_returns_dict():
    with _mock_catalog():
        from agent_bom.mitre_attack import get_attack_techniques

        result = get_attack_techniques()
    assert isinstance(result, dict)
    assert len(result) > 0


def test_get_attack_techniques_maps_id_to_name():
    with _mock_catalog():
        from agent_bom.mitre_attack import get_attack_techniques

        result = get_attack_techniques()
    assert result["T1059"] == "Command and Scripting Interpreter"


def test_technique_ids_start_with_t():
    with _mock_catalog():
        from agent_bom.mitre_fetch import get_techniques

        techniques = get_techniques()
    for tid in techniques:
        assert tid.startswith("T"), f"Expected T-code, got {tid!r}"


def test_technique_names_nonempty():
    with _mock_catalog():
        from agent_bom.mitre_fetch import get_techniques

        techniques = get_techniques()
    for tid, meta in techniques.items():
        assert meta.get("name"), f"Empty name for {tid}"


def test_techniques_have_tactics():
    with _mock_catalog():
        from agent_bom.mitre_fetch import get_techniques

        techniques = get_techniques()
    for tid, meta in techniques.items():
        assert isinstance(meta.get("tactics"), list), f"Missing tactics for {tid}"


# ─── tag_cis_check — non-fail checks produce no tags ─────────────────────────


@pytest.mark.parametrize("status", [CheckStatus.PASS, CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE])
def test_no_tags_for_non_fail(status):
    with _mock_catalog():
        c = _check("1.4", "1 - Identity and Access Management", status)
        assert tag_cis_check(c) == []


# ─── tag_cis_check — section/keyword → tactic → technique ────────────────────


def test_iam_section_maps_to_credential_or_privilege_techniques():
    with _mock_catalog():
        c = _check("9.9", "1 - Identity and Access Management")
        tags = tag_cis_check(c)
    assert len(tags) > 0
    assert all(t.startswith("T") for t in tags)


def test_logging_section_maps_to_defense_evasion():
    with _mock_catalog():
        c = _check("2.1", "2 - Logging and Monitoring")
        tags = tag_cis_check(c)
    assert "T1562" in tags or "T1562.008" in tags


def test_storage_section_maps_to_collection_or_exfiltration():
    with _mock_catalog():
        c = _check("3.1", "3 - Storage Accounts")
        tags = tag_cis_check(c)
    assert any(t in tags for t in ("T1530", "T1537"))


def test_network_section_maps_to_c2():
    with _mock_catalog():
        c = _check("4.1", "4 - Networking")
        tags = tag_cis_check(c)
    assert "T1090" in tags


def test_privilege_section_maps_to_privilege_escalation():
    with _mock_catalog():
        c = _check("5.1", "5 - Access Control and Privilege")
        tags = tag_cis_check(c)
    assert "T1548" in tags or "T1078" in tags


def test_unknown_section_falls_back_to_initial_access():
    with _mock_catalog():
        c = _check("99.99", "99 - Unrecognised Section")
        tags = tag_cis_check(c)
    assert len(tags) > 0


def test_mfa_keyword_in_title():
    with _mock_catalog():
        check = CISCheckResult(
            check_id="1.1",
            title="Ensure MFA is enabled for all users",
            status=CheckStatus.FAIL,
            severity="high",
            cis_section="1 - Identity",
        )
        tags = tag_cis_check(check)
    assert len(tags) > 0


def test_cis_output_is_sorted():
    with _mock_catalog():
        c = _check("1.4", "1 - Identity and Access Management")
        tags = tag_cis_check(c)
    assert tags == sorted(tags)


# ─── tag_provenance_finding ────────────────────────────────────────────────────


def test_provenance_empty_flags_returns_empty():
    with _mock_catalog():
        assert tag_provenance_finding({"risk_flags": []}) == []


def test_provenance_unsafe_format_maps_to_execution():
    with _mock_catalog():
        tags = tag_provenance_finding({"risk_flags": ["unsafe_format:.pt"]})
    assert len(tags) > 0
    assert "T1059" in tags or any(t.startswith("T") for t in tags)


def test_provenance_no_digest_maps_to_initial_access():
    with _mock_catalog():
        tags = tag_provenance_finding({"risk_flags": ["no_digest"]})
    assert len(tags) > 0


def test_provenance_public_large_maps_to_collection():
    with _mock_catalog():
        tags = tag_provenance_finding({"risk_flags": ["public_large"]})
    assert "T1530" in tags or "T1537" in tags


def test_provenance_multiple_flags():
    with _mock_catalog():
        tags = tag_provenance_finding({"risk_flags": ["no_digest", "public_large"]})
    assert len(tags) > 0


# ─── tag_blast_radius — CWE-based mapping ─────────────────────────────────────


@pytest.mark.parametrize(
    "cwe,expected_tag",
    [
        ("CWE-78", "T1059"),
        ("CWE-78", "T1059.004"),
        ("CWE-89", "T1190"),
        ("CWE-22", "T1083"),
        ("CWE-287", "T1078"),
        ("CWE-798", "T1552"),
        ("CWE-502", "T1059"),
        ("CWE-502", "T1190"),
        ("CWE-400", "T1499"),
        ("CWE-494", "T1195.002"),
    ],
)
def test_cwe_to_attack_mapping(cwe: str, expected_tag: str):
    with _mock_catalog():
        tags = tag_blast_radius(_br(cwe_ids=[cwe]))
    assert expected_tag in tags, f"Expected {expected_tag} for {cwe}, got {tags}"


def test_cwe_normalisation_without_prefix():
    with _mock_catalog():
        tags_with = tag_blast_radius(_br(cwe_ids=["CWE-78"]))
        tags_bare = tag_blast_radius(_br(cwe_ids=["78"]))
    assert tags_with == tags_bare


def test_cwe_normalisation_lowercase():
    with _mock_catalog():
        tags = tag_blast_radius(_br(cwe_ids=["cwe-78"]))
    assert "T1059" in tags


def test_multiple_cwes_combined():
    with _mock_catalog():
        tags = tag_blast_radius(_br(cwe_ids=["CWE-78", "CWE-89"]))
    assert "T1059" in tags
    assert "T1190" in tags


def test_unknown_cwe_no_error():
    with _mock_catalog():
        tags = tag_blast_radius(_br(cwe_ids=["CWE-99999"]))
    assert isinstance(tags, list)


def test_high_severity_without_direct_cwe_mapping_falls_back_to_initial_access():
    with _mock_catalog():
        tags = tag_blast_radius(_br(cwe_ids=["CWE-99999"], severity=Severity.HIGH))
    assert len(tags) > 0


# ─── tag_blast_radius — context-based signals ─────────────────────────────────


def test_exposed_credentials_adds_credential_access_techniques():
    with _mock_catalog():
        tags = tag_blast_radius(_br(creds=["OPENAI_API_KEY"]))
    assert "T1552" in tags or "T1556" in tags


def test_critical_severity_adds_initial_access_techniques():
    with _mock_catalog():
        tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert any(t in tags for t in ("T1190", "T1078", "T1195", "T1195.002"))


def test_kev_adds_initial_access_techniques():
    with _mock_catalog():
        tags = tag_blast_radius(_br(is_kev=True, severity=Severity.MEDIUM))
    assert len(tags) > 0


def test_exec_tool_adds_execution_techniques():
    exec_tool = MCPTool(name="run_shell", description="Execute shell commands on the server")
    with _mock_catalog():
        tags = tag_blast_radius(_br(tools=[exec_tool]))
    assert "T1059" in tags or "T1059.004" in tags


def test_non_exec_tool_does_not_add_execution():
    read_tool = MCPTool(name="read_file", description="Read a file from the filesystem")
    with _mock_catalog():
        tags_read = tag_blast_radius(_br(tools=[read_tool]))
        tags_none = tag_blast_radius(_br(tools=[]))
    exec_read = {t for t in tags_read if t in ("T1059", "T1059.004")}
    exec_none = {t for t in tags_none if t in ("T1059", "T1059.004")}
    assert exec_read == exec_none


def test_blast_radius_output_is_sorted():
    with _mock_catalog():
        tags = tag_blast_radius(_br(cwe_ids=["CWE-78", "CWE-89"], creds=["KEY"]))
    assert tags == sorted(tags)


def test_returns_list():
    with _mock_catalog():
        result = tag_blast_radius(_br())
    assert isinstance(result, list)


def test_all_returned_techniques_in_catalog():
    """Every technique returned must be in the fetched catalog."""
    br = _br(
        cwe_ids=["CWE-78", "CWE-89", "CWE-287", "CWE-798"],
        creds=["API_KEY"],
        severity=Severity.CRITICAL,
        tools=[MCPTool(name="exec_code", description="Run arbitrary code")],
    )
    with _mock_catalog():
        from agent_bom.mitre_fetch import get_techniques

        catalog = get_techniques()
        tags = tag_blast_radius(br)

    for t in tags:
        assert t in catalog, f"Technique {t} not in fetched catalog"


def test_empty_catalog_returns_empty_tags():
    """Gracefully handles empty catalog (network failure)."""
    with patch.multiple(
        "agent_bom.mitre_fetch",
        get_techniques=lambda: {},
        get_cwe_to_attack=lambda: {},
    ):
        tags = tag_blast_radius(_br(cwe_ids=["CWE-78"]))
    assert tags == []


# ─── Labels ───────────────────────────────────────────────────────────────────


def test_attack_label_known():
    with _mock_catalog():
        ATTACK_TECHNIQUES._data = None
        label = attack_label("T1059")
    assert "T1059" in label
    assert "Command and Scripting Interpreter" in label


def test_attack_label_unknown():
    with _mock_catalog():
        ATTACK_TECHNIQUES._data = None
        label = attack_label("T9999")
    assert "T9999" in label
    assert "Unknown" in label


def test_attack_labels_list():
    with _mock_catalog():
        ATTACK_TECHNIQUES._data = None
        result = attack_labels(["T1059", "T1552"])
    assert len(result) == 2
    assert all(isinstance(s, str) for s in result)
