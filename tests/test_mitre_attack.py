"""Tests for mitre_attack.py — MITRE ATT&CK Enterprise technique mapping."""

from __future__ import annotations

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

# ---------------------------------------------------------------------------
# Helpers for blast radius tests
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check(check_id: str, section: str, status: CheckStatus = CheckStatus.FAIL) -> CISCheckResult:
    return CISCheckResult(
        check_id=check_id,
        title=f"Check {check_id}",
        status=status,
        severity="medium",
        cis_section=section,
    )


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


def test_catalog_nonempty():
    assert len(ATTACK_TECHNIQUES) > 0


def test_catalog_format():
    for tid, name in ATTACK_TECHNIQUES.items():
        assert tid.startswith("T"), f"Expected T-code, got {tid}"
        assert name, f"Empty name for {tid}"


# ---------------------------------------------------------------------------
# tag_cis_check — passing/error checks produce no tags
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [CheckStatus.PASS, CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE])
def test_no_tags_for_non_fail(status):
    c = _check("1.4", "1 - Identity and Access Management", status)
    assert tag_cis_check(c) == []


# ---------------------------------------------------------------------------
# Section-based tagging
# ---------------------------------------------------------------------------


def test_iam_section_tags_valid_accounts():
    c = _check("9.9", "1 - Identity and Access Management")
    tags = tag_cis_check(c)
    assert "T1078" in tags
    assert "T1078.004" in tags


def test_auth_section_tags_valid_accounts():
    c = _check("9.9", "1 - Authentication")
    tags = tag_cis_check(c)
    assert "T1078" in tags or "T1078.004" in tags


def test_logging_section_tags_impair_defenses():
    c = _check("9.9", "2 - Logging")
    tags = tag_cis_check(c)
    assert "T1562" in tags
    assert "T1562.008" in tags


def test_cloudtrail_section_tags_impair_defenses():
    c = _check("9.9", "2 - Logging and CloudTrail")
    tags = tag_cis_check(c)
    assert "T1562.008" in tags


def test_storage_section_tags_cloud_storage():
    c = _check("9.9", "3 - Storage Accounts")
    tags = tag_cis_check(c)
    assert "T1530" in tags


def test_network_section_tags_remote_services():
    c = _check("9.9", "4 - Networking")
    tags = tag_cis_check(c)
    assert "T1021" in tags


def test_access_control_section_tags_elevation():
    c = _check("9.9", "5 - Access Control")
    tags = tag_cis_check(c)
    assert "T1548" in tags or "T1098" in tags


# ---------------------------------------------------------------------------
# Check-ID specific overrides
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "check_id,expected_tag",
    [
        ("1.1", "T1556"),  # security defaults / MFA
        ("1.2", "T1556"),  # MFA for all users
        ("1.4", "T1552"),  # root access key
        ("1.5", "T1556"),  # MFA on root
        ("1.6", "T1556"),  # hardware MFA
        ("1.7", "T1552"),  # SA key rotation
        ("1.14", "T1552"),  # access key rotation
        ("1.16", "T1548.005"),  # full admin policy
        ("2.1", "T1562.008"),  # audit disabled
        ("2.2", "T1070"),  # log validation off
        ("3.1", "T1537"),  # public storage
        ("3.3", "T1485"),  # no versioning
        ("4.1", "T1021.004"),  # SSH from internet
        ("4.2", "T1021.001"),  # RDP from internet
        ("6.1", "T1021.001"),  # Azure RDP
        ("6.2", "T1021.004"),  # Azure SSH
        ("8.1", "T1552"),  # Key Vault key no expiry
        ("8.2", "T1552"),  # Key Vault secret no expiry
    ],
)
def test_check_id_overrides(check_id: str, expected_tag: str):
    section = "1 - Identity and Access Management"
    if check_id.startswith("2"):
        section = "2 - Logging"
    elif check_id.startswith("3"):
        section = "3 - Storage Accounts"
    elif check_id.startswith("4"):
        section = "4 - Networking"
    elif check_id.startswith("5"):
        section = "5 - Cloud Storage"
    elif check_id.startswith("6"):
        section = "6 - Networking"
    elif check_id.startswith("8"):
        section = "8 - Key Vault"
    c = _check(check_id, section)
    assert expected_tag in tag_cis_check(c), f"Expected {expected_tag} for check {check_id}"


# ---------------------------------------------------------------------------
# GCP check_id 3.7 disambiguation
# ---------------------------------------------------------------------------


def test_gcp_3_7_network_section_gives_rdp():
    """GCP 3.7 (firewall RDP) should map to T1021.001, not T1537."""
    c = _check("3.7", "3 - Networking")
    tags = tag_cis_check(c)
    assert "T1021.001" in tags
    assert "T1537" not in tags


def test_azure_3_7_storage_section_gives_transfer():
    """Azure 3.7 (public blob) should map to T1537."""
    c = _check("3.7", "3 - Storage Accounts")
    tags = tag_cis_check(c)
    assert "T1537" in tags


# ---------------------------------------------------------------------------
# Output is sorted
# ---------------------------------------------------------------------------


def test_output_is_sorted():
    c = _check("1.4", "1 - Identity and Access Management")
    tags = tag_cis_check(c)
    assert tags == sorted(tags)


# ---------------------------------------------------------------------------
# tag_provenance_finding
# ---------------------------------------------------------------------------


def test_provenance_unsafe_format():
    finding = {"risk_flags": ["unsafe_format:.pt"]}
    tags = tag_provenance_finding(finding)
    assert len(tags) > 0


def test_provenance_no_digest():
    finding = {"risk_flags": ["no_digest"]}
    tags = tag_provenance_finding(finding)
    assert "T1195.002" in tags


def test_provenance_public_large():
    finding = {"risk_flags": ["public_large"]}
    tags = tag_provenance_finding(finding)
    assert "T1530" in tags


def test_provenance_empty_flags():
    finding = {"risk_flags": []}
    assert tag_provenance_finding(finding) == []


def test_provenance_multiple_flags():
    finding = {"risk_flags": ["no_digest", "public_large"]}
    tags = tag_provenance_finding(finding)
    assert "T1195.002" in tags
    assert "T1530" in tags


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


def test_attack_label_known():
    assert attack_label("T1078.004") == "T1078.004 Valid Accounts: Cloud Accounts"


def test_attack_label_unknown():
    assert "T9999" in attack_label("T9999")
    assert "Unknown" in attack_label("T9999")


def test_attack_labels_list():
    result = attack_labels(["T1078", "T1530"])
    assert len(result) == 2
    assert all(isinstance(s, str) for s in result)


# ---------------------------------------------------------------------------
# tag_blast_radius — CWE-based mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cwe,expected_tag",
    [
        ("CWE-78", "T1059"),  # OS command injection → execution
        ("CWE-78", "T1059.004"),  # also unix shell
        ("CWE-89", "T1190"),  # SQL injection → exploit public-facing app
        ("CWE-22", "T1083"),  # path traversal → file discovery
        ("CWE-79", "T1189"),  # XSS → drive-by compromise
        ("CWE-79", "T1185"),  # XSS → browser session hijacking
        ("CWE-352", "T1185"),  # CSRF → session hijacking
        ("CWE-601", "T1189"),  # open redirect → drive-by
        ("CWE-918", "T1090"),  # SSRF → proxy
        ("CWE-287", "T1078"),  # improper auth → valid accounts
        ("CWE-306", "T1078"),  # missing auth → valid accounts
        ("CWE-269", "T1548"),  # privilege management → elevation
        ("CWE-798", "T1552"),  # hard-coded creds → unsecured credentials
        ("CWE-326", "T1600"),  # weak encryption
        ("CWE-327", "T1600"),  # broken crypto
        ("CWE-319", "T1040"),  # cleartext transmission → network sniffing
        ("CWE-200", "T1005"),  # info exposure → data from local system
        ("CWE-125", "T1499"),  # out-of-bounds read → DoS
        ("CWE-787", "T1499"),  # out-of-bounds write → DoS
        ("CWE-416", "T1499"),  # use-after-free → DoS
        ("CWE-400", "T1499"),  # resource exhaustion → DoS
        ("CWE-1333", "T1499"),  # ReDoS → DoS
        ("CWE-494", "T1195.002"),  # download without integrity check
        ("CWE-502", "T1059"),  # deserialization → execution
        ("CWE-502", "T1190"),  # deserialization → exploit app
        ("CWE-611", "T1083"),  # XXE → file discovery
        ("CWE-611", "T1190"),  # XXE → exploit app
    ],
)
def test_cwe_to_attack_mapping(cwe: str, expected_tag: str):
    tags = tag_blast_radius(_br(cwe_ids=[cwe]))
    assert expected_tag in tags, f"Expected {expected_tag} for {cwe}, got {tags}"


def test_cwe_normalisation_without_prefix():
    """Accepts bare '78' as well as 'CWE-78'."""
    tags_with_prefix = tag_blast_radius(_br(cwe_ids=["CWE-78"]))
    tags_bare = tag_blast_radius(_br(cwe_ids=["78"]))
    assert tags_with_prefix == tags_bare


def test_cwe_normalisation_lowercase():
    """Accepts 'cwe-78' (case-insensitive)."""
    tags = tag_blast_radius(_br(cwe_ids=["cwe-78"]))
    assert "T1059" in tags


def test_multiple_cwes_combined():
    """Multiple CWEs produce the union of technique sets."""
    tags = tag_blast_radius(_br(cwe_ids=["CWE-78", "CWE-89"]))
    assert "T1059" in tags
    assert "T1190" in tags


def test_unknown_cwe_no_error():
    """Unknown CWE does not raise and returns empty (minus context signals)."""
    tags = tag_blast_radius(_br(cwe_ids=["CWE-99999"]))
    # Should not raise; may still have context-based tags for high severity
    assert isinstance(tags, list)


# ---------------------------------------------------------------------------
# tag_blast_radius — context-based signals
# ---------------------------------------------------------------------------


def test_exposed_credentials_adds_t1552():
    tags = tag_blast_radius(_br(creds=["OPENAI_API_KEY"]))
    assert "T1552" in tags


def test_critical_severity_adds_t1190():
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert "T1190" in tags


def test_high_severity_without_cwe_adds_supply_chain():
    """HIGH+ vuln with no CWE IDs gets supply chain as baseline."""
    tags = tag_blast_radius(_br(severity=Severity.HIGH, cwe_ids=[]))
    assert "T1195.002" in tags


def test_medium_severity_without_cwe_no_supply_chain():
    """MEDIUM severity without CWE does not get supply chain tag."""
    tags = tag_blast_radius(_br(severity=Severity.MEDIUM, cwe_ids=[]))
    assert "T1195.002" not in tags


def test_kev_adds_t1190():
    tags = tag_blast_radius(_br(is_kev=True, severity=Severity.MEDIUM))
    assert "T1190" in tags


def test_exec_tool_adds_t1059():
    exec_tool = MCPTool(name="run_shell", description="Execute shell commands on the server")
    tags = tag_blast_radius(_br(tools=[exec_tool]))
    assert "T1059" in tags


def test_non_exec_tool_no_t1059():
    read_tool = MCPTool(name="read_file", description="Read a file from the filesystem")
    tags = tag_blast_radius(_br(tools=[read_tool]))
    assert "T1059" not in tags


def test_blast_radius_output_is_sorted():
    tags = tag_blast_radius(_br(cwe_ids=["CWE-78", "CWE-89"], creds=["KEY"]))
    assert tags == sorted(tags)


def test_returns_list():
    result = tag_blast_radius(_br())
    assert isinstance(result, list)


def test_catalog_covers_all_tagged_techniques():
    """Every technique returned by tag_blast_radius must be in ATTACK_TECHNIQUES."""
    br = _br(
        cwe_ids=["CWE-78", "CWE-89", "CWE-79", "CWE-798"],
        creds=["API_KEY"],
        severity=Severity.CRITICAL,
        tools=[MCPTool(name="exec_code", description="Run arbitrary code")],
    )
    tags = tag_blast_radius(br)
    for t in tags:
        assert t in ATTACK_TECHNIQUES, f"Technique {t} not in ATTACK_TECHNIQUES catalog"
