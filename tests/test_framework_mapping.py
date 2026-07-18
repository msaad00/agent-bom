"""Characterization + contract tests for the unified framework-mapping layer.

The framework tags a finding evidences were historically resolved through
three parallel code paths:

  1. CWE -> per-framework control IDs, inlined identically in every
     blast-radius tagger (``CWE_COMPLIANCE_MAP.get(cwe).get(framework)``).
  2. CVE-intrinsic framework tagging (``vuln_compliance.tag_vulnerability``).
  3. Finding source/asset/finding-type -> framework slug fan-out
     (``compliance_hub.select_frameworks``).

This suite pins the EXACT tag output of every path against golden literals so
the consolidation onto ``agent_bom.framework_mapping`` is provably
behavior-preserving: the values below were captured from the pre-refactor code
and must not move. If a value here changes, the refactor changed behavior and
the change is a bug — not a test to update.
"""

from __future__ import annotations

from agent_bom import (
    cis_controls,
    iso_27001,
    nist_800_53,
    nist_csf,
    owasp,
    pci_dss,
    soc2,
    vuln_compliance,
)
from agent_bom.compliance_hub import select_frameworks
from agent_bom.finding import FindingSource, FindingType
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)


def _br(
    cwes: list[str],
    *,
    severity: Severity = Severity.HIGH,
    pkg_name: str = "flask",
    is_kev: bool = False,
    fixed_version: str | None = "2.0.0",
    creds: list[str] | None = None,
    tools: list | None = None,
    num_agents: int = 1,
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-0001",
        summary="x",
        severity=severity,
        fixed_version=fixed_version,
        is_kev=is_kev,
        cwe_ids=cwes,
    )
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    agents = [Agent(name=f"a{i}", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp") for i in range(num_agents)]
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[MCPServer(name="s")],
        affected_agents=agents,
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


# A single representative finding exercised across every tagger: a CRITICAL,
# KEV, fixable vuln on an AI package with exposed credentials and two CWEs —
# one lowercase (`cwe-798`) to lock the case-normalization behavior of the
# blast-radius taggers.
def _representative_br() -> BlastRadius:
    return _br(
        ["CWE-89", "cwe-798"],
        severity=Severity.CRITICAL,
        pkg_name="openai",
        is_kev=True,
        creds=["API_KEY"],
    )


# ─── Path 1 + 2: blast-radius taggers (CWE -> per-framework controls) ─────────


def test_cis_tags_unchanged():
    assert cis_controls.tag_blast_radius(_representative_br()) == [
        "CIS-02.1",
        "CIS-02.3",
        "CIS-02.7",
        "CIS-07.1",
        "CIS-07.4",
        "CIS-07.5",
        "CIS-16.1",
        "CIS-16.12",
    ]


def test_nist_800_53_tags_unchanged():
    assert nist_800_53.tag_blast_radius(_representative_br()) == [
        "AC-3",
        "AC-6",
        "CM-6",
        "CM-8",
        "IA-5",
        "IR-5",
        "IR-6",
        "RA-5",
        "RA-7",
        "SC-28",
        "SI-10",
        "SI-2",
        "SI-3",
        "SI-4",
        "SI-5",
        "SR-11",
        "SR-3",
        "SR-4",
    ]


def test_iso_27001_tags_unchanged():
    assert iso_27001.tag_blast_radius(_representative_br()) == [
        "A.5.19",
        "A.5.20",
        "A.5.21",
        "A.5.23",
        "A.5.28",
        "A.8.24",
        "A.8.28",
        "A.8.8",
        "A.8.9",
    ]


def test_owasp_tags_unchanged():
    assert owasp.tag_blast_radius(_representative_br()) == [
        "LLM02",
        "LLM04",
        "LLM05",
        "LLM06",
    ]


def test_soc2_tags_unchanged():
    assert soc2.tag_blast_radius(_representative_br()) == [
        "CC6.1",
        "CC6.8",
        "CC7.1",
        "CC7.2",
        "CC7.4",
        "CC8.1",
        "CC9.1",
        "CC9.2",
    ]


def test_nist_csf_tags_unchanged():
    assert nist_csf.tag_blast_radius(_representative_br()) == [
        "DE.CM-09",
        "GV.SC-05",
        "GV.SC-07",
        "ID.AM-05",
        "ID.RA-01",
        "ID.RA-02",
        "ID.RA-05",
        "PR.AA-01",
        "PR.DS-01",
        "RS.AN-03",
        "RS.MI-02",
    ]


def test_pci_dss_tags_unchanged():
    assert pci_dss.tag_blast_radius(_representative_br()) == [
        "11.3.1",
        "11.3.2",
        "12.3.1",
        "2.2.1",
        "6.3.1",
        "6.3.2",
        "6.3.3",
        "8.6.1",
    ]


def test_vuln_compliance_tags_unchanged():
    br = _representative_br()
    assert vuln_compliance.tag_vulnerability(br.vulnerability, br.package) == {
        "owasp_llm": ["LLM02", "LLM04", "LLM05"],
        "atlas": ["AML.T0010", "AML.T0043"],
        "nist_ai_rmf": ["GOVERN-1.7", "MANAGE-1.3", "MAP-3.5", "MEASURE-2.5", "MEASURE-2.9"],
        "nist_csf": [
            "DE.CM-09",
            "GV.SC-05",
            "GV.SC-07",
            "ID.AM-05",
            "ID.RA-01",
            "ID.RA-02",
            "ID.RA-05",
            "PR.DS-01",
            "RS.AN-03",
            "RS.MI-02",
        ],
        "nist_800_53": ["CM-6", "CM-8", "IR-5", "IR-6", "RA-5", "RA-7", "SI-10", "SI-2", "SI-3", "SI-4", "SI-5", "SR-11", "SR-3", "SR-4"],
        "fedramp": [
            "FedRAMP-CM-6",
            "FedRAMP-CM-8",
            "FedRAMP-IR-5",
            "FedRAMP-IR-6",
            "FedRAMP-RA-5",
            "FedRAMP-RA-7",
            "FedRAMP-SI-10",
            "FedRAMP-SI-2",
            "FedRAMP-SI-3",
            "FedRAMP-SI-4",
            "FedRAMP-SI-5",
            "FedRAMP-SR-3",
        ],
        "cis": ["CIS-02.1", "CIS-02.3", "CIS-02.7", "CIS-07.1", "CIS-07.4", "CIS-07.5", "CIS-16.1", "CIS-16.12"],
        "iso_27001": ["A.5.19", "A.5.20", "A.5.21", "A.5.23", "A.5.28", "A.8.28", "A.8.8"],
        "soc2": ["CC6.8", "CC7.1", "CC7.2", "CC7.4", "CC8.1", "CC9.1", "CC9.2"],
        "eu_ai_act": ["ART-15", "ART-17", "ART-6", "ART-9"],
        "owasp_mcp": ["MCP04"],
        "owasp_agentic": ["ASI01", "ASI04", "ASI09"],
    }


# ─── Path 3: source/asset/finding-type -> framework slug fan-out ──────────────

# Representative rows including the #4211/#4215 narrowing that must be preserved:
# CLOUD_CIS asserts only "cis"; CLOUD_SECURITY (vendor best practice) asserts none.
_SELECT_GOLDEN = [
    (
        (FindingSource.MCP_SCAN, "mcp_server", FindingType.INJECTION),
        ["owasp-llm", "owasp-mcp", "owasp-agentic", "atlas", "attack", "nist", "eu-ai-act"],
    ),
    (
        (FindingSource.CLOUD_CIS, "cloud_resource", FindingType.CIS_FAIL),
        ["cis"],
    ),
    (
        (FindingSource.CLOUD_SECURITY, "cloud_resource", FindingType.CLOUD_BEST_PRACTICE_FAIL),
        [],
    ),
    (
        (FindingSource.SAST, "package", FindingType.CREDENTIAL_EXPOSURE),
        ["nist-csf", "iso-27001", "soc2", "pci-dss"],
    ),
    (
        (FindingSource.SAST, None, FindingType.INJECTION),
        ["owasp-llm", "owasp-mcp", "owasp-agentic", "atlas", "attack", "nist", "nist-csf", "eu-ai-act", "soc2", "pci-dss"],
    ),
]


def test_select_frameworks_unchanged():
    for (source, asset_type, finding_type), expected in _SELECT_GOLDEN:
        assert select_frameworks(source, asset_type=asset_type, finding_type=finding_type) == expected


def test_select_frameworks_include_gov_unchanged():
    assert select_frameworks(
        FindingSource.CLOUD_CIS,
        asset_type="cloud_resource",
        finding_type=FindingType.CIS_FAIL,
        include_gov=True,
    ) == ["nist-800-53", "fedramp", "cis", "cmmc"]
    assert select_frameworks(
        FindingSource.CLOUD_SECURITY,
        asset_type="cloud_resource",
        finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
        include_gov=True,
    ) == ["nist-800-53", "fedramp", "cmmc"]


# ─── New layer: lookup contract ──────────────────────────────────────────────


def test_controls_for_cwe_resolves_per_framework():
    from agent_bom import framework_mapping as fm

    # CWE-89 (SQL injection) evidences these controls per framework.
    assert fm.controls_for_cwe("CWE-89", "cis") == ["CIS-16.1"]
    assert fm.controls_for_cwe("CWE-89", "nist_800_53") == ["SI-10", "SI-3"]
    assert fm.controls_for_cwe("CWE-89", "owasp_llm") == ["LLM02"]
    # Unknown CWE / framework -> empty, never KeyError.
    assert fm.controls_for_cwe("CWE-99999", "cis") == []
    assert fm.controls_for_cwe("CWE-89", "no_such_framework") == []


def test_controls_for_cwe_normalizes_case_by_default():
    from agent_bom import framework_mapping as fm

    # Blast-radius taggers historically upper-cased the CWE id.
    assert fm.controls_for_cwe("cwe-798", "cis") == ["CIS-16.1"]
    # vuln_compliance historically looked up the raw id (no normalization).
    assert fm.controls_for_cwe("cwe-798", "cis", normalize=False) == []


def test_controls_for_cwes_dedupes_and_preserves_order():
    from agent_bom import framework_mapping as fm

    # CWE-78 and CWE-89 both map to SI-10, SI-3 under nist_800_53; the bulk
    # helper de-dupes while preserving first-seen order.
    assert fm.controls_for_cwes(["CWE-78", "CWE-89"], "nist_800_53") == ["SI-10", "SI-3"]


def test_control_catalog_seam_present_and_empty():
    """PR2 plugs provenanced catalogs into this registry; PR1 ships it empty."""
    from agent_bom import framework_mapping as fm

    assert isinstance(fm.FRAMEWORK_CONTROL_CATALOG, dict)
    assert fm.FRAMEWORK_CONTROL_CATALOG == {}
    # Lookup against an unpopulated catalog is safe (returns None), never raises.
    assert fm.control_spec("cis", "CIS-16.1") is None
