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


def test_pci_dss_descriptors_are_own_wording_not_copyrighted_text():
    """PCI DSS 4.0 requirement text is copyrighted; the catalog must carry
    agent-bom's OWN short descriptors and the same provenance/copyright note the
    sibling framework modules (iso_27001, soc2, cis_controls) already carry —
    only the factual requirement IDs are reused.
    """
    import inspect

    # Near-verbatim PCI DSS 4.0 requirement phrasings must not be reproduced.
    banned_phrases = [
        "at least quarterly by pci ssc asv",
        "performed at least quarterly",
        "cryptographic cipher suites and protocols in use",
        "minimum complexity requirements",
    ]
    for code, descriptor in pci_dss.PCI_DSS_REQUIREMENTS.items():
        low = descriptor.lower()
        for phrase in banned_phrases:
            assert phrase not in low, f"{code} reproduces copyrighted PCI DSS wording: {descriptor!r}"

    # The IDs (the facts) are preserved so tagging is unaffected.
    assert {"6.3.1", "6.3.2", "11.3.1", "11.3.2", "12.3.1"} <= set(pci_dss.PCI_DSS_REQUIREMENTS)

    # Provenance/copyright note present in the module source, like the siblings.
    src = inspect.getsource(pci_dss)
    assert "copyright" in src.lower()
    assert "own" in src.lower()


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


def test_control_catalog_registers_expected_frameworks():
    """PR2 populates the registry from vendored data (PR1 shipped it empty)."""
    from agent_bom import framework_mapping as fm

    assert isinstance(fm.FRAMEWORK_CONTROL_CATALOG, dict)
    for slug in ("nist-800-53", "iso-27001", "soc2", "cis"):
        assert slug in fm.FRAMEWORK_CONTROL_CATALOG
        assert fm.FRAMEWORK_CONTROL_CATALOG[slug], f"{slug} catalog is empty"
    # Lookup against an uncatalogued control is still safe (returns None).
    assert fm.control_spec("nist-800-53", "ZZ-999") is None
    assert fm.control_spec("no-such-framework", "AC-2") is None


def test_nist_control_spec_carries_authoritative_public_domain_title():
    """NIST 800-53 (public domain / CC0) is vendored with its real title."""
    from agent_bom import framework_mapping as fm

    spec = fm.control_spec("nist-800-53", "AC-2")
    assert spec is not None
    assert spec.control_id == "AC-2"
    assert spec.title == "Account Management"  # authoritative NIST SP 800-53 title
    assert spec.reference_only is False
    # PR3 curates check -> control: AC-2 (Account Management) is evidenced by the
    # AWS CIS Foundations "credentials unused >= 45 days are disabled" check only.
    assert spec.evidencing_checks == ("cis:aws:1.12",)
    # Every control our CWE table maps to must resolve to a real NIST title.
    for cid in ("AC-3", "AC-6", "AU-2", "CM-7", "IA-5", "SC-8", "SI-3", "SR-3"):
        assert fm.control_spec("nist-800-53", cid).title


def test_nist_catalog_provenance_record_complete():
    """The vendored NIST catalog records source/version/sha256/license."""
    from agent_bom import framework_catalog as fc

    prov = fc.nist_catalog_provenance()
    assert prov["publication"] == "NIST SP 800-53 Rev 5"
    assert prov["catalog_version"]  # e.g. "5.2.0"
    assert "CC0" in prov["license"] or "public domain" in prov["license"].lower()
    src = prov["source"]
    assert src["url"].startswith("https://raw.githubusercontent.com/usnistgov/oscal-content/")
    assert src["oscal_release"] and src["oscal_commit"]
    assert len(src["sha256"]) == 64
    assert len(prov["normalized_sha256"]) == 64


def test_nist_to_iso_crosswalk_resolves_ids_only():
    """NIST's official crosswalk maps AC-2 to ISO Annex A IDs — never titles."""
    from agent_bom import framework_mapping as fm

    iso_ids = fm.nist_to_iso("AC-2")
    assert iso_ids == ["A.5.16", "A.5.18", "A.8.2"]
    # Only identifiers are present; no ISO control title text leaks through.
    assert all(i.startswith("A.") for i in iso_ids)
    assert fm.nist_to_iso("ZZ-999") == []


def test_crosswalk_provenance_is_nist_public_domain():
    from agent_bom import framework_catalog as fc

    prov = fc.crosswalk_provenance()
    assert prov["mapping_authority"] == "NIST"
    assert "CC0" in prov["license"] or "public domain" in prov["license"].lower()
    assert prov["source"]["url"].startswith("https://csrc.nist.gov/")
    assert len(prov["source"]["sha256"]) == 64
    # No ISO title/description is stored — only the reference note.
    assert "identifier only" in prov["iso_reference"].lower()


def test_reference_only_frameworks_carry_no_copyrighted_title():
    """ISO / SOC 2 / CIS specs are reference-only: ID is the fact, no © title."""
    from agent_bom import framework_mapping as fm

    # A representative sample of official copyrighted titles that MUST NOT appear.
    forbidden = {
        "Management of technical vulnerabilities",  # ISO/IEC 27001:2022
        "Use of cryptography",
        "Secure coding",
        "Detection and monitoring of anomalies and events",  # AICPA TSC
        "Establish and maintain a vulnerability management process",  # CIS v8
        "Establish and maintain a software inventory",
    }
    for slug in ("iso-27001", "soc2", "cis"):
        catalog = fm.FRAMEWORK_CONTROL_CATALOG[slug]
        for spec in catalog.values():
            assert spec.reference_only is True
            assert spec.title is None or spec.title not in forbidden

    # The specific ISO control AC-2 maps to is catalogued reference-only, no title.
    a_spec = fm.control_spec("iso-27001", "A.5.16")
    assert a_spec is not None and a_spec.reference_only is True and a_spec.title is None
    # A CIS/SOC2 spec resolves and carries our own (non-official) descriptor.
    assert fm.control_spec("cis", "CIS-07.1").title == "Vulnerability-management program"
    assert fm.control_spec("soc2", "CC7.1").title == "Anomaly and event detection"


# ─── PR3: check -> NIST 800-53 control curation (vendor-asserted) ─────────────


def test_nist_evidencing_checks_reuse_cwe_compliance_map():
    """Every CWE the in-repo CWE_COMPLIANCE_MAP maps to a NIST control appears as
    a ``cwe:<CWE-ID>`` evidencing check on that control's spec — 100% reuse of
    already-curated data, no new assertion."""
    from agent_bom import framework_mapping as fm
    from agent_bom.constants import CWE_COMPLIANCE_MAP

    for cwe, frameworks in CWE_COMPLIANCE_MAP.items():
        for control_id in frameworks.get("nist_800_53", []):
            spec = fm.control_spec("nist-800-53", control_id)
            assert spec is not None, f"{control_id} missing from NIST catalog"
            assert f"cwe:{cwe}" in spec.evidencing_checks

    # SI-10 (Information Input Validation) is evidenced by the injection CWEs.
    si10 = fm.control_spec("nist-800-53", "SI-10")
    assert "cwe:CWE-89" in si10.evidencing_checks
    # Every evidencing check carries a recognised, namespaced provenance prefix.
    assert all(c.startswith(("cwe:", "cis:")) for c in si10.evidencing_checks)


def test_nist_evidencing_checks_include_vendor_asserted_cis_mapping():
    """A defensible CIS-Foundations-check -> NIST-control objective match is
    surfaced as a ``cis:<cloud>:<check_id>`` evidencing check (vendor-asserted)."""
    from agent_bom import framework_mapping as fm

    # Public-S3 account block evidences boundary protection + access enforcement.
    assert fm.nist_controls_for_cis_check("aws", "2.1.1") == ["AC-3", "SC-7"]
    # S3 server-side encryption evidences protection of data at rest.
    assert "SC-28" in fm.nist_controls_for_cis_check("aws", "2.1.2")
    # Unknown check / cloud -> empty, never KeyError.
    assert fm.nist_controls_for_cis_check("aws", "99.99") == []
    assert fm.nist_controls_for_cis_check("no-such-cloud", "2.1.1") == []

    # The mapping is reflected on the control specs (both directions reconcile).
    ac3 = fm.control_spec("nist-800-53", "AC-3")
    assert "cis:aws:2.1.1" in ac3.evidencing_checks
    # Every NIST control the CIS table references resolves to a real NIST title.
    for (_cloud, _check), controls in fm.CIS_FOUNDATIONS_TO_NIST_800_53.items():
        for control_id in controls:
            assert fm.control_spec("nist-800-53", control_id).title


def test_nist_evidenced_controls_set_matches_specs():
    """The exported evidenced-controls set equals the controls whose spec carries
    at least one evidencing check — the route's reconciliation seam."""
    from agent_bom import framework_mapping as fm

    derived = {cid for cid, spec in fm.FRAMEWORK_CONTROL_CATALOG["nist-800-53"].items() if spec.evidencing_checks}
    assert derived == set(fm.NIST_800_53_EVIDENCED_CONTROLS)
    # AC-2 is evidenced only via the CIS table; SI-10 only via CWE; both present.
    assert "AC-2" in derived
    assert "SI-10" in derived


def test_vendored_catalog_integrity_and_counts_reconcile():
    """Digest + published counts must reconcile with the vendored payloads."""
    from agent_bom import framework_catalog as fc

    assert fc.verify_catalog_integrity() == []
    # Counts reconcile with the actual populated data.
    assert fc.nist_catalog_provenance()["control_count"] == len(fc.nist_controls())
    cross = fc.nist_to_iso_crosswalk()
    assert fc.crosswalk_provenance()["nist_control_count"] == len(cross)
