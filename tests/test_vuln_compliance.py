"""Tests for CVE-level compliance framework tagging."""

from __future__ import annotations

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.vuln_compliance import tag_vulnerability

# ─── helpers ───────────────────────────────────────────────────────────────


def _vuln(
    severity: Severity = Severity.HIGH,
    is_kev: bool = False,
    fixed_version: str | None = "2.0.0",
    cwe_ids: list[str] | None = None,
    epss_score: float | None = None,
    **kwargs,
) -> Vulnerability:
    return Vulnerability(
        id="CVE-2024-1234",
        summary="Test vulnerability",
        severity=severity,
        is_kev=is_kev,
        fixed_version=fixed_version,
        cwe_ids=cwe_ids or [],
        epss_score=epss_score,
        **kwargs,
    )


def _pkg(name: str = "lodash", ecosystem: str = "npm") -> Package:
    return Package(name=name, version="1.0.0", ecosystem=ecosystem)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Model — compliance_tags field
# ═══════════════════════════════════════════════════════════════════════════


class TestModelDefault:
    def test_default_empty_dict(self):
        v = _vuln()
        assert v.compliance_tags == {}

    def test_set_at_construction(self):
        v = Vulnerability(
            id="CVE-2024-1234",
            summary="test",
            severity=Severity.HIGH,
            compliance_tags={"nist_csf": ["ID.RA-01"]},
        )
        assert v.compliance_tags == {"nist_csf": ["ID.RA-01"]}


# ═══════════════════════════════════════════════════════════════════════════
# 2. Always-on tags (apply to every CVE regardless of properties)
# ═══════════════════════════════════════════════════════════════════════════


class TestAlwaysOnTags:
    def test_nist_csf_base_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "DE.CM-09" in tags["nist_csf"]
        assert "GV.SC-05" in tags["nist_csf"]
        assert "GV.SC-07" in tags["nist_csf"]
        assert "ID.RA-01" in tags["nist_csf"]

    def test_cis_base_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "CIS-02.1" in tags["cis"]
        assert "CIS-07.1" in tags["cis"]
        assert "CIS-07.5" in tags["cis"]

    def test_iso_27001_base_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "A.5.19" in tags["iso_27001"]
        assert "A.5.21" in tags["iso_27001"]
        assert "A.8.8" in tags["iso_27001"]

    def test_soc2_base_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "CC7.1" in tags["soc2"]
        assert "CC9.1" in tags["soc2"]
        assert "CC9.2" in tags["soc2"]

    def test_atlas_context_sensitive(self):
        # ATLAS tags are now context-sensitive: AML.T0010 only for supply-chain-relevant vulns
        # A generic LOW-severity lodash vuln should NOT get ATLAS tags
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "atlas" not in tags

        # KEV vulns DO get supply chain tag
        tags_kev = tag_vulnerability(_vuln(severity=Severity.LOW, is_kev=True), _pkg())
        assert "AML.T0010" in tags_kev["atlas"]

    def test_nist_rmf_base_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "GOVERN-1.7" in tags["nist_ai_rmf"]
        assert "MAP-3.5" in tags["nist_ai_rmf"]

    def test_eu_ai_act_base_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "ART-9" in tags["eu_ai_act"]
        assert "ART-15" in tags["eu_ai_act"]

    def test_owasp_mcp_base_tag(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "MCP04" in tags["owasp_mcp"]

    def test_owasp_agentic_base_tags(self):
        # Agentic tags are now context-sensitive: ASI04 (Supply Chain) always present,
        # ASI01 only for AI packages, ASI09 only for KEV
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "ASI04" in tags["owasp_agentic"]
        assert "ASI01" not in tags["owasp_agentic"]  # lodash is not AI
        assert "ASI09" not in tags["owasp_agentic"]  # not KEV


# ═══════════════════════════════════════════════════════════════════════════
# 3. Severity-based tags
# ═══════════════════════════════════════════════════════════════════════════


class TestSeverityTags:
    def test_critical_triggers_severity_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.CRITICAL, fixed_version=None), _pkg())
        assert "ID.RA-05" in tags["nist_csf"]
        assert "CIS-02.3" in tags["cis"]
        assert "A.5.20" in tags["iso_27001"]
        assert "CC6.8" in tags["soc2"]

    def test_high_triggers_severity_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.HIGH, fixed_version=None), _pkg())
        assert "ID.RA-05" in tags["nist_csf"]
        assert "CIS-02.3" in tags["cis"]
        assert "A.5.20" in tags["iso_27001"]

    def test_medium_does_not_trigger_severity_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.MEDIUM, fixed_version=None), _pkg())
        assert "ID.RA-05" not in tags["nist_csf"]
        assert "CIS-02.3" not in tags["cis"]
        assert "A.5.20" not in tags["iso_27001"]

    def test_low_does_not_trigger_severity_tags(self):
        tags = tag_vulnerability(_vuln(severity=Severity.LOW, fixed_version=None), _pkg())
        assert "ID.RA-05" not in tags["nist_csf"]
        assert "CIS-02.3" not in tags["cis"]


# ═══════════════════════════════════════════════════════════════════════════
# 4. KEV tags
# ═══════════════════════════════════════════════════════════════════════════


class TestKevTags:
    def test_kev_triggers_response_tags(self):
        tags = tag_vulnerability(_vuln(is_kev=True, fixed_version=None), _pkg())
        assert "RS.MI-02" in tags["nist_csf"]
        assert "ID.RA-02" in tags["nist_csf"]
        assert "CIS-16.12" in tags["cis"]
        assert "A.5.28" in tags["iso_27001"]
        assert "CC7.4" in tags["soc2"]
        assert "MANAGE-1.3" in tags["nist_ai_rmf"]

    def test_non_kev_does_not_trigger(self):
        tags = tag_vulnerability(_vuln(is_kev=False, fixed_version=None), _pkg())
        assert "RS.MI-02" not in tags["nist_csf"]
        assert "CIS-16.12" not in tags["cis"]
        assert "A.5.28" not in tags["iso_27001"]
        assert "CC7.4" not in tags["soc2"]

    def test_epss_triggers_ra02(self):
        tags = tag_vulnerability(_vuln(epss_score=0.5, fixed_version=None), _pkg())
        assert "ID.RA-02" in tags["nist_csf"]


# ═══════════════════════════════════════════════════════════════════════════
# 5. Fix available tags
# ═══════════════════════════════════════════════════════════════════════════


class TestFixAvailableTags:
    def test_fixed_version_triggers_remediation_tags(self):
        tags = tag_vulnerability(_vuln(fixed_version="2.0.0"), _pkg())
        assert "RS.AN-03" in tags["nist_csf"]
        assert "CIS-07.4" in tags["cis"]
        assert "A.8.28" in tags["iso_27001"]
        assert "CC8.1" in tags["soc2"]
        assert "ART-17" in tags["eu_ai_act"]
        assert "MEASURE-2.9" in tags["nist_ai_rmf"]

    def test_no_fix_skips_remediation_tags(self):
        tags = tag_vulnerability(_vuln(fixed_version=None), _pkg())
        assert "RS.AN-03" not in tags["nist_csf"]
        assert "CIS-07.4" not in tags["cis"]
        assert "A.8.28" not in tags["iso_27001"]
        assert "CC8.1" not in tags["soc2"]
        assert "ART-17" not in tags["eu_ai_act"]


# ═══════════════════════════════════════════════════════════════════════════
# 6. AI package tags
# ═══════════════════════════════════════════════════════════════════════════


class TestAiPackageTags:
    def test_ai_package_triggers_ai_tags(self):
        tags = tag_vulnerability(
            _vuln(severity=Severity.HIGH, fixed_version=None),
            _pkg(name="transformers"),
        )
        assert "LLM05" in tags.get("owasp_llm", [])
        assert "LLM03" in tags.get("owasp_llm", [])  # training package
        assert "LLM04" in tags.get("owasp_llm", [])  # AI + HIGH
        assert "ID.AM-05" in tags["nist_csf"]
        assert "CIS-02.7" in tags["cis"]
        assert "A.5.23" in tags["iso_27001"]
        assert "CC7.2" in tags["soc2"]
        assert "ART-6" in tags["eu_ai_act"]
        assert "AML.T0020" in tags["atlas"]
        assert "MEASURE-2.5" in tags["nist_ai_rmf"]

    def test_non_ai_package_skips_ai_tags(self):
        tags = tag_vulnerability(
            _vuln(severity=Severity.HIGH, fixed_version=None),
            _pkg(name="lodash"),
        )
        assert "owasp_llm" not in tags or "LLM05" not in tags.get("owasp_llm", [])
        assert "ID.AM-05" not in tags["nist_csf"]
        assert "CIS-02.7" not in tags["cis"]
        assert "ART-6" not in tags["eu_ai_act"]

    def test_ai_package_low_severity_no_high_tags(self):
        tags = tag_vulnerability(
            _vuln(severity=Severity.LOW, fixed_version=None),
            _pkg(name="torch"),
        )
        # Should have AI-specific tags but not severity-dependent ones
        assert "LLM05" in tags.get("owasp_llm", [])
        assert "LLM04" not in tags.get("owasp_llm", [])  # LLM04 needs HIGH
        # AML.T0020 (Poison Training Data) fires for training packages
        # regardless of severity — the risk is about the package role
        assert "AML.T0020" in tags.get("atlas", [])
        # AML.T0043 (Craft Adversarial Data) needs HIGH severity
        assert "AML.T0043" not in tags.get("atlas", [])


# ═══════════════════════════════════════════════════════════════════════════
# 7. CWE mapping tags
# ═══════════════════════════════════════════════════════════════════════════


class TestCweMappingTags:
    def test_cwe_79_xss_maps_to_frameworks(self):
        tags = tag_vulnerability(
            _vuln(cwe_ids=["CWE-79"], fixed_version=None),
            _pkg(name="app", ecosystem="sast"),
        )
        assert "LLM02" in tags.get("owasp_llm", [])
        assert "A.8.28" in tags["iso_27001"]
        assert "PR.DS-01" in tags["nist_csf"]

    def test_cwe_798_hardcoded_creds(self):
        tags = tag_vulnerability(
            _vuln(cwe_ids=["CWE-798"], fixed_version=None),
            _pkg(name="app", ecosystem="sast"),
        )
        assert "LLM06" in tags.get("owasp_llm", [])
        assert "A.8.9" in tags["iso_27001"]
        assert "PR.AA-01" in tags["nist_csf"]
        assert "CIS-16.1" in tags["cis"]

    def test_non_sast_ecosystem_gets_cwe_mapping(self):
        tags = tag_vulnerability(
            _vuln(cwe_ids=["CWE-79"], fixed_version=None),
            _pkg(name="lodash", ecosystem="npm"),
        )
        # CWE mapping applies to ALL ecosystems (not just SAST)
        assert "LLM02" in tags.get("owasp_llm", [])

    def test_multiple_cwes(self):
        tags = tag_vulnerability(
            _vuln(cwe_ids=["CWE-78", "CWE-89"], fixed_version=None),
            _pkg(name="app", ecosystem="sast"),
        )
        assert "LLM02" in tags.get("owasp_llm", [])
        assert "CIS-16.1" in tags["cis"]


# ═══════════════════════════════════════════════════════════════════════════
# 8. Malicious package tags
# ═══════════════════════════════════════════════════════════════════════════


class TestMaliciousTags:
    def test_malicious_package_triggers_mcp03(self):
        pkg = _pkg()
        pkg.is_malicious = True
        tags = tag_vulnerability(_vuln(fixed_version=None), pkg)
        assert "MCP03" in tags["owasp_mcp"]

    def test_non_malicious_no_mcp03(self):
        tags = tag_vulnerability(_vuln(fixed_version=None), _pkg())
        assert "MCP03" not in tags["owasp_mcp"]


# ═══════════════════════════════════════════════════════════════════════════
# 9. All frameworks present
# ═══════════════════════════════════════════════════════════════════════════


class TestAllFrameworks:
    def test_all_frameworks_populated(self):
        """Every CVE should have tags from all 12 frameworks (some may be empty for OWASP LLM)."""
        tags = tag_vulnerability(
            _vuln(severity=Severity.CRITICAL, is_kev=True, fixed_version="2.0"),
            _pkg(name="torch"),
        )
        # These always have at least base tags
        for fw in [
            "atlas",
            "nist_ai_rmf",
            "nist_csf",
            "nist_800_53",
            "fedramp",
            "cis",
            "iso_27001",
            "soc2",
            "eu_ai_act",
            "owasp_mcp",
            "owasp_agentic",
        ]:
            assert fw in tags, f"Missing framework: {fw}"
            assert len(tags[fw]) > 0, f"Empty tags for: {fw}"

    def test_comprehensive_tags_for_critical_kev_ai_package(self):
        """CRITICAL + KEV + AI package should produce the richest tag set."""
        tags = tag_vulnerability(
            _vuln(severity=Severity.CRITICAL, is_kev=True, fixed_version="2.0"),
            _pkg(name="transformers"),
        )
        # OWASP LLM: LLM03 (training), LLM04 (AI+HIGH), LLM05 (AI)
        assert "LLM03" in tags["owasp_llm"]
        assert "LLM04" in tags["owasp_llm"]
        assert "LLM05" in tags["owasp_llm"]
        # KEV tags
        assert "RS.MI-02" in tags["nist_csf"]
        assert "CIS-16.12" in tags["cis"]
        # Fix tags
        assert "RS.AN-03" in tags["nist_csf"]
        assert "ART-17" in tags["eu_ai_act"]


# ═══════════════════════════════════════════════════════════════════════════
# 10. JSON output integration
# ═══════════════════════════════════════════════════════════════════════════


class TestJsonIntegration:
    def test_blast_radius_json_has_compliance_tags(self):
        from agent_bom.models import AIBOMReport, BlastRadius
        from agent_bom.output import to_json

        vuln = _vuln(severity=Severity.CRITICAL)
        vuln.compliance_tags = tag_vulnerability(vuln, _pkg())
        pkg = _pkg()

        br = BlastRadius(
            vulnerability=vuln,
            package=pkg,
            affected_servers=[],
            affected_agents=[],
            exposed_credentials=[],
            exposed_tools=[],
        )

        report = AIBOMReport(agents=[], blast_radii=[br])
        data = to_json(report)

        blast_items = data.get("blast_radius", [])
        assert len(blast_items) == 1
        ct = blast_items[0]["compliance_tags"]
        assert "nist_csf" in ct
        assert "cis" in ct
        assert "ID.RA-05" in ct["nist_csf"]  # CRITICAL severity
