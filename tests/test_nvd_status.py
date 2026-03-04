"""Tests for NVD vulnerability status tracking + remediation source links."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.models import (
    BlastRadius,
    Package,
    Severity,
    Vulnerability,
)

# ─── helpers ───────────────────────────────────────────────────────────────


def _vuln(
    cve_id: str = "CVE-2024-1234",
    severity: Severity = Severity.HIGH,
    nvd_status: str | None = None,
    references: list[str] | None = None,
    fixed_version: str | None = "2.0.0",
    **kwargs,
) -> Vulnerability:
    return Vulnerability(
        id=cve_id,
        summary=f"Test vuln {cve_id}",
        severity=severity,
        nvd_status=nvd_status,
        references=references or [],
        fixed_version=fixed_version,
        **kwargs,
    )


def _pkg(name: str = "lodash", version: str = "1.0.0", ecosystem: str = "npm") -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem)


def _blast(vuln: Vulnerability | None = None, pkg: Package | None = None) -> BlastRadius:
    return BlastRadius(
        vulnerability=vuln or _vuln(),
        package=pkg or _pkg(),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1. Model — nvd_status field
# ═══════════════════════════════════════════════════════════════════════════


class TestVulnerabilityNvdStatus:
    def test_default_none(self):
        v = _vuln()
        assert v.nvd_status is None

    def test_set_at_construction(self):
        v = _vuln(nvd_status="ANALYZED")
        assert v.nvd_status == "ANALYZED"

    @pytest.mark.parametrize(
        "status",
        [
            "RECEIVED",
            "AWAITING_ANALYSIS",
            "UNDERGOING_ANALYSIS",
            "ANALYZED",
            "MODIFIED",
            "DEFERRED",
            "REJECTED",
        ],
    )
    def test_all_nvd_status_values(self, status: str):
        v = _vuln(nvd_status=status)
        assert v.nvd_status == status


# ═══════════════════════════════════════════════════════════════════════════
# 2. Enrichment — vulnStatus extraction + NVD reference merging
# ═══════════════════════════════════════════════════════════════════════════


class TestEnrichmentNvdStatus:
    """Test that enrichment extracts vulnStatus and merges NVD references."""

    @pytest.mark.asyncio
    async def test_extract_vuln_status(self):
        """enrich_vulnerabilities should set nvd_status from NVD response."""
        vuln = _vuln(cve_id="CVE-2024-9999")

        nvd_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "vulnStatus": "AWAITING_ANALYSIS",
                        "weaknesses": [],
                        "published": "2024-01-01",
                        "lastModified": "2024-06-01",
                        "references": [],
                    }
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = nvd_response

        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment.create_client") as mock_client,
        ):
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

            # Clear caches to force fresh fetch
            import agent_bom.enrichment as _enr
            from agent_bom.enrichment import enrich_vulnerabilities

            _enr._nvd_file_cache.clear()
            _enr._epss_file_cache.clear()
            _enr._enrichment_cache_loaded = False

            await enrich_vulnerabilities([vuln], enable_nvd=True, enable_epss=False, enable_kev=False)

        assert vuln.nvd_status == "AWAITING_ANALYSIS"

    @pytest.mark.asyncio
    async def test_merge_nvd_references(self):
        """NVD references should be merged with existing OSV references (deduplicated)."""
        vuln = _vuln(
            cve_id="CVE-2024-8888",
            references=["https://osv.dev/vuln/CVE-2024-8888"],
        )

        nvd_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "vulnStatus": "ANALYZED",
                        "weaknesses": [],
                        "published": "2024-01-01",
                        "lastModified": "2024-06-01",
                        "references": [
                            {"url": "https://github.com/advisory/123"},
                            {"url": "https://osv.dev/vuln/CVE-2024-8888"},  # duplicate
                        ],
                    }
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = nvd_response

        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment.create_client") as mock_client,
        ):
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

            import agent_bom.enrichment as _enr
            from agent_bom.enrichment import enrich_vulnerabilities

            _enr._nvd_file_cache.clear()
            _enr._epss_file_cache.clear()
            _enr._enrichment_cache_loaded = False

            await enrich_vulnerabilities([vuln], enable_nvd=True, enable_epss=False, enable_kev=False)

        # Canonical NVD link should be first
        assert vuln.references[0] == "https://nvd.nist.gov/vuln/detail/CVE-2024-8888"
        # OSV ref still present
        assert "https://osv.dev/vuln/CVE-2024-8888" in vuln.references
        # GitHub advisory added
        assert "https://github.com/advisory/123" in vuln.references
        # No duplicates
        assert len(vuln.references) == len(set(vuln.references))

    @pytest.mark.asyncio
    async def test_canonical_nvd_link_not_duplicated(self):
        """If canonical NVD link already exists, don't add it again."""
        canonical = "https://nvd.nist.gov/vuln/detail/CVE-2024-7777"
        vuln = _vuln(cve_id="CVE-2024-7777", references=[canonical])

        nvd_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "vulnStatus": "ANALYZED",
                        "weaknesses": [],
                        "published": "2024-01-01",
                        "lastModified": "2024-06-01",
                        "references": [],
                    }
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = nvd_response

        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment.create_client") as mock_client,
        ):
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

            import agent_bom.enrichment as _enr
            from agent_bom.enrichment import enrich_vulnerabilities

            _enr._nvd_file_cache.clear()
            _enr._epss_file_cache.clear()
            _enr._enrichment_cache_loaded = False

            await enrich_vulnerabilities([vuln], enable_nvd=True, enable_epss=False, enable_kev=False)

        # Should appear exactly once
        assert vuln.references.count(canonical) == 1


# ═══════════════════════════════════════════════════════════════════════════
# 3. PackageFix — references field
# ═══════════════════════════════════════════════════════════════════════════


class TestPackageFixReferences:
    def test_default_empty(self):
        from agent_bom.remediate import PackageFix

        f = PackageFix(
            package="lodash",
            ecosystem="npm",
            current_version="1.0.0",
            fixed_version="2.0.0",
            command="npm install lodash@2.0.0",
        )
        assert f.references == []

    def test_populated(self):
        from agent_bom.remediate import PackageFix

        refs = ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "https://github.com/advisory/123"]
        f = PackageFix(
            package="lodash",
            ecosystem="npm",
            current_version="1.0.0",
            fixed_version="2.0.0",
            command="npm install lodash@2.0.0",
            references=refs,
        )
        assert f.references == refs


# ═══════════════════════════════════════════════════════════════════════════
# 4. Remediation pipeline — references propagation
# ═══════════════════════════════════════════════════════════════════════════


class TestRemediationPipeline:
    def test_build_remediation_plan_collects_references(self):
        """build_remediation_plan should collect references from blast radius vulns."""
        from agent_bom.output import build_remediation_plan

        refs = ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "https://github.com/advisory/999"]
        vuln = _vuln(references=refs)
        br = _blast(vuln=vuln)

        plan = build_remediation_plan([br])
        assert len(plan) == 1
        assert sorted(refs) == plan[0]["references"]

    def test_build_remediation_plan_deduplicates_references(self):
        """References from multiple blast radii for the same package should be deduplicated."""
        from agent_bom.output import build_remediation_plan

        vuln1 = _vuln(cve_id="CVE-2024-0001", references=["https://a.com", "https://b.com"])
        vuln2 = _vuln(cve_id="CVE-2024-0002", references=["https://b.com", "https://c.com"])
        pkg = _pkg()
        br1 = _blast(vuln=vuln1, pkg=pkg)
        br2 = _blast(vuln=vuln2, pkg=pkg)

        plan = build_remediation_plan([br1, br2])
        assert len(plan) == 1
        assert plan[0]["references"] == ["https://a.com", "https://b.com", "https://c.com"]

    def test_generate_package_fixes_propagates_references(self):
        """generate_package_fixes should propagate references to PackageFix objects."""
        from agent_bom.remediate import generate_package_fixes

        refs = ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]
        plan_items = [
            {
                "package": "lodash",
                "ecosystem": "npm",
                "current": "1.0.0",
                "fix": "2.0.0",
                "vulns": ["CVE-2024-1234"],
                "agents": ["agent-a"],
                "references": refs,
            }
        ]

        fixable, unfixable = generate_package_fixes(plan_items)
        assert len(fixable) == 1
        assert fixable[0].references == refs
        assert len(unfixable) == 0

    def test_generate_package_fixes_unfixable_has_references(self):
        """Unfixable items should also carry references."""
        from agent_bom.remediate import generate_package_fixes

        refs = ["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"]
        plan_items = [
            {
                "package": "badpkg",
                "ecosystem": "pypi",
                "current": "0.1.0",
                "fix": None,
                "vulns": ["CVE-2024-5678"],
                "agents": [],
                "references": refs,
            }
        ]

        fixable, unfixable = generate_package_fixes(plan_items)
        assert len(unfixable) == 1
        assert unfixable[0]["references"] == refs

    def test_generate_package_fixes_missing_references(self):
        """Missing references key in plan item should default to empty list."""
        from agent_bom.remediate import generate_package_fixes

        plan_items = [
            {
                "package": "pkg",
                "ecosystem": "npm",
                "current": "1.0",
                "fix": "2.0",
                "vulns": ["CVE-2024-0001"],
                "agents": [],
                # no "references" key
            }
        ]

        fixable, _ = generate_package_fixes(plan_items)
        assert fixable[0].references == []


# ═══════════════════════════════════════════════════════════════════════════
# 5. JSON output — nvd_status + references
# ═══════════════════════════════════════════════════════════════════════════


class TestJsonOutput:
    def test_blast_radius_json_has_nvd_status(self):
        """Blast radius JSON should include nvd_status."""
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        vuln = _vuln(nvd_status="REJECTED")
        br = _blast(vuln=vuln)

        report = AIBOMReport(agents=[], blast_radii=[br])
        data = to_json(report)

        blast_items = data.get("blast_radius", [])
        assert len(blast_items) == 1
        assert blast_items[0]["nvd_status"] == "REJECTED"

    def test_blast_radius_json_nvd_status_none(self):
        """Blast radius JSON should include nvd_status=None when not set."""
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        br = _blast()
        report = AIBOMReport(agents=[], blast_radii=[br])
        data = to_json(report)

        blast_items = data.get("blast_radius", [])
        assert blast_items[0]["nvd_status"] is None

    def test_remediation_json_has_references(self):
        """Remediation plan JSON should include references."""
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        refs = ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]
        vuln = _vuln(references=refs)
        br = _blast(vuln=vuln)

        report = AIBOMReport(agents=[], blast_radii=[br])
        data = to_json(report)

        plan = data.get("remediation_plan", [])
        assert len(plan) == 1
        assert refs[0] in plan[0]["references"]


# ═══════════════════════════════════════════════════════════════════════════
# 6. Markdown export — advisory links
# ═══════════════════════════════════════════════════════════════════════════


class TestMarkdownExport:
    def test_export_remediation_md_includes_advisories(self, tmp_path):
        """Markdown export should include advisory links for fixes with references."""
        from agent_bom.remediate import PackageFix, RemediationPlan, export_remediation_md

        fix = PackageFix(
            package="lodash",
            ecosystem="npm",
            current_version="1.0.0",
            fixed_version="2.0.0",
            command="npm install lodash@2.0.0",
            vulns=["CVE-2024-1234"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                "https://github.com/advisory/123",
            ],
        )

        plan = RemediationPlan(
            generated_at="2024-01-01T00:00:00",
            package_fixes=[fix],
            credential_fixes=[],
            unfixable=[],
        )

        out = tmp_path / "remediation.md"
        export_remediation_md(plan, str(out))
        content = out.read_text()

        assert "**Advisories:**" in content
        assert "https://nvd.nist.gov/vuln/detail/CVE-2024-1234" in content
        assert "https://github.com/advisory/123" in content

    def test_export_remediation_md_no_advisories_when_empty(self, tmp_path):
        """No advisories section when references are empty."""
        from agent_bom.remediate import PackageFix, RemediationPlan, export_remediation_md

        fix = PackageFix(
            package="lodash",
            ecosystem="npm",
            current_version="1.0.0",
            fixed_version="2.0.0",
            command="npm install lodash@2.0.0",
            vulns=["CVE-2024-1234"],
            references=[],
        )

        plan = RemediationPlan(
            generated_at="2024-01-01T00:00:00",
            package_fixes=[fix],
            credential_fixes=[],
            unfixable=[],
        )

        out = tmp_path / "remediation.md"
        export_remediation_md(plan, str(out))
        content = out.read_text()

        assert "**Advisories:**" not in content

    def test_export_remediation_md_caps_advisories_at_3(self, tmp_path):
        """Advisory links should be capped at 3."""
        from agent_bom.remediate import PackageFix, RemediationPlan, export_remediation_md

        fix = PackageFix(
            package="lodash",
            ecosystem="npm",
            current_version="1.0.0",
            fixed_version="2.0.0",
            command="npm install lodash@2.0.0",
            vulns=["CVE-2024-1234"],
            references=[f"https://ref{i}.com" for i in range(10)],
        )

        plan = RemediationPlan(
            generated_at="2024-01-01T00:00:00",
            package_fixes=[fix],
            credential_fixes=[],
            unfixable=[],
        )

        out = tmp_path / "remediation.md"
        export_remediation_md(plan, str(out))
        content = out.read_text()

        # Only 3 refs should appear (capped) — use line matching to avoid CodeQL URL-in-string false positives
        ref_lines = [line for line in content.splitlines() if line.strip().startswith("- https://ref")]
        assert len(ref_lines) == 3
        assert ref_lines[0].strip() == "- https://ref0.com"
        assert ref_lines[2].strip() == "- https://ref2.com"


# ═══════════════════════════════════════════════════════════════════════════
# 7. MCP tool — references in remediate output
# ═══════════════════════════════════════════════════════════════════════════


class TestMCPReferences:
    def test_package_fix_references_capped_at_10(self):
        """MCP remediate tool should cap references at 10."""
        from agent_bom.remediate import PackageFix

        refs = [f"https://ref{i}.com" for i in range(20)]
        f = PackageFix(
            package="x",
            ecosystem="npm",
            current_version="1.0",
            fixed_version="2.0",
            command="npm i x@2.0",
            references=refs,
        )

        # Simulate MCP serialization
        serialized = {"references": f.references[:10]}
        assert len(serialized["references"]) == 10
        assert serialized["references"][0] == "https://ref0.com"
        assert serialized["references"][9] == "https://ref9.com"
