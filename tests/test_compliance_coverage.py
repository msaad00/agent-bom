"""Drift checks for compliance coverage disclosures."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agent_bom.cloud.aisvs_benchmark import AISVS_CHECK_IDS
from agent_bom.compliance_coverage import (
    AISVS_BENCHMARK,
    TAG_MAPPED_FRAMEWORKS,
    framework_output_key_by_slug,
    framework_report_labels_by_slug,
    normalize_framework_slug,
    render_compliance_coverage_table,
)

ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"
START = "<!-- compliance-coverage:start -->"
END = "<!-- compliance-coverage:end -->"


def _coverage_table_from_architecture() -> str:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    start = text.index(START) + len(START)
    end = text.index(END, start)
    return text[start:end].strip()


def test_architecture_coverage_table_is_generated_from_metadata() -> None:
    assert _coverage_table_from_architecture() == render_compliance_coverage_table()


def test_coverage_generator_check_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_compliance_coverage_table.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_api_framework_maps_are_derived_from_metadata() -> None:
    output_map = framework_output_key_by_slug()
    report_map = framework_report_labels_by_slug()

    assert output_map == {metadata.slug: metadata.output_key for metadata in TAG_MAPPED_FRAMEWORKS}
    assert report_map == {metadata.slug: (metadata.output_key, metadata.report_label) for metadata in TAG_MAPPED_FRAMEWORKS}
    assert output_map["pci-dss"] == "pci_dss"


def test_normalize_framework_slug_accepts_pci_dss_aliases() -> None:
    assert normalize_framework_slug("pci-dss") == "pci-dss"
    assert normalize_framework_slug("pci_dss") == "pci-dss"
    assert normalize_framework_slug("PCI_DSS") == "pci-dss"


def test_aisvs_coverage_uses_benchmark_registry() -> None:
    assert AISVS_BENCHMARK.check_ids == AISVS_CHECK_IDS
    assert AISVS_BENCHMARK.check_count == len(AISVS_CHECK_IDS)
    assert f"{AISVS_BENCHMARK.check_count} checks" in render_compliance_coverage_table()


def test_every_registered_framework_is_actually_tagged_by_a_scan() -> None:
    """A framework the product lists must be one a scan can evaluate.

    PCI DSS shipped a complete requirement catalog and a complete tagger, was
    listed in the framework registry, was offered by the API and the narrative,
    and counted toward the advertised compliance surface count — but the scanner
    never called its tagger, so `pci_dss_tags` was always empty and PCI DSS could
    only ever report `not_evaluated`. Drive the check off the registry so a
    future framework cannot be added to the catalogue without being wired.
    """
    from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS
    from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability
    from agent_bom.scanners.package_scan import apply_framework_tags

    blast_radius = BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2025-0001",
            summary="Remote code execution",
            severity=Severity.CRITICAL,
            fixed_version="2.0.0",
            is_kev=True,
            cwe_ids=["CWE-94", "CWE-327"],
        ),
        package=Package(name="langchain", version="0.1.0", ecosystem="pypi"),
        affected_servers=[MCPServer(name="server")],
        affected_agents=[Agent(name="claude", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp")],
        exposed_credentials=["OPENAI_API_KEY"],
        exposed_tools=[],
    )

    # Seed a sentinel in every field: a wired tagger overwrites it, an unwired
    # one leaves it. This isolates wiring from whether a given fixture happens
    # to trigger a given framework's rules.
    sentinel = ["__unwired__"]
    for field in COMPLIANCE_TAG_FIELDS:
        setattr(blast_radius, field, list(sentinel))

    apply_framework_tags(blast_radius)

    unwired = [field for field in COMPLIANCE_TAG_FIELDS if getattr(blast_radius, field) == sentinel]
    assert not unwired, f"registered frameworks a scan never tags: {unwired}"
    # And the fixture is realistic enough that most frameworks really do fire,
    # so a tagger silently returning nothing for everything would still show up.
    populated = [field for field in COMPLIANCE_TAG_FIELDS if getattr(blast_radius, field)]
    assert len(populated) >= len(COMPLIANCE_TAG_FIELDS) - 2, populated
