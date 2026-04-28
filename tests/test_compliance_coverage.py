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


def test_aisvs_coverage_uses_benchmark_registry() -> None:
    assert AISVS_BENCHMARK.check_ids == AISVS_CHECK_IDS
    assert AISVS_BENCHMARK.check_count == len(AISVS_CHECK_IDS)
    assert f"{AISVS_BENCHMARK.check_count} checks" in render_compliance_coverage_table()
