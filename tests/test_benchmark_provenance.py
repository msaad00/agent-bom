"""Foundation tests for CSPM benchmark provenance + machine-verifiable coverage.

These pin the honesty contract: a coverage percentage is published only when an
authoritative denominator and mapping are repository-provenanced and
machine-verifiable; otherwise counts are reported without a fabricated ratio.
The drift gate must fail on catalog, registry, duplicate-ID, or classification
divergence.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from agent_bom.cloud import benchmark_provenance as bp

PROVIDERS = ("aws", "azure", "gcp", "snowflake", "databricks")


def test_provenance_pins_source_version_retrieval_digest_and_license():
    for provider in PROVIDERS:
        prov = bp.BENCHMARK_PROVENANCE[provider]
        assert prov.provider == provider
        assert prov.source_url.startswith("https://")
        assert prov.benchmark_version
        # retrieved_at is a real ISO date, not a placeholder.
        dt.date.fromisoformat(prov.retrieved_at)
        assert prov.license_note
        assert prov.access_mode in ("reference_url_only", "repository_provenanced")
        # No restricted catalog is vendored, so nothing is repository-provenanced.
        assert prov.catalog_repository_provenance is False
        assert prov.source_digest is None
        assert prov.official_control_count is None


def test_control_inventory_derives_counts_from_registries():
    for provider in PROVIDERS:
        inv = bp.build_control_inventory(provider)
        assert inv.provider == provider
        assert inv.implemented_control_count == len(inv.control_ids)
        # automated + manual partitions the implemented set with no overlap.
        assert set(inv.automated_control_ids).isdisjoint(inv.manual_control_ids)
        assert len(inv.automated_control_ids) + len(inv.manual_control_ids) == inv.implemented_control_count
        # unsupported and official are unknown until a denominator is provenanced.
        assert inv.unsupported_control_count is None
        assert inv.official_control_count is None
        assert inv.inventory_digest


def test_coverage_percentage_withheld_when_denominator_not_verifiable():
    # Every currently-supported benchmark lacks a repository-provenanced official
    # denominator (CIS content is license-restricted), so no percentage is emitted.
    for provider in PROVIDERS:
        inv = bp.build_control_inventory(provider)
        assert bp.coverage_percentage(inv) is None


def test_coverage_percentage_published_only_when_provenanced():
    prov = bp.BenchmarkProvenance(
        provider="synthetic",
        benchmark_name="Synthetic",
        benchmark_version="1.0",
        benchmark_type="cis",
        source_url="https://example.org/benchmark",
        retrieved_at="2026-07-18",
        source_digest="a" * 64,
        license_note="Permissibly sourced first-party catalog for the test.",
        access_mode="repository_provenanced",
        catalog_repository_provenance=True,
        official_control_count=50,
    )
    inv = bp.ControlInventory(
        provider="synthetic",
        control_ids=("1.1", "1.2"),
        automated_control_ids=("1.1", "1.2"),
        manual_control_ids=(),
        implemented_control_count=2,
        official_control_count=50,
        unsupported_control_count=48,
        inventory_digest="deadbeef",
        provenance=prov,
    )
    assert bp.coverage_percentage(inv) == pytest.approx(4.0)

    # If the catalog is not repository-provenanced, the same numerator emits no %.
    withheld = bp.BenchmarkProvenance(
        **{**prov.__dict__, "catalog_repository_provenance": False, "official_control_count": None, "source_digest": None}
    )
    inv_withheld = bp.ControlInventory(
        **{**inv.__dict__, "official_control_count": None, "unsupported_control_count": None, "provenance": withheld}
    )
    assert bp.coverage_percentage(inv_withheld) is None


def _live_records():
    return bp.build_drift_records()


def test_drift_check_clean_on_current_tree():
    committed = bp.load_committed_inventory()
    live = _live_records()
    assert bp.evaluate_drift(committed, live) == []


def test_drift_check_fails_on_duplicate_control_id():
    committed = bp.load_committed_inventory()
    live = _live_records()
    live["aws"]["control_ids"] = list(live["aws"]["control_ids"]) + [live["aws"]["control_ids"][0]]
    problems = bp.evaluate_drift(committed, live)
    assert any("duplicate" in p.lower() for p in problems)


def test_drift_check_fails_on_registry_count_divergence():
    committed = bp.load_committed_inventory()
    live = _live_records()
    live["azure"]["control_ids"] = list(live["azure"]["control_ids"]) + ["9.99"]
    live["azure"]["automated_control_ids"] = list(live["azure"]["automated_control_ids"]) + ["9.99"]
    problems = bp.evaluate_drift(committed, live)
    assert any("azure" in p for p in problems)


def test_drift_check_fails_when_committed_catalog_hand_edited():
    # A stale/hand-edited committed artifact (control dropped without regenerating)
    # must be caught even though the live registry is internally self-consistent.
    committed = bp.load_committed_inventory()
    live = _live_records()
    committed["aws"]["control_ids"] = list(committed["aws"]["control_ids"])[:-1]
    problems = bp.evaluate_drift(committed, live)
    assert any("aws" in p for p in problems)


def test_drift_check_fails_on_classification_divergence():
    committed = bp.load_committed_inventory()
    live = _live_records()
    # Reclassify an automated control as manual without regenerating the catalog.
    moved = live["gcp"]["automated_control_ids"][0]
    live["gcp"]["automated_control_ids"] = list(live["gcp"]["automated_control_ids"])[1:]
    live["gcp"]["manual_control_ids"] = list(live["gcp"]["manual_control_ids"]) + [moved]
    problems = bp.evaluate_drift(committed, live)
    assert any("gcp" in p for p in problems)


def test_drift_check_fails_on_unverifiable_percentage_publication():
    committed = bp.load_committed_inventory()
    live = _live_records()
    live["snowflake"]["coverage_percentage"] = 35.9  # fabricated ratio
    problems = bp.evaluate_drift(committed, live)
    assert any("snowflake" in p and "percentage" in p.lower() for p in problems)


def test_committed_inventory_is_in_sync_and_json_serializable():
    committed = bp.load_committed_inventory()
    # The committed artifact round-trips and matches the generator output.
    regenerated = json.loads(bp.render_committed_inventory())["providers"]
    assert committed == regenerated
