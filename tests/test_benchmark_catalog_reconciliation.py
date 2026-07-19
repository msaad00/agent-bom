"""Prove the benchmark catalogs (issue #4120).

The Foundation (PR #4196) reconciled the *committed* control inventory against
the AST-parsed code registries. These tests close the remaining gap: they prove
the catalog is actually *evaluated* — i.e. the inventory the manifest publishes
is a bijection with the controls the evaluators emit at run time — so the
inventory, the report-embedded manifest, and the runtime check set can never
silently diverge into three different truths.

Nothing here needs live cloud credentials: GCP's ``run_benchmark`` is driven
with every read forced to error (fail-closed), and the Snowflake leaf checks are
driven with an empty cursor.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import patch

import pytest

from agent_bom.cloud import benchmark_provenance as bp
from agent_bom.cloud.benchmark_manifests import benchmark_manifest

PROVIDERS = tuple(bp.REGISTRY_SPECS)


# ── manifest ↔ inventory ↔ honesty reconciliation (all providers) ───────────


@pytest.mark.parametrize("provider", PROVIDERS)
def test_manifest_reconciles_with_inventory(provider: str) -> None:
    """The report-exposed manifest is derived from the same inventory."""
    inv = bp.build_control_inventory(provider)
    manifest = benchmark_manifest(provider)

    assert manifest["implemented_control_count"] == inv.implemented_control_count
    assert manifest["implemented_control_count"] == len(inv.control_ids)
    assert manifest["automated_control_ids"] == list(inv.automated_control_ids)
    assert manifest["manual_control_ids"] == list(inv.manual_control_ids)
    assert manifest["inventory_digest"] == inv.inventory_digest


@pytest.mark.parametrize("provider", PROVIDERS)
def test_no_duplicate_control_ids(provider: str) -> None:
    inv = bp.build_control_inventory(provider)
    assert len(inv.control_ids) == len(set(inv.control_ids)), f"{provider} has duplicate control ids"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_automated_and_manual_partition_the_registry(provider: str) -> None:
    inv = bp.build_control_inventory(provider)
    automated = set(inv.automated_control_ids)
    manual = set(inv.manual_control_ids)
    assert not (automated & manual), f"{provider}: a control is both automated and manual"
    assert automated | manual == set(inv.control_ids), f"{provider}: automated∪manual != registry"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_coverage_is_withheld_no_fabricated_denominator(provider: str) -> None:
    """No coverage % or official denominator is published without provenance."""
    inv = bp.build_control_inventory(provider)
    manifest = benchmark_manifest(provider)
    # Every current benchmark is license-restricted (CIS) or vendor best
    # practice, so the official denominator stays None and the percentage is
    # withheld rather than fabricated.
    assert bp.coverage_percentage(inv) is None
    assert inv.official_control_count is None
    assert manifest["coverage_percentage"] is None
    assert manifest["official_control_count"] is None


def test_committed_inventory_matches_live_registries() -> None:
    """The committed artifact is in sync with the live code registries."""
    committed = bp.load_committed_inventory()
    live = bp.build_drift_records()
    assert bp.evaluate_drift(committed, live) == []


# ── execution-level bijection: inventory == emitted checks (GCP) ────────────


def _gcp_report_all_errored():
    """Run the GCP benchmark hermetically with every read forced to fail.

    A fake ``googleapiclient`` module satisfies the SDK guard; ``_discovery_client``
    is patched to raise and the ``google.cloud.*`` clients are made unimportable,
    so every check falls through to its fail-closed ERROR path (never a
    no-data PASS) while still emitting exactly one result per registered control.
    """
    import agent_bom.cloud.gcp_cis_benchmark as g

    fake_googleapiclient = types.ModuleType("googleapiclient")
    mods = {
        "googleapiclient": fake_googleapiclient,
        "google.cloud.compute_v1": None,
        "google.cloud.logging_v2": None,
        "google.cloud.storage": None,
    }
    with patch.object(g, "_discovery_client", side_effect=RuntimeError("hermetic: no network")), patch.dict(sys.modules, mods):
        return g.run_benchmark(project_id="reconciliation-project")


def test_gcp_emitted_checks_are_a_bijection_with_the_inventory() -> None:
    inv = bp.build_control_inventory("gcp")
    report = _gcp_report_all_errored()
    emitted = [c.check_id for c in report.checks]

    assert len(emitted) == len(set(emitted)), "GCP emitted a duplicate control id at run time"
    assert set(emitted) == set(inv.control_ids), (
        f"GCP runtime/inventory divergence — missing: {sorted(set(inv.control_ids) - set(emitted))}, "
        f"extra: {sorted(set(emitted) - set(inv.control_ids))}"
    )
    assert len(emitted) == inv.implemented_control_count
    assert report.to_dict()["benchmark_manifest"]["implemented_control_count"] == len(emitted)


def test_gcp_no_data_never_reports_a_false_pass() -> None:
    """Fail-closed: with no readable evidence, nothing may be reported PASS."""
    report = _gcp_report_all_errored()
    assert all(c.status.value in {"error", "not_applicable"} for c in report.checks)


# ── evaluator existence + emitted-id proof (Snowflake) ──────────────────────


class _EmptyCursor:
    """Cursor honoring the ``_run_query`` contract with no rows."""

    description: list = []

    def execute(self, *args, **kwargs) -> None:
        return None

    def fetchall(self) -> list:
        return []

    def fetchone(self):  # noqa: ANN201 - test stub
        return None


def test_snowflake_every_inventory_control_has_a_matching_evaluator() -> None:
    import agent_bom.cloud.snowflake_cis_benchmark as s

    inv = bp.build_control_inventory("snowflake")
    for control_id in inv.control_ids:
        fn = getattr(s, f"_check_{control_id.replace('.', '_')}", None)
        assert fn is not None, f"snowflake inventory control {control_id} has no _check_ evaluator"
        result = fn(_EmptyCursor())
        assert result.check_id == control_id, (
            f"snowflake evaluator for {control_id} emits check_id {result.check_id!r} — id/evaluator mismatch"
        )
