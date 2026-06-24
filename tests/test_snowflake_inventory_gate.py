"""Snowflake estate-inventory gate — symmetric with the AWS/Azure/GCP gates.

Snowflake previously ran only via the ``--snowflake`` CLI flag. The
``AGENT_BOM_SNOWFLAKE_INVENTORY`` gate makes enablement consistent across every
provider: when the flag is on, an ordinary scan folds the Snowflake estate
(``snowflake_*_data`` blocks) into the report via the shared
``enrich_report_with_snowflake_estate`` helper; default OFF is a no-op with no
network I/O.
"""

from __future__ import annotations

from typing import Any

import agent_bom.scan_enrichment as enrich
from agent_bom.cloud import snowflake
from agent_bom.models import AIBOMReport

_CLEAR = (
    "AGENT_BOM_CLOUD_INVENTORY",
    "AGENT_BOM_AZURE_INVENTORY",
    "AGENT_BOM_GCP_INVENTORY",
    "AGENT_BOM_SNOWFLAKE_INVENTORY",
    "AGENT_BOM_OKTA_DISCOVERY",
    "AGENT_BOM_ENTRA_DISCOVERY",
)


def _clear(monkeypatch: Any) -> None:
    for flag in _CLEAR:
        monkeypatch.delenv(flag, raising=False)


# ── Flag gating (mirrors test_cloud_gcp_inventory) ──────────────────────────


def test_inventory_disabled_by_default(monkeypatch):
    monkeypatch.delenv(snowflake.INVENTORY_ENV_FLAG, raising=False)
    assert snowflake.inventory_enabled() is False


def test_inventory_flag_enables(monkeypatch):
    monkeypatch.setenv(snowflake.INVENTORY_ENV_FLAG, "true")
    assert snowflake.inventory_enabled() is True


def test_inventory_flag_truthy_variants(monkeypatch):
    for value in ("1", "yes", "on", "TRUE", " On "):
        monkeypatch.setenv(snowflake.INVENTORY_ENV_FLAG, value)
        assert snowflake.inventory_enabled() is True, value
    for value in ("0", "false", "no", "", "off"):
        monkeypatch.setenv(snowflake.INVENTORY_ENV_FLAG, value)
        assert snowflake.inventory_enabled() is False, value


# ── Enrichment wiring: no-op when off, runs (mocked) when on ─────────────────


def test_enrichment_noop_when_flag_off(monkeypatch):
    _clear(monkeypatch)

    def _boom(*a, **k):
        raise AssertionError("Snowflake estate must not run when the flag is off")

    monkeypatch.setattr(snowflake, "enrich_report_with_snowflake_estate", _boom)

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)

    assert report.snowflake_object_graph_data is None
    assert report.snowflake_activity_data is None


def test_enrichment_runs_mocked_when_flag_on(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_INVENTORY", "1")

    called: list[str] = []

    def _fake(report):
        called.append("ran")
        report.snowflake_object_graph_data = {"status": "ok", "objects": [{"fqn": "DB.PUBLIC.T"}]}

    monkeypatch.setattr(snowflake, "enrich_report_with_snowflake_estate", _fake)

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)

    assert called == ["ran"]
    assert report.snowflake_object_graph_data == {"status": "ok", "objects": [{"fqn": "DB.PUBLIC.T"}]}


def test_enrichment_crash_safe_when_flag_on(monkeypatch):
    """A connector raising inside the estate helper must never break a scan."""
    _clear(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_INVENTORY", "1")

    monkeypatch.setattr(
        snowflake,
        "enrich_report_with_snowflake_estate",
        lambda report: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)  # must not raise

    assert report.snowflake_object_graph_data is None


def test_estate_helper_attaches_blocks_and_is_crash_safe(monkeypatch):
    """The shared helper attaches blocks returned by discoveries and swallows failures."""
    _clear(monkeypatch)

    monkeypatch.setattr(
        snowflake,
        "discover_object_dependencies",
        lambda *a, **k: {"status": "ok", "objects": [{"fqn": "DB.PUBLIC.ORDERS"}], "dependencies": []},
    )
    # A failing discovery must not abort the others nor the scan.
    monkeypatch.setattr(
        snowflake,
        "discover_login_anomalies",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    snowflake.enrich_report_with_snowflake_estate(report)  # must not raise

    assert report.snowflake_object_graph_data is not None
    assert report.snowflake_object_graph_data["objects"][0]["fqn"] == "DB.PUBLIC.ORDERS"
    assert report.snowflake_login_anomalies_data is None
