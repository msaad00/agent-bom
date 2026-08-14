from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from agent_bom.db.adoption_events import (
    AdoptionEventStore,
    record_scan_completion_best_effort,
    set_adoption_event_store,
)


def test_adoption_events_are_disabled_without_opt_in(tmp_path: Path) -> None:
    db_path = tmp_path / "adoption.sqlite"
    store = AdoptionEventStore(db_path, enabled=False)

    assert store.record("scan_completed", channel="cli", outcome="complete") is False
    assert store.summary()["enabled"] is False
    assert not db_path.exists()


def test_enabled_adoption_store_restricts_database_permissions(tmp_path: Path) -> None:
    db_path = tmp_path / "adoption.sqlite"
    AdoptionEventStore(db_path, enabled=True).record("scan_completed", channel="cli", outcome="complete")

    assert stat.S_IMODE(db_path.stat().st_mode) == stat.S_IRUSR | stat.S_IWUSR


def test_funnel_records_only_bounded_non_customer_dimensions(tmp_path: Path) -> None:
    db_path = tmp_path / "adoption.sqlite"
    store = AdoptionEventStore(db_path, enabled=True)

    assert store.record("scan_completed", channel="cli", outcome="complete") is True
    assert store.record("artifact_created", channel="cli", artifact_type="sarif") is True
    assert store.record("investigation_started", channel="control_plane") is True
    assert store.record("verification_completed", channel="control_plane", outcome="verified_fixed") is True

    summary = store.summary()
    assert summary["schema_version"] == "adoption-funnel.v1"
    assert summary["enabled"] is True
    assert summary["counts"] == {
        "artifact_created": 1,
        "investigation_started": 1,
        "scan_completed": 1,
        "verification_completed": 1,
    }
    assert summary["privacy"]["stores_source_contents"] is False
    assert summary["privacy"]["stores_customer_resource_identifiers"] is False

    rows = store.events()
    serialized = json.dumps(rows, sort_keys=True)
    for forbidden in ("source_content", "secret", "credential", "resource_id", "finding_id", "tenant_id"):
        assert forbidden not in serialized


def test_repeat_ci_and_control_plane_milestones_are_idempotent(tmp_path: Path) -> None:
    store = AdoptionEventStore(tmp_path / "adoption.sqlite", enabled=True)

    store.record("scan_completed", channel="ci", outcome="complete", ci_provider="github_actions")
    store.record("scan_completed", channel="ci", outcome="partial", ci_provider="github_actions")
    store.record("scan_completed", channel="control_plane", outcome="complete")
    store.record("scan_completed", channel="control_plane", outcome="complete")

    counts = store.summary()["counts"]
    assert counts["scan_completed"] == 4
    assert counts["repeat_use"] == 1
    assert counts["ci_adopted"] == 1
    assert counts["control_plane_adopted"] == 1


@pytest.mark.parametrize(
    ("event_name", "dimensions"),
    [
        ("unknown_event", {"channel": "cli"}),
        ("scan_completed", {"channel": "cli", "resource_id": "customer-vm-123"}),
        ("scan_completed", {"channel": "cli", "outcome": "customer-specific-outcome"}),
        ("artifact_created", {"channel": "cli", "artifact_type": "../../secret"}),
    ],
)
def test_unknown_or_customer_controlled_dimensions_fail_closed(
    tmp_path: Path,
    event_name: str,
    dimensions: dict[str, str],
) -> None:
    store = AdoptionEventStore(tmp_path / "adoption.sqlite", enabled=True)

    with pytest.raises(ValueError):
        store.record(event_name, **dimensions)
    assert not store.events()


def test_scan_completion_detects_ci_and_records_only_artifact_type(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = AdoptionEventStore(tmp_path / "adoption.sqlite", enabled=True)
    set_adoption_event_store(store)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    try:
        assert record_scan_completion_best_effort(outcome="complete", artifact_type="sarif") is True
    finally:
        set_adoption_event_store(None)

    assert store.summary()["counts"] == {"artifact_created": 1, "ci_adopted": 1, "scan_completed": 1}
    serialized = json.dumps(store.events(), sort_keys=True)
    assert "github_actions" in serialized
    assert "GITHUB" not in serialized


def test_saved_history_report_counts_as_a_json_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom import history

    store = AdoptionEventStore(tmp_path / "adoption.sqlite", enabled=True)
    set_adoption_event_store(store)
    monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
    monkeypatch.setattr("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *args, **kwargs: None)
    try:
        history.save_report({"scan_id": "synthetic", "findings": []})
    finally:
        set_adoption_event_store(None)

    assert store.summary()["counts"] == {"artifact_created": 1}
