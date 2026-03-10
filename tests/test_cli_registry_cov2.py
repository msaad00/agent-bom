"""Tests for agent_bom.cli._registry to improve coverage."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli._registry import (
    registry,
    schedule,
)

# ---------------------------------------------------------------------------
# registry list
# ---------------------------------------------------------------------------


def test_registry_list_json():
    runner = CliRunner()
    with patch(
        "agent_bom.registry.list_registry",
        return_value=[
            {
                "package": "test-server",
                "latest_version": "1.0.0",
                "ecosystem": "npm",
                "category": "database",
                "risk_level": "high",
                "verified": True,
            }
        ],
    ):
        result = runner.invoke(registry, ["list", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1


def test_registry_list_table():
    runner = CliRunner()
    with patch(
        "agent_bom.registry.list_registry",
        return_value=[
            {
                "package": "test-server",
                "latest_version": "1.0.0",
                "ecosystem": "npm",
                "category": "database",
                "risk_level": "high",
                "verified": True,
            },
            {
                "package": "server2",
                "latest_version": "2.0",
                "ecosystem": "pypi",
                "category": "filesystem",
                "risk_level": "low",
                "verified": False,
            },
        ],
    ):
        result = runner.invoke(registry, ["list"])
        assert result.exit_code == 0
        assert "test-server" in result.output


def test_registry_list_with_filters():
    runner = CliRunner()
    with patch("agent_bom.registry.list_registry", return_value=[]):
        result = runner.invoke(registry, ["list", "--category", "database", "--risk-level", "high", "--ecosystem", "npm"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# registry search
# ---------------------------------------------------------------------------


def test_registry_search_no_results():
    runner = CliRunner()
    with patch("agent_bom.registry.search_registry", return_value=[]):
        result = runner.invoke(registry, ["search", "nonexistent"])
        assert result.exit_code == 0
        assert "No results" in result.output


def test_registry_search_with_results():
    runner = CliRunner()
    with patch(
        "agent_bom.registry.search_registry",
        return_value=[
            {
                "package": "test-server",
                "latest_version": "1.0",
                "ecosystem": "npm",
                "category": "database",
                "risk_level": "medium",
                "description": "A test server for testing",
            },
        ],
    ):
        result = runner.invoke(registry, ["search", "test"])
        assert result.exit_code == 0
        assert "test-server" in result.output


# ---------------------------------------------------------------------------
# registry update
# ---------------------------------------------------------------------------


def test_registry_update():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        updated=2,
        unchanged=8,
        failed=1,
        total=11,
        details=[
            {"package": "pkg1", "status": "updated", "old": "1.0", "new": "2.0"},
            {"package": "pkg2", "status": "updated", "old": "3.0", "new": "4.0"},
            {"package": "pkg3", "status": "failed"},
        ],
    )
    with patch("agent_bom.registry.update_registry_versions_sync", return_value=mock_result):
        result = runner.invoke(registry, ["update", "--dry-run"])
        assert result.exit_code == 0
        assert "Updated 2" in result.output


def test_registry_update_many_failures():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        updated=0,
        unchanged=0,
        failed=10,
        total=10,
        details=[{"package": f"pkg{i}", "status": "failed"} for i in range(10)],
    )
    with patch("agent_bom.registry.update_registry_versions_sync", return_value=mock_result):
        result = runner.invoke(registry, ["update"])
        assert result.exit_code == 0
        assert "Failed to resolve" in result.output


# ---------------------------------------------------------------------------
# registry enrich
# ---------------------------------------------------------------------------


def test_registry_enrich_some():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        enriched=2,
        skipped=5,
        total=7,
        details=[
            {"server": "srv1", "fields_enriched": ["risk_level", "credential_env_vars"]},
            {"server": "srv2", "fields_enriched": ["risk_justification"]},
        ],
    )
    with patch("agent_bom.registry.enrich_registry_entries", return_value=mock_result):
        result = runner.invoke(registry, ["enrich"])
        assert result.exit_code == 0
        assert "Enriched 2" in result.output


def test_registry_enrich_none():
    runner = CliRunner()
    mock_result = SimpleNamespace(enriched=0, skipped=5, total=5, details=[])
    with patch("agent_bom.registry.enrich_registry_entries", return_value=mock_result):
        result = runner.invoke(registry, ["enrich", "--dry-run"])
        assert result.exit_code == 0
        assert "complete metadata" in result.output


# ---------------------------------------------------------------------------
# registry enrich-cves
# ---------------------------------------------------------------------------


def test_registry_enrich_cves_found():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        enriched=1,
        total=5,
        scannable=3,
        total_cves=3,
        total_critical=1,
        total_kev=0,
        details=[
            {"server": "srv1", "cve_count": 2, "ghsa_count": 1, "kev": False, "cves": ["CVE-2025-0001", "CVE-2025-0002"]},
        ],
    )
    with patch("agent_bom.registry.enrich_registry_with_cves_sync", return_value=mock_result):
        result = runner.invoke(registry, ["enrich-cves"])
        assert result.exit_code == 0
        assert "CVE-2025-0001" in result.output


def test_registry_enrich_cves_none():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        enriched=0,
        total=5,
        scannable=3,
        total_cves=0,
        total_critical=0,
        total_kev=0,
        details=[],
    )
    with patch("agent_bom.registry.enrich_registry_with_cves_sync", return_value=mock_result):
        result = runner.invoke(registry, ["enrich-cves", "--dry-run"])
        assert result.exit_code == 0
        assert "No known CVEs" in result.output


def test_registry_enrich_cves_with_kev():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        enriched=1,
        total=2,
        scannable=2,
        total_cves=1,
        total_critical=0,
        total_kev=1,
        details=[
            {"server": "srv1", "cve_count": 1, "ghsa_count": 0, "kev": True, "cves": ["CVE-2025-9999"]},
        ],
    )
    with patch("agent_bom.registry.enrich_registry_with_cves_sync", return_value=mock_result):
        result = runner.invoke(registry, ["enrich-cves"])
        assert result.exit_code == 0
        assert "KEV" in result.output


# ---------------------------------------------------------------------------
# registry smithery-sync
# ---------------------------------------------------------------------------


def test_smithery_sync_no_token():
    runner = CliRunner()
    result = runner.invoke(registry, ["smithery-sync"])
    assert result.exit_code == 1
    assert "API key required" in result.output


def test_smithery_sync_success():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        added=3,
        skipped=10,
        total_fetched=13,
        details=[
            {"display_name": "server1", "verified": True, "use_count": 100, "risk_level": "low"},
        ],
    )
    with patch("agent_bom.smithery.sync_from_smithery_sync", return_value=mock_result):
        result = runner.invoke(registry, ["smithery-sync", "--token", "test-key"])
        assert result.exit_code == 0
        assert "Added 3" in result.output


def test_smithery_sync_none_added():
    runner = CliRunner()
    mock_result = SimpleNamespace(added=0, skipped=10, total_fetched=10, details=[])
    with patch("agent_bom.smithery.sync_from_smithery_sync", return_value=mock_result):
        result = runner.invoke(registry, ["smithery-sync", "--token", "key"])
        assert result.exit_code == 0
        assert "No new servers" in result.output


# ---------------------------------------------------------------------------
# registry mcp-sync
# ---------------------------------------------------------------------------


def test_mcp_sync_success():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        added=5,
        skipped=20,
        total_fetched=25,
        details=[{"server": "srv1", "version": "1.0"}],
    )
    with patch("agent_bom.mcp_official_registry.sync_from_official_registry_sync", return_value=mock_result):
        result = runner.invoke(registry, ["mcp-sync"])
        assert result.exit_code == 0
        assert "Added 5" in result.output


def test_mcp_sync_none():
    runner = CliRunner()
    mock_result = SimpleNamespace(added=0, skipped=10, total_fetched=10, details=[])
    with patch("agent_bom.mcp_official_registry.sync_from_official_registry_sync", return_value=mock_result):
        result = runner.invoke(registry, ["mcp-sync", "--dry-run"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# registry glama-sync
# ---------------------------------------------------------------------------


def test_glama_sync_success():
    runner = CliRunner()
    mock_result = SimpleNamespace(
        added=2,
        skipped=8,
        total_fetched=10,
        details=[{"server": "s1"}, {"server": "s2"}],
    )
    with patch("agent_bom.glama.sync_from_glama_sync", return_value=mock_result):
        result = runner.invoke(registry, ["glama-sync"])
        assert result.exit_code == 0
        assert "Added 2" in result.output


# ---------------------------------------------------------------------------
# registry sync-all
# ---------------------------------------------------------------------------


def test_sync_all_no_smithery():
    runner = CliRunner()
    mock_r = SimpleNamespace(added=1, skipped=5, total_fetched=6, details=[])
    with (
        patch("agent_bom.mcp_official_registry.sync_from_official_registry_sync", return_value=mock_r),
        patch("agent_bom.glama.sync_from_glama_sync", return_value=mock_r),
    ):
        result = runner.invoke(registry, ["sync-all", "--dry-run"])
        assert result.exit_code == 0
        assert "Skipped" in result.output  # Smithery skipped


def test_sync_all_with_smithery():
    runner = CliRunner()
    mock_r = SimpleNamespace(added=1, skipped=5, total_fetched=6, details=[])
    with (
        patch("agent_bom.mcp_official_registry.sync_from_official_registry_sync", return_value=mock_r),
        patch("agent_bom.smithery.sync_from_smithery_sync", return_value=mock_r),
        patch("agent_bom.glama.sync_from_glama_sync", return_value=mock_r),
    ):
        result = runner.invoke(registry, ["sync-all", "--smithery-token", "key"])
        assert result.exit_code == 0
        assert "3" in result.output  # total added across all sources


# ---------------------------------------------------------------------------
# schedule commands
# ---------------------------------------------------------------------------


def test_schedule_add():
    runner = CliRunner()
    with patch("agent_bom.api.schedule_store.InMemoryScheduleStore") as mock_cls:
        mock_store = MagicMock()
        mock_cls.return_value = mock_store
        result = runner.invoke(schedule, ["add", "--name", "daily", "--cron", "0 0 * * *"])
        assert result.exit_code == 0
        assert "Schedule created" in result.output


def test_schedule_list_empty():
    runner = CliRunner()
    with patch("agent_bom.api.schedule_store.InMemoryScheduleStore") as mock_cls:
        mock_store = MagicMock()
        mock_store.list_all.return_value = []
        mock_cls.return_value = mock_store
        result = runner.invoke(schedule, ["list"])
        assert result.exit_code == 0
        assert "No schedules" in result.output


def test_schedule_list_with_items():
    runner = CliRunner()
    mock_sched = SimpleNamespace(
        schedule_id="abc12345",
        name="daily",
        cron_expression="0 0 * * *",
        enabled=True,
        next_run="2025-01-02T00:00:00Z",
    )
    with patch("agent_bom.api.schedule_store.InMemoryScheduleStore") as mock_cls:
        mock_store = MagicMock()
        mock_store.list_all.return_value = [mock_sched]
        mock_cls.return_value = mock_store
        result = runner.invoke(schedule, ["list"])
        assert result.exit_code == 0
        assert "daily" in result.output


def test_schedule_remove_success():
    runner = CliRunner()
    with patch("agent_bom.api.schedule_store.InMemoryScheduleStore") as mock_cls:
        mock_store = MagicMock()
        mock_store.delete.return_value = True
        mock_cls.return_value = mock_store
        result = runner.invoke(schedule, ["remove", "abc-123"])
        assert result.exit_code == 0
        assert "Deleted" in result.output


def test_schedule_remove_not_found():
    runner = CliRunner()
    with patch("agent_bom.api.schedule_store.InMemoryScheduleStore") as mock_cls:
        mock_store = MagicMock()
        mock_store.delete.return_value = False
        mock_cls.return_value = mock_store
        result = runner.invoke(schedule, ["remove", "xyz-999"])
        assert result.exit_code == 1
        assert "not found" in result.output
