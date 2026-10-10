"""Storage backend support tiers: classification, startup warning and strict mode."""

from __future__ import annotations

import logging

import pytest

from agent_bom.core.settings import SettingError
from agent_bom.storage import tiers
from agent_bom.storage.tiers import (
    StorageSelection,
    StorageTier,
    UnsupportedStorageBackendError,
    classify_storage,
    enforce_storage_tiers,
    preflight_storage_backends,
    storage_selection_from_env,
)

_STORAGE_ENV = (
    "SNOWFLAKE_ACCOUNT",
    "AGENT_BOM_POSTGRES_URL",
    "AGENT_BOM_DB",
    "AGENT_BOM_GRAPH_BACKEND",
    "AGENT_BOM_ANALYTICS_BACKEND",
    "AGENT_BOM_CLICKHOUSE_URL",
    "AGENT_BOM_REQUIRE_SUPPORTED_STORAGE",
    "AGENT_BOM_REQUIRE_TENANT_BOUNDARY",
    "AGENT_BOM_CONTROL_PLANE_REPLICAS",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
)


@pytest.fixture(autouse=True)
def isolated_storage_env(monkeypatch):
    for name in _STORAGE_ENV:
        monkeypatch.delenv(name, raising=False)


def _backends(selection: StorageSelection) -> dict[str, tuple[str, StorageTier]]:
    return {item.component: (item.backend, item.tier) for item in classify_storage(selection).components}


@pytest.mark.parametrize(
    ("selection", "expected"),
    [
        (
            StorageSelection(),
            {"control_plane": ("memory", StorageTier.SUPPORTED), "graph": ("sqlite", StorageTier.SUPPORTED)},
        ),
        (
            StorageSelection(sqlite=True),
            {"control_plane": ("sqlite", StorageTier.SUPPORTED), "graph": ("sqlite", StorageTier.SUPPORTED)},
        ),
        (
            StorageSelection(postgres=True, sqlite=True),
            {"control_plane": ("postgres", StorageTier.SUPPORTED), "graph": ("postgres", StorageTier.SUPPORTED)},
        ),
        (
            StorageSelection(postgres=True, analytics_backend="clickhouse"),
            {
                "control_plane": ("postgres", StorageTier.SUPPORTED),
                "graph": ("postgres", StorageTier.SUPPORTED),
                "analytics": ("clickhouse", StorageTier.ANALYTICS_SINK),
            },
        ),
        (
            StorageSelection(snowflake=True, postgres=True),
            {"control_plane": ("snowflake", StorageTier.EXPERIMENTAL), "graph": ("postgres", StorageTier.SUPPORTED)},
        ),
        (
            StorageSelection(postgres=True, graph_backend="neptune"),
            {"control_plane": ("memory", StorageTier.SUPPORTED), "graph": ("neptune", StorageTier.EXPERIMENTAL)},
        ),
    ],
)
def test_classify_storage_matches_backend_precedence(selection, expected):
    assert _backends(selection) == expected


def test_clickhouse_is_never_the_system_of_record():
    report = classify_storage(StorageSelection(analytics_backend="clickhouse"))

    control_plane = [item for item in report.components if item.component == "control_plane"]
    assert [item.backend for item in control_plane] == ["memory"]
    assert report.experimental == ()


def test_selection_from_env_reads_postgres_url_in_agent_bom_db(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://synthetic:do-not-print@localhost/db")
    monkeypatch.setenv("AGENT_BOM_CLICKHOUSE_URL", "http://clickhouse.local:8123")

    selection = storage_selection_from_env()

    assert selection.postgres is True
    assert selection.sqlite is False
    assert selection.analytics_backend == "clickhouse"
    assert selection.multi_tenant is False


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AGENT_BOM_REQUIRE_TENANT_BOUNDARY", "1"),
        ("AGENT_BOM_CONTROL_PLANE_REPLICAS", "3"),
        ("AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON", '{"tenant-a": {"issuer": "https://idp.example"}}'),
    ],
)
def test_selection_from_env_detects_multi_tenant_signals(monkeypatch, name, value):
    monkeypatch.setenv(name, value)

    assert storage_selection_from_env().multi_tenant is True


def test_supported_backends_do_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="agent_bom.storage.tiers"):
        enforce_storage_tiers(classify_storage(StorageSelection(postgres=True, analytics_backend="clickhouse")), strict=True)

    assert caplog.records == []


def test_experimental_backend_logs_one_structured_warning(caplog):
    report = classify_storage(StorageSelection(snowflake=True, graph_backend="neptune"))

    with caplog.at_level(logging.WARNING, logger="agent_bom.storage.tiers"):
        enforce_storage_tiers(report, strict=False)

    assert len(caplog.records) == 1
    record = caplog.records[0]
    message = record.getMessage()
    assert "snowflake (control_plane)" in message
    assert "neptune (graph)" in message
    assert "tier=experimental" in message
    assert tiers.STORAGE_TIERS_DOC in message
    assert record.context["event"] == "storage_tier_experimental"
    assert record.context["experimental"] == ["snowflake", "neptune"]


def test_multi_tenant_warning_states_isolation_is_not_proven(caplog):
    report = classify_storage(StorageSelection(snowflake=True, multi_tenant=True))

    with caplog.at_level(logging.WARNING, logger="agent_bom.storage.tiers"):
        enforce_storage_tiers(report, strict=False)

    message = caplog.records[0].getMessage()
    assert "looks multi-tenant" in message
    assert "tenant isolation for these backends is not proven" in message


def test_strict_mode_refuses_experimental_backend():
    report = classify_storage(StorageSelection(graph_backend="neptune"))

    with pytest.raises(UnsupportedStorageBackendError, match="AGENT_BOM_REQUIRE_SUPPORTED_STORAGE=1"):
        enforce_storage_tiers(report, strict=True)


def test_preflight_is_advisory_by_default(monkeypatch, caplog):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "synthetic-account")

    with caplog.at_level(logging.WARNING, logger="agent_bom.storage.tiers"):
        report = preflight_storage_backends()

    assert [item.backend for item in report.experimental] == ["snowflake"]
    assert len(caplog.records) == 1


def test_preflight_strict_env_refuses_startup(monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "synthetic-account")
    monkeypatch.setenv("AGENT_BOM_REQUIRE_SUPPORTED_STORAGE", "1")

    with pytest.raises(UnsupportedStorageBackendError):
        preflight_storage_backends()


def test_preflight_strict_env_allows_supported_backends(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://synthetic@localhost/db")
    monkeypatch.setenv("AGENT_BOM_REQUIRE_SUPPORTED_STORAGE", "1")

    report = preflight_storage_backends()

    assert report.experimental == ()


def test_preflight_rejects_malformed_strict_flag(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_REQUIRE_SUPPORTED_STORAGE", "maybe")

    with pytest.raises(SettingError):
        preflight_storage_backends()


def test_preflight_still_rejects_remote_dsn_in_sqlite_path(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DB", "mysql://synthetic@localhost/db")

    with pytest.raises(ValueError, match="SQLite requires a filesystem path"):
        preflight_storage_backends()
