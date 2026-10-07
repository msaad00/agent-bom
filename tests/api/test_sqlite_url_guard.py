"""A remote database URL must never be opened as a local SQLite filename."""

import importlib
import sqlite3
from pathlib import Path

import pytest

STORES = [
    ("agent_bom.api.store", "SQLiteJobStore"),
    ("agent_bom.api.webhook_store", "SQLiteWebhookSubscriptionStore"),
    ("agent_bom.api.dataset_version_store", "SQLiteDatasetVersionStore"),
    ("agent_bom.api.evaluation_store", "SQLiteEvaluationRunStore"),
    ("agent_bom.api.drift_incident_store", "SQLiteDriftIncidentStore"),
    ("agent_bom.api.export_schedule_store", "SQLiteExportScheduleStore"),
    ("agent_bom.api.access_review", "SQLiteAccessReviewStore"),
    ("agent_bom.api.compliance_hub_store", "SQLiteComplianceHubStore"),
    ("agent_bom.cloud.runtime_workload_evidence_store", "SQLiteRuntimeWorkloadEvidenceStore"),
    ("agent_bom.api.storage.sql", "SQLiteBackend"),
    ("agent_bom.api.exception_store", "SQLiteExceptionStore"),
]


@pytest.mark.parametrize("module,class_name", STORES)
@pytest.mark.parametrize("scheme", ["postgres", "postgresql"])
def test_remote_url_is_rejected_before_sqlite_connect(monkeypatch, module, class_name, scheme):
    constructor = getattr(importlib.import_module(module), class_name)

    def forbidden(*args, **kwargs):
        pytest.fail("Remote DSN reached SQLite connect")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    with pytest.raises(ValueError, match="SQLite.*filesystem") as exc:
        constructor(f"{scheme}://user:sentinel-password@db.example/production")
    assert "sentinel-password" not in str(exc.value)
    assert "db.example" not in str(exc.value)


@pytest.mark.parametrize("value", [":memory:", "relative.db", "./postgres:archive.db", Path("relative.db")])
def test_valid_sqlite_paths_are_preserved(value):
    from agent_bom.storage.factory import validate_sqlite_path

    assert validate_sqlite_path(value) == str(value)


@pytest.mark.parametrize("value", [Path("postgresql://user:password@host/db"), " HTTPS://host/db", "mysql://host/db"])
def test_path_objects_and_other_remote_schemes_are_rejected(value):
    from agent_bom.storage.factory import validate_sqlite_path

    with pytest.raises(ValueError, match="SQLite.*filesystem"):
        validate_sqlite_path(value)


@pytest.mark.asyncio
async def test_lifespan_rejects_remote_url_before_initializing_any_store(monkeypatch):
    from agent_bom.api.server import _lifespan, app

    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://user:sentinel-password@db.example/production")
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: pytest.fail("Invalid config reached SQLite"))
    with pytest.raises(ValueError, match="SQLite.*filesystem") as exc:
        async with _lifespan(app):
            pass
    assert "sentinel-password" not in str(exc.value)
