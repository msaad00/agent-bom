"""Skills result persistence follows the configured API tier without cross-tenant reads."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from agent_bom.api import skills_scan_store as stores
from agent_bom.api.routes.skills import router
from tests.auth_helpers import PROXY_SECRET, proxy_headers


@pytest.fixture(autouse=True)
def isolated_store(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    original = stores._default_store
    for name in ("AGENT_BOM_DB", "AGENT_BOM_POSTGRES_URL", "SNOWFLAKE_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)
    stores.set_skills_scan_store(None)
    yield
    stores.set_skills_scan_store(original)


def run(tenant="alpha", run_id="same", age_days=0):
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    return stores.SkillsScanRun(tenant, run_id, created.isoformat(), {"owner": tenant, "run_id": run_id})


def test_configured_sqlite_survives_factory_restart_and_another_instance(monkeypatch, tmp_path):
    path = tmp_path / "control.db"
    monkeypatch.setenv("AGENT_BOM_DB", str(path))
    first = stores.get_skills_scan_store()
    first.put(run())
    second = stores.SQLiteSkillsScanStore(path)
    assert second.latest_for_tenant("alpha").payload == {"owner": "alpha", "run_id": "same"}
    second.put(run("beta"))
    stores.set_skills_scan_store(None)
    restarted = stores.get_skills_scan_store()
    assert restarted.latest_for_tenant("alpha").payload["owner"] == "alpha"
    assert restarted.latest_for_tenant("beta").payload["owner"] == "beta"
    assert restarted.latest_for_tenant("other") is None


def test_explicit_store_is_preserved_over_configured_sqlite(monkeypatch, tmp_path):
    injected = stores.InMemorySkillsScanStore()
    stores.set_skills_scan_store(injected)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "unused.db"))
    assert stores.get_skills_scan_store() is injected
    assert not (tmp_path / "unused.db").exists()


@pytest.mark.parametrize("setting", ["AGENT_BOM_POSTGRES_URL", "SNOWFLAKE_ACCOUNT"])
def test_unsupported_durable_backend_is_skills_only_unavailable(monkeypatch, setting):
    monkeypatch.setenv(setting, "synthetic-configured-tier")
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    client = TestClient(app)
    response = client.get("/v1/skills/scan", headers=proxy_headers(role="viewer", tenant="alpha"))
    assert response.status_code == 503
    assert "SQLite" in response.json()["detail"]
    assert "synthetic-configured-tier" not in response.text


def test_memory_default_remains_explicitly_ephemeral():
    stores.get_skills_scan_store().put(run())
    stores.set_skills_scan_store(None)
    assert isinstance(stores.get_skills_scan_store(), stores.InMemorySkillsScanStore)
    assert stores.get_skills_scan_store().latest_for_tenant("alpha") is None


def test_real_http_scan_survives_sqlite_store_restart(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "results.db"))
    monkeypatch.setenv("AGENT_BOM_API_LOCAL_PATH_SCANS", "enabled")
    monkeypatch.setenv("AGENT_BOM_API_SCAN_ROOT", str(tmp_path))
    (tmp_path / "SKILL.md").write_text("---\nname: fixture\ndescription: Read public documentation\n---\n# Read docs\n")
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    client = TestClient(app)
    posted = client.post("/v1/skills/scan", headers=proxy_headers(role="admin", tenant="alpha"), json={"files": ["SKILL.md"]})
    assert posted.status_code == 200
    assert posted.json()["summary"]["files_scanned"] == 1
    stores.set_skills_scan_store(None)
    restarted = TestClient(app)
    latest = restarted.get("/v1/skills/scan", headers=proxy_headers(role="viewer", tenant="alpha"))
    assert latest.json() == posted.json()
    other = restarted.get("/v1/skills/scan", headers=proxy_headers(role="viewer", tenant="beta"))
    assert other.json()["status"] == "no_data"


@pytest.mark.parametrize("setting", ["AGENT_BOM_POSTGRES_URL", "SNOWFLAKE_ACCOUNT"])
def test_unsupported_tier_rejects_before_scanner_side_effects(monkeypatch, tmp_path, setting):
    from unittest.mock import Mock

    from agent_bom import skills_service

    monkeypatch.setenv(setting, "synthetic-configured-tier")
    monkeypatch.setenv("AGENT_BOM_API_LOCAL_PATH_SCANS", "enabled")
    monkeypatch.setenv("AGENT_BOM_API_SCAN_ROOT", str(tmp_path))
    (tmp_path / "SKILL.md").write_text("# Fixture\n")
    scanner = Mock(side_effect=AssertionError("unavailable storage must reject before scan"))
    monkeypatch.setattr(skills_service, "scan_skill_targets", scanner)
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    response = TestClient(app).post("/v1/skills/scan", headers=proxy_headers(role="admin", tenant="alpha"), json={"files": ["SKILL.md"]})
    assert response.status_code == 503
    scanner.assert_not_called()


def test_explicit_sqlite_companion_wins_over_remote_tier(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "synthetic-configured-tier")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "skills.db"))
    assert isinstance(stores.get_skills_scan_store(), stores.SQLiteSkillsScanStore)


@pytest.mark.parametrize("db", ["postgres://fixture/skills", "postgresql://fixture/skills", "postgresql+psycopg://fixture/skills"])
def test_remote_db_url_never_becomes_sqlite_filename(monkeypatch, db):
    monkeypatch.setenv("AGENT_BOM_DB", db)
    with pytest.raises(stores.SkillsPersistenceUnavailableError):
        stores.get_skills_scan_store()
