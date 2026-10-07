"""Configured exception persistence retains approval without creating authority."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_bom.api import audit_log, stores
from agent_bom.api.models import ExceptionRequest
from agent_bom.api.routes import enterprise


def test_configured_sqlite_exceptions_survive_new_process(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "waivers.db"))
    monkeypatch.setattr(stores, "_exception_store", None)
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-a", api_key_name="reviewer", api_key_role="admin"))
    approved = enterprise.create_exception(
        request,
        ExceptionRequest(vuln_id="CVE-2025-0001", package_name="example", reason="Bounded acceptance", expires_at="2099-01-01T00:00:00Z"),
    )
    enterprise.approve_exception(request, approved["exception_id"])
    pending = enterprise.create_exception(
        request,
        ExceptionRequest(vuln_id="CVE-2025-0002", package_name="example", reason="Awaiting review", expires_at="2099-01-01T00:00:00Z"),
    )
    original = {item.exception_id: item.to_dict() for item in stores._get_exception_store().list_all(tenant_id="tenant-a")}
    script = """
import json
from agent_bom.api.stores import _get_exception_store
store = _get_exception_store()
approved = store.find_matching('CVE-2025-0001', 'example', tenant_id='tenant-a')
print(json.dumps({
    'records': {item.exception_id: item.to_dict() for item in store.list_all(tenant_id='tenant-a')},
    'approved_match': approved.exception_id if approved else None,
    'pending_match': store.find_matching('CVE-2025-0002', 'example', tenant_id='tenant-a') is not None,
    'foreign_match': store.find_matching('CVE-2025-0001', 'example', tenant_id='tenant-b') is not None,
    'foreign_records': [item.to_dict() for item in store.list_all(tenant_id='tenant-b')],
}))
"""
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    result = subprocess.run([sys.executable, "-c", script], env=env, check=True, text=True, capture_output=True, timeout=30)
    restored = json.loads(result.stdout)
    assert restored["records"] == original
    assert restored["approved_match"] == approved["exception_id"]
    assert restored["records"][pending["exception_id"]]["status"] == "pending"
    assert restored["pending_match"] is False
    assert restored["foreign_match"] is False
    assert restored["foreign_records"] == []


def test_configured_storage_failure_does_not_fall_back_to_memory(monkeypatch, tmp_path):
    import sqlite3

    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "missing" / "waivers.db"))
    monkeypatch.setattr(stores, "_exception_store", None)
    with pytest.raises(sqlite3.OperationalError):
        stores._get_exception_store()
    assert stores._exception_store is None


def test_explicit_store_override_is_preserved(monkeypatch):
    from agent_bom.api.exception_store import InMemoryExceptionStore

    selected = InMemoryExceptionStore()
    monkeypatch.setattr(stores, "_exception_store", selected)
    monkeypatch.setenv("AGENT_BOM_DB", "/invalid/unused/path.db")
    assert stores._get_exception_store() is selected


def test_postgres_configuration_takes_precedence_over_sqlite(monkeypatch):
    from agent_bom.api import postgres_store
    from agent_bom.api.exception_store import InMemoryExceptionStore

    selected = InMemoryExceptionStore()
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://unused/test")
    monkeypatch.setenv("AGENT_BOM_DB", "/invalid/unused/path.db")
    monkeypatch.setattr(stores, "_exception_store", None)
    monkeypatch.setattr(postgres_store, "PostgresExceptionStore", lambda: selected)
    assert stores._get_exception_store() is selected


def test_postgres_configuration_failure_cannot_become_in_memory(monkeypatch):
    from agent_bom.api import postgres_store

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://unused/test")
    monkeypatch.setattr(stores, "_exception_store", None)

    def unavailable():
        raise RuntimeError("Configured backend unavailable")

    monkeypatch.setattr(postgres_store, "PostgresExceptionStore", unavailable)
    with pytest.raises(RuntimeError, match="Configured backend unavailable"):
        stores._get_exception_store()
    assert stores._exception_store is None


def test_store_import_does_not_initialize_unrelated_audit_signer():
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env.update(
        PYTHONPATH=str(Path(__file__).resolve().parents[2] / "src"),
        AGENT_BOM_POSTGRES_URL="postgresql://unused.invalid/fixture",
    )
    result = subprocess.run(
        [sys.executable, "-c", "import sys; import agent_bom.api.stores; assert 'agent_bom.api.audit_log' not in sys.modules"],
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
