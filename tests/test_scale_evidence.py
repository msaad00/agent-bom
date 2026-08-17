from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_scale_evidence_scaffold_is_complete() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_scale_evidence.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_postgres_scale_workflow_migrates_before_workload() -> None:
    """Scale evidence must use the shipped schema and database-enforced RLS."""
    workflow = Path(".github/workflows/postgres-scale-evidence.yml").read_text()

    assert "Migrate ephemeral Postgres schema" in workflow
    assert "alembic -c deploy/supabase/postgres/alembic.ini upgrade head" in workflow
    assert "AGENT_BOM_POSTGRES_URL: postgresql://agent_bom_app:" in workflow
    assert "AGENT_BOM_POSTGRES_MAINTENANCE_URL: postgresql://agent_bom_maintenance:" in workflow
    assert "AGENT_BOM_POSTGRES_ADMIN_URL: postgresql://agent_bom:" in workflow
    assert "AGENT_BOM_AUDIT_HMAC_KEY: postgres-scale-evidence-audit-signing-key" in workflow
    assert "ALTER DATABASE agent_bom SET init.maintenance_password = 'benchmark_maintenance'" in workflow
    assert "AGENT_BOM_ALLOW_SUPERUSER_DB" not in workflow


def test_postgres_scale_evidence_sets_current_postgres_url(monkeypatch) -> None:
    script = Path("scripts/run_postgres_scale_evidence.py")
    spec = importlib.util.spec_from_file_location("run_postgres_scale_evidence", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    env_keys = (
        "AGENT_BOM_POSTGRES_URL",
        "AGENT_BOM_POSTGRES_DSN",
        "AGENT_BOM_POSTGRES_POOL_MIN_SIZE",
        "AGENT_BOM_POSTGRES_POOL_MAX_SIZE",
    )
    original_env = {key: os.environ.get(key) for key in env_keys}

    with monkeypatch.context() as isolated_env:
        # Register all four variables with monkeypatch before the benchmark helper
        # mutates os.environ directly, so teardown cannot leak its pool size into
        # later config reloads in the randomized/xdist test suite.
        for key in env_keys:
            isolated_env.setenv(key, "test-baseline")

        module._set_postgres_env(
            "postgresql://agent_bom:agent_bom@localhost:5432/agent_bom",
            pool_min_size=1,
            pool_max_size=4,
        )

        assert os.environ["AGENT_BOM_POSTGRES_URL"] == "postgresql://agent_bom:agent_bom@localhost:5432/agent_bom"
        assert os.environ["AGENT_BOM_POSTGRES_DSN"] == "postgresql://agent_bom:agent_bom@localhost:5432/agent_bom"
        assert os.environ["AGENT_BOM_POSTGRES_POOL_MIN_SIZE"] == "1"
        assert os.environ["AGENT_BOM_POSTGRES_POOL_MAX_SIZE"] == "4"

    assert {key: os.environ.get(key) for key in env_keys} == original_env


def test_postgres_scale_evidence_records_bounded_pool_budget() -> None:
    script = Path("scripts/run_postgres_scale_evidence.py")
    spec = importlib.util.spec_from_file_location("run_postgres_scale_evidence", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    evidence = module.generate(
        None,
        [1_000],
        4,
        ["job_put"],
        dry_run=True,
        pool_min_size=1,
        pool_max_size=4,
    )

    assert evidence["environment"]["postgres_pool_min_size_per_replica"] == 1
    assert evidence["environment"]["postgres_pool_max_size_per_replica"] == 4
    assert evidence["environment"]["postgres_pool_max_connections"] == 16


def test_postgres_scale_evidence_requires_maintenance_role_for_audit(monkeypatch) -> None:
    script = Path("scripts/run_postgres_scale_evidence.py")
    spec = importlib.util.spec_from_file_location("run_postgres_scale_evidence", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_MAINTENANCE_URL", raising=False)

    with pytest.raises(SystemExit, match="AGENT_BOM_POSTGRES_MAINTENANCE_URL.*--kinds includes audit"):
        module.generate(
            "postgresql://app@localhost/agent_bom",
            [1],
            1,
            ["audit"],
            dry_run=False,
        )


def test_postgres_scale_evidence_preflights_migrated_schema(monkeypatch) -> None:
    script = Path("scripts/run_postgres_scale_evidence.py")
    spec = importlib.util.spec_from_file_location("run_postgres_scale_evidence", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class Result:
        def __init__(self, value: str | None) -> None:
            self.value = value

        def fetchone(self) -> tuple[str | None]:
            return (self.value,)

    class Connection:
        def __init__(self, value: str | None) -> None:
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def execute(self, _query: str) -> Result:
            return Result(self.value)

    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda _dsn: Connection("control_plane_schema_versions")),
    )
    module._validate_postgres_schema("postgresql://app@localhost/agent_bom")

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda _dsn: Connection(None)))
    with pytest.raises(SystemExit, match="alembic.*upgrade head"):
        module._validate_postgres_schema("postgresql://app@localhost/agent_bom")


def test_postgres_scale_workflow_bounds_each_replica_pool() -> None:
    workflow = Path(".github/workflows/postgres-scale-evidence.yml").read_text()

    assert 'AGENT_BOM_POSTGRES_POOL_MIN_SIZE: "1"' in workflow
    assert 'AGENT_BOM_POSTGRES_POOL_MAX_SIZE: "4"' in workflow


def test_postgres_scale_audit_payload_matches_runtime_contract() -> None:
    from agent_bom.api.audit_log import AuditEntry

    script = Path("scripts/run_postgres_scale_evidence.py")
    spec = importlib.util.spec_from_file_location("run_postgres_scale_evidence", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    entry = AuditEntry(**module._synth_audit_entry(7, tenant_id="tenant-7"))

    assert entry.details == {"tenant_id": "tenant-7", "source": "postgres-scale-evidence", "idx": 7}


def test_postgres_scale_job_models_use_api_contract() -> None:
    script = Path("scripts/run_postgres_scale_evidence.py").read_text()

    assert "from agent_bom.api.models import ScanJob, ScanRequest" in script
    assert "from agent_bom.models import ScanJob, ScanRequest" not in script


def test_postgres_scale_job_operations_install_and_reset_tenant(monkeypatch) -> None:
    script = Path("scripts/run_postgres_scale_evidence.py")
    spec = importlib.util.spec_from_file_location("run_postgres_scale_evidence", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    events: list[tuple[str, object]] = []

    class Store:
        def put(self, job) -> None:
            events.append(("put", job.tenant_id))

        def get(self, job_id: str, tenant_id: str):
            events.append(("get", (job_id, tenant_id)))
            return object()

    monkeypatch.setattr("agent_bom.api.postgres_common.set_current_tenant", lambda tenant: events.append(("set", tenant)) or "token")
    monkeypatch.setattr("agent_bom.api.postgres_common.reset_current_tenant", lambda token: events.append(("reset", token)))

    store = Store()
    module._tenant_job_put(store, SimpleNamespace(tenant_id="tenant-a"))
    assert module._tenant_job_get(store, "job-a", "tenant-a") is not None

    assert events == [
        ("set", "tenant-a"),
        ("put", "tenant-a"),
        ("reset", "token"),
        ("set", "tenant-a"),
        ("get", ("job-a", "tenant-a")),
        ("reset", "token"),
    ]
