from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


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
    assert "AGENT_BOM_POSTGRES_ADMIN_URL: postgresql://agent_bom:" in workflow
    assert "AGENT_BOM_ALLOW_SUPERUSER_DB" not in workflow


def test_postgres_scale_evidence_sets_current_postgres_url(monkeypatch) -> None:
    script = Path("scripts/run_postgres_scale_evidence.py")
    spec = importlib.util.spec_from_file_location("run_postgres_scale_evidence", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_DSN", raising=False)

    module._set_postgres_env("postgresql://agent_bom:agent_bom@localhost:5432/agent_bom")

    assert os.environ["AGENT_BOM_POSTGRES_URL"] == "postgresql://agent_bom:agent_bom@localhost:5432/agent_bom"
    assert os.environ["AGENT_BOM_POSTGRES_DSN"] == "postgresql://agent_bom:agent_bom@localhost:5432/agent_bom"


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
