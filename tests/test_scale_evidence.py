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
