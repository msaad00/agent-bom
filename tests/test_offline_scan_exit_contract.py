from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("database_state", ["missing", "corrupt"])
def test_real_offline_repository_scan_writes_partial_artifact_and_exits_one(
    tmp_path: Path,
    database_state: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    database = tmp_path / "vulns.db"
    if database_state == "corrupt":
        database.write_text("not a sqlite database", encoding="utf-8")

    report = tmp_path / "report.json"
    clean_home = tmp_path / "home"
    clean_home.mkdir()
    source_root = Path(__file__).resolve().parents[1] / "src"
    inherited_pythonpath = os.environ.get("PYTHONPATH", "")
    env = {
        **os.environ,
        "HOME": str(clean_home),
        "AGENT_BOM_DB_PATH": str(database),
        "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
        "AGENT_BOM_CONFIG": str(tmp_path / "no-config.toml"),
        "PYTHONPATH": os.pathsep.join(part for part in (str(source_root), inherited_pythonpath) if part),
    }
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from agent_bom.cli import main; main()",
            "scan",
            str(project),
            "--offline",
            "--no-auto-update-db",
            "--format",
            "json",
            "--output",
            str(report),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["scan_run"]["outcome"] == "partial"
    assert payload["scan_run"]["issues"][0]["code"] == "required_scanner_unavailable"
    assert payload["scan_performance"]["coverage_state"] == "incomplete"
    assert "populated local vulnerability DB" in payload["warnings"][0]
