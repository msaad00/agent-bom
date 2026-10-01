"""Qualification must detect persisted-content loss and use independent workers."""

import json
import subprocess
import sys

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from scripts.qualify_graph_store import verify_checkpoint, write


def test_process_qualification_and_content_verified_restart(tmp_path):
    report, restart, database = (tmp_path / name for name in ("report.json", "restart.json", "graph.db"))
    command = [sys.executable, "scripts/qualify_graph_store.py", "--sqlite", str(database)]
    completed = subprocess.run(
        command + ["--executor", "processes", "--seconds", "1", "--nodes", "50", "--output", str(report)],
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(report.read_text())
    assert result["executor"] == "processes"
    assert len({worker["pid"] for worker in result["outcomes"]}) == 4
    assert all(worker["operations"] > 0 for worker in result["outcomes"])
    assert all(value["content_sha256"] for value in result["checkpoint"].values())
    verified = subprocess.run(
        command + ["--verify-checkpoint", str(report), "--output", str(restart)], capture_output=True, text=True, timeout=30
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(restart.read_text())["verified_tenants"] == 2


def test_checkpoint_rejects_same_count_content_change(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    write(store, "tenant", 50, 0)
    revision = store.snapshot_identity(tenant_id="tenant", scan_id="qualification", for_paging=True)[1]
    with pytest.raises(AssertionError, match="content"):
        verify_checkpoint(store, {"tenant": {"revision": revision, "nodes": 50, "content_sha256": "wrong"}})


def test_optimized_python_does_not_silently_disable_qualification(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-O",
            "scripts/qualify_graph_store.py",
            "--sqlite",
            str(tmp_path / "graph.db"),
            "--output",
            str(tmp_path / "report.json"),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert "assertions" in result.stderr


def test_failed_qualification_keeps_a_private_failure_receipt(tmp_path):
    report = tmp_path / "failure.json"
    result = subprocess.run(
        [sys.executable, "scripts/qualify_graph_store.py", "--sqlite", str(tmp_path), "--output", str(report)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 1
    assert json.loads(report.read_text())["status"] == "failed"
    assert report.stat().st_mode & 0o777 == 0o600
    original = report.read_bytes()
    repeated = subprocess.run(
        [sys.executable, "scripts/qualify_graph_store.py", "--sqlite", str(tmp_path), "--output", str(report)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert repeated.returncode != 0
    assert report.read_bytes() == original
