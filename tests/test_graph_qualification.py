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
    for worker in result["outcomes"]:
        measurements = worker["operation_measurements"]
        assert measurements["samples"] == worker["operations"]
        assert sum(measurements["progress_by_second"].values()) == worker["operations"]
        assert 0 <= measurements["p50_ms"] <= measurements["p95_ms"] <= measurements["max_ms"]
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


def test_thread_worker_failure_preserves_safe_sqlite_diagnostics(monkeypatch, tmp_path):
    import sqlite3

    from scripts import qualify_graph_store as probe

    original = probe.write

    def fail_after_seed(store, tenant, size, sequence):
        if sequence:
            exc = sqlite3.OperationalError("secret=do-not-record /private/customer.db")
            exc.sqlite_errorcode = sqlite3.SQLITE_BUSY
            exc.sqlite_errorname = "SQLITE_BUSY"
            raise exc
        return original(store, tenant, size, sequence)

    monkeypatch.setattr(probe, "write", fail_after_seed)
    with pytest.raises(probe.QualificationError) as failed:
        probe.qualify(SQLiteGraphStore(tmp_path / "graph.db"), 0.5, 50)
    outcomes = failed.value.outcomes
    errors = [item for item in outcomes if item.get("error_type") == "OperationalError"]
    assert errors and all(item["stage"] == "write" for item in errors)
    assert all(item["sqlite_errorcode"] == sqlite3.SQLITE_BUSY for item in errors)
    assert all(item["sqlite_errorname"] == "SQLITE_BUSY" for item in errors)
    assert all(item["operations"] == 0 for item in errors)
    assert "do-not-record" not in json.dumps(outcomes)
    assert len(outcomes) == 4


def test_thread_reader_rejects_duplicate_relationship_pages(monkeypatch, tmp_path):
    from scripts import qualify_graph_store as probe

    store = SQLiteGraphStore(tmp_path / "graph.db")
    original = store.incident_edges_page

    def repeat_page(**kwargs):
        kwargs.pop("cursor", None)
        return original(**kwargs)

    monkeypatch.setattr(store, "incident_edges_page", repeat_page)
    from threading import Event

    probe.write(store, "tenant", 50, 0)
    result = probe.run_worker(store, "tenant", 50, "reader", Event())
    assert result["error_type"] == "AssertionError"
    assert result["stage"] == "validate_pages"
    assert result["completed_read_pairs"] == 0


def test_failure_receipt_has_sqlite_code_without_raw_error(tmp_path):
    report = tmp_path / "failure.json"
    result = subprocess.run(
        [sys.executable, "scripts/qualify_graph_store.py", "--sqlite", str(tmp_path), "--output", str(report)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    receipt = json.loads(report.read_text())
    assert result.returncode == 1
    assert receipt["sqlite_errorname"] == "SQLITE_CANTOPEN"
    assert receipt["stage"] == "qualify"
    assert str(tmp_path) not in result.stdout


def test_real_sqlite_busy_code_is_preserved(tmp_path):
    import sqlite3

    from scripts.qualify_graph_store import error_details

    with sqlite3.connect(tmp_path / "locked.db") as owner, sqlite3.connect(tmp_path / "locked.db", timeout=0) as contender:
        owner.execute("CREATE TABLE evidence (id INTEGER)")
        owner.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError) as error:
            contender.execute("INSERT INTO evidence VALUES (1)")
        assert error_details(error.value) == {"error_type": "OperationalError", "sqlite_errorcode": 5, "sqlite_errorname": "SQLITE_BUSY"}


def test_process_start_failure_is_ready_and_has_safe_diagnostics(monkeypatch):
    import queue
    import sqlite3
    from contextlib import contextmanager
    from threading import Event

    from scripts import qualify_graph_store as probe

    @contextmanager
    def unavailable_store(sqlite):
        exc = sqlite3.OperationalError("password=secret")
        exc.sqlite_errorcode = sqlite3.SQLITE_CANTOPEN
        exc.sqlite_errorname = "untrusted private contents"
        raise exc
        yield  # pragma: no cover

    monkeypatch.setattr(probe, "open_store", unavailable_store)
    ready, outcomes = queue.Queue(), queue.Queue()
    stop = Event()
    probe.process_worker(None, "tenant", 50, "writer", ready, Event(), stop, outcomes)
    assert ready.get_nowait()["status"] == "failed"
    failure = outcomes.get_nowait()
    assert failure["stage"] == "open_store"
    assert failure["sqlite_errorcode"] == 14
    assert "sqlite_errorname" not in failure
    assert "secret" not in json.dumps(failure)
    assert stop.is_set()


def test_reader_records_bounded_latency_and_serialized_payload_evidence(monkeypatch, tmp_path):
    from threading import Event

    from scripts import qualify_graph_store as probe

    store = SQLiteGraphStore(tmp_path / "graph.db")
    probe.write(store, "measured", 50, 0)
    original = store.incident_edges_page
    stop = Event()

    def one_pair(**kwargs):
        page = original(**kwargs)
        if kwargs.get("cursor"):
            stop.set()
        return page

    monkeypatch.setattr(store, "incident_edges_page", one_pair)
    result = probe.run_worker(store, "measured", 50, "reader", stop)
    assert "error_type" not in result
    measurements = result["read_measurements"]
    assert measurements["samples"] == 1
    assert measurements["sample_limit"] == 512
    assert measurements["p95_ms"] >= measurements["p50_ms"] >= 0
    assert measurements["max_payload_bytes"] >= measurements["mean_payload_bytes"] > 0
    assert measurements["representation"] == "two incident-edge pages serialized as compact JSON; not HTTP wire bytes"
