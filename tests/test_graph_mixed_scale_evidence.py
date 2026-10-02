"""Mixed-load evidence must retain failures and prove its synthetic fixture."""

import importlib.util
import sqlite3
from pathlib import Path

import pytest

_PATH = Path(__file__).parents[1] / "scripts" / "run_graph_mixed_scale_evidence.py"
_SPEC = importlib.util.spec_from_file_location("mixed_scale", _PATH)
assert _SPEC and _SPEC.loader
evidence = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(evidence)


def test_output_cannot_recursively_include_the_source_checkout(tmp_path, monkeypatch):
    import argparse

    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    output = tmp_path / "src" / "evidence"
    with pytest.raises(ValueError, match="outside"):
        evidence.run(argparse.Namespace(output=output))
    assert not output.exists()


def test_seed_preserves_tenant_counts_and_refuses_existing_state(tmp_path):
    db = tmp_path / "graph.db"
    counts = evidence.seed(db, tenants=2, findings=12, assets=3, agents=2, servers=2)
    assert len(counts) == 2
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT tenant_id, count(*) FROM graph_nodes GROUP BY tenant_id ORDER BY tenant_id").fetchall() == [
            ("scale-0", 19),
            ("scale-1", 19),
        ]
        assert conn.execute("SELECT count(*) FROM graph_edges").fetchone()[0] == 32
    with pytest.raises(FileExistsError):
        evidence.seed(db, tenants=2, findings=12, assets=3, agents=2, servers=2)


def test_summary_retains_rejected_and_timed_out_requests():
    result = evidence.summarize(
        [
            {"operation": "page", "ok": True, "ms": 10, "bytes": 20},
            {"operation": "page", "ok": False, "ms": 30, "status": 429, "bytes": 10},
            {"operation": "page", "ok": False, "ms": 180000, "error_type": "ReadTimeout", "bytes": 0},
        ]
    )
    assert result["page"]["requests"] == 3
    assert result["page"]["failures"] == 2
    assert result["page"]["all_attempts_ms"]["p99"] == 180000
    assert result["page"]["successful_ms"]["samples"] == 1


def test_response_validation_rejects_cross_tenant_and_unbounded_evidence():
    body = {"tenant_id": "scale-0", "nodes": [{"label": "scale-0 asset 0"}], "edges": []}
    assert evidence.valid_response("page", body, "scale-0", batch=2)
    assert not evidence.valid_response("page", body, "scale-1", batch=2)
    body["nodes"][0]["label"] = "scale-01 asset 0"
    assert not evidence.valid_response("page", body, "scale-0", batch=2)
    body["nodes"][0]["label"] = "scale-0 asset 0"
    body["edges"] = [{}] * 1001
    assert not evidence.valid_response("page", body, "scale-0", batch=2)
    assert not evidence.valid_response("ingest", {"ingested": 2, "tenant_id": "scale-1"}, "scale-0", batch=2)


def test_search_checks_result_ownership_without_an_absent_top_level_tenant():
    body = {"results": [{"label": "scale-0 finding 0", "attributes": {"owner": "scale-0"}}]}
    assert evidence.valid_response("search", body, "scale-0", batch=2)
    body["results"][0]["attributes"]["owner"] = "scale-1"
    assert not evidence.valid_response("search", body, "scale-0", batch=2)
    assert not evidence.valid_response("page", {"nodes": body["results"]}, "scale-0", batch=2)
    assert not evidence.valid_response("ingest", {"ingested": 2}, "scale-0", batch=2)
    assert not evidence.valid_response("search", [], "scale-0", batch=2)


def test_overlap_reports_measured_intervals_without_double_counting():
    rows = [
        {"operation": "ingest", "tenant": "a", "ok": True, "start_offset_ms": 0, "end_offset_ms": 10},
        {"operation": "ingest", "tenant": "a", "ok": False, "start_offset_ms": 2, "end_offset_ms": 8},
        {"operation": "page", "tenant": "a", "ok": True, "start_offset_ms": 5, "end_offset_ms": 15},
        {"operation": "search", "tenant": "a", "ok": True, "start_offset_ms": 20, "end_offset_ms": 30},
    ]
    result = evidence.overlap_summary(rows)
    assert result["read_write_overlap_ms"] == 5
    assert result["read_attempts_overlapping_ingest"] == 1
    assert result["read_attempts_overlapping_successful_ingest"] == 1
    assert result["by_operation"]["search"]["overlapping_ingest"] == 0
    rows[0]["ok"] = False
    assert evidence.overlap_summary(rows)["read_attempts_overlapping_successful_ingest"] == 0


def test_runtime_source_is_an_immutable_hashed_copy(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "runtime.py").write_text("original")
    frozen = tmp_path / "frozen"
    digest = evidence.freeze_source(source, frozen)
    (source / "runtime.py").write_text("changed")
    assert (frozen / "runtime.py").read_text() == "original"
    assert evidence.tree_digest(frozen) == digest
    assert evidence.tree_digest(source) != digest


@pytest.fixture()
def fake_run(tmp_path, monkeypatch):
    """Exercise orchestration and faults without Docker or a network listener."""
    import argparse
    import json
    import subprocess
    import threading
    import time

    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    (root / "src" / "runtime.py").write_text("fixture")
    monkeypatch.setattr(evidence, "ROOT", root)
    monkeypatch.setattr(evidence.subprocess, "check_output", lambda *a, **k: b"" if not k.get("text") else "revision\n")
    flags = {"request_error": False, "client_error": False, "cleanup_error": False, "write_error": False}
    calls = []
    setup_lock = threading.Lock()
    clients = 0

    def seed(db, **kwargs):
        db.write_bytes(b"fixture")
        return [{"tenant": "scale-0", "counts": {"nodes": 5, "edges": 3}}]

    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == "run":
            flags["secret_file_at_launch"] = (tmp_path / "result" / ".container.env").exists()
            flags["launch_env"] = kwargs.get("env", {})
        return "127.0.0.1:54321\n" if args[0] == "port" else "container\n"

    def remove(args, **kwargs):
        calls.append(tuple(args))
        content = "" if kwargs.get("text") else b""
        return subprocess.CompletedProcess(args, int(flags["cleanup_error"] and args[1] == "rm"), stdout=content, stderr=content)

    class Response:
        def __init__(self, body, status=200):
            self.status_code = status
            self.body = body
            self.content = json.dumps(body).encode()

        def json(self):
            return self.body

    class Client:
        def __init__(self, **kwargs):
            nonlocal clients
            self.tenant = kwargs.get("headers", {}).get("X-Agent-Bom-Tenant-ID")
            self.pages = 0
            if self.tenant:
                with setup_lock:
                    clients += 1
                    if flags["client_error"] and clients == 1:
                        raise RuntimeError("secret must not enter receipt")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, path, **kwargs):
            if path == "/health":
                return Response({})
            if not self.tenant:
                return Response({}, 401)
            time.sleep(0.005)
            if path == "/v1/graph":
                self.pages += 1
                if flags["request_error"] and self.pages == 2:
                    raise RuntimeError("secret must not enter receipt")
            node = {"label": self.tenant + " asset 0", "attributes": {"owner": self.tenant}}
            return Response({"results": [node]} if path.endswith("search") else {"tenant_id": self.tenant, "nodes": [node], "edges": []})

        def post(self, path, **kwargs):
            time.sleep(0.005)
            return Response({"tenant_id": self.tenant, "ingested": 2})

    original_write = Path.write_text

    def write(path, *args, **kwargs):
        if flags["write_error"] and path.name.startswith("receipt") and any(call[0] == "run" for call in calls):
            raise OSError("secret must not enter receipt")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(evidence, "seed", seed)
    monkeypatch.setattr(evidence, "docker", docker)
    monkeypatch.setattr(
        evidence,
        "resources",
        lambda name: {"memory_peak_bytes": 100, "cpu_stat": "usage_usec 10", "source_file": "/candidate/agent_bom/__init__.py"},
    )
    monkeypatch.setattr(evidence.subprocess, "run", remove)
    monkeypatch.setattr(evidence.httpx, "Client", Client)
    monkeypatch.setattr(Path, "write_text", write)
    args = argparse.Namespace(
        output=tmp_path / "result",
        tenants=1,
        findings_per_tenant=2,
        assets_per_tenant=2,
        agents_per_tenant=1,
        servers_per_tenant=1,
        read_requests=2,
        ingest_batches=2,
        batch_size=2,
        timeout=1,
    )
    return args, flags, calls


def test_unexpected_request_failure_preserves_all_attempts(fake_run):
    import json

    args, flags, calls = fake_run
    flags["request_error"] = True
    assert evidence.run(args) == 1
    text = (args.output / "receipt.json").read_text()
    receipt = json.loads(text)
    assert len(receipt["rows"]) == receipt["expected_attempts"] == 6
    assert sum(not row["ok"] for row in receipt["rows"]) == 1
    assert all(row["end_offset_ms"] >= row["start_offset_ms"] >= 0 for row in receipt["rows"])
    assert "secret must not enter receipt" not in text
    assert receipt["overlap"]["read_attempts_overlapping_ingest"] > 0
    assert receipt["cleanup"]["container"]["ok"]
    assert not (args.output / ".container.env").exists()
    assert receipt["source"]["runtime_tree_sha256"] and receipt["source"]["harness_sha256"]


def test_worker_setup_failure_does_not_discard_other_workers(fake_run, monkeypatch):
    import json
    from types import SimpleNamespace

    args, flags, calls = fake_run
    flags["client_error"] = True
    monkeypatch.setattr(evidence.threading, "Barrier", lambda *a, **k: SimpleNamespace(wait=lambda: None))
    assert evidence.run(args) == 1
    receipt = json.loads((args.output / "receipt.json").read_text())
    assert len(receipt["rows"]) == 4
    assert receipt["expected_attempts"] == 6
    assert len(receipt["worker_errors"]) == 1
    assert receipt["cleanup"]["container"]["ok"]


def test_receipt_write_failure_cannot_skip_cleanup(fake_run):
    args, flags, calls = fake_run
    flags["write_error"] = True
    assert evidence.run(args) == 1
    assert any(call[:3] == ("docker", "rm", "-f") for call in calls)
    assert not (args.output / ".container.env").exists()


def test_cleanup_failure_prevents_passed_receipt(fake_run):
    import json

    args, flags, calls = fake_run
    flags["cleanup_error"] = True
    assert evidence.run(args) == 1
    receipt = json.loads((args.output / "receipt.json").read_text())
    assert not receipt["cleanup"]["container"]["ok"]
    assert receipt["status"] == "failed"
    assert not (args.output / ".container.env").exists()


def test_container_must_import_the_frozen_candidate(fake_run, monkeypatch):
    import json

    args, flags, calls = fake_run
    monkeypatch.setattr(evidence, "resources", lambda name: {"source_file": "/image/agent_bom/__init__.py"})
    assert evidence.run(args) == 1
    receipt = json.loads((args.output / "receipt.json").read_text())
    assert receipt["error_type"] == "RuntimeError"
    assert receipt["rows"] == []
    assert receipt["cleanup"]["container"]["ok"]


def test_proxy_secret_never_enters_files_or_command_arguments(fake_run, monkeypatch):
    import os

    args, flags, calls = fake_run
    marker = "ephemeral-proxy-test-marker"
    monkeypatch.setattr(evidence.secrets, "token_urlsafe", lambda size: marker)
    assert evidence.run(args) == 0
    assert not flags["secret_file_at_launch"]
    assert flags["launch_env"]["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] == marker
    assert "AGENT_BOM_TRUST_PROXY_AUTH_SECRET" not in os.environ
    assert not any(marker in argument for call in calls for argument in call)
    assert all(marker.encode() not in path.read_bytes() for path in args.output.rglob("*") if path.is_file())


def test_docker_passes_private_environment_without_changing_parent(monkeypatch):
    import os
    from types import SimpleNamespace

    captured = {}

    def execute(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(stdout="container")

    monkeypatch.setattr(evidence.subprocess, "run", execute)
    private_env = {**os.environ, "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": "ephemeral-test-marker"}
    assert evidence.docker("run", "--env", "AGENT_BOM_TRUST_PROXY_AUTH_SECRET", env=private_env) == "container"
    assert captured["env"] == private_env
    assert "ephemeral-test-marker" not in captured["command"]
    assert "AGENT_BOM_TRUST_PROXY_AUTH_SECRET" not in os.environ


def test_server_diagnostics_redact_generated_and_credential_shaped_secrets():
    text = evidence.sanitized_diagnostics("failure minted-fixture-secret\npassword=private-value", "minted-fixture-secret")
    assert "failure" in text
    assert "minted-fixture-secret" not in text
    assert "private-value" not in text
