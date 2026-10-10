#!/usr/bin/env python3
"""Bounded concurrent graph write/read qualification against a task-owned store.

Uses explicit --sqlite or AGENT_BOM_POSTGRES_URL credentials. Run migrations
before PostgreSQL qualification. Never point this at a production database:
uniquely named qualification tenants and snapshots are retained as evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import queue
import sqlite3
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from uuid import uuid4

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_graph import PostgresGraphStore
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode


@contextmanager
def tenant_scope(tenant):
    token = set_current_tenant(tenant)
    try:
        yield
    finally:
        reset_current_tenant(token)


def write(store, tenant, size, sequence):
    with tenant_scope(tenant):
        store.save_graph_streaming(
            tenant_id=tenant,
            scan_id="qualification",
            write_generation="reused-writer",
            nodes=(
                UnifiedNode(
                    id=f"asset:{i}",
                    entity_type=EntityType.AGENT if i == 0 else EntityType.CLOUD_RESOURCE,
                    label=f"{tenant}:{sequence}:{i}",
                    data_sources=["qualification_fixture"],
                )
                for i in range(size)
            ),
            edges=(UnifiedEdge(source="asset:0", target=f"asset:{i}", relationship=RelationshipType.USES) for i in range(1, size)),
        )


def content_digest(graph):
    """Deterministic evidence receipt, not a signed or independent checkpoint."""
    payload = graph.to_dict()
    payload["nodes"] = sorted(payload["nodes"], key=lambda node: node["id"])
    payload["edges"] = sorted(payload["edges"], key=lambda edge: json.dumps(edge, sort_keys=True))
    payload["attack_paths"] = sorted(payload.get("attack_paths", []), key=lambda item: json.dumps(item, sort_keys=True))
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def checkpoint_for(store, tenants, size):
    checkpoint = {}
    for tenant in tenants:
        with tenant_scope(tenant):
            checkpoint[tenant] = {
                "revision": store.snapshot_identity(tenant_id=tenant, scan_id="qualification", for_paging=True)[1],
                "nodes": size,
                "content_sha256": content_digest(store.load_graph(tenant_id=tenant, scan_id="qualification")),
            }
    return checkpoint


def verify_checkpoint(store, checkpoint):
    for tenant, expected in checkpoint.items():
        with tenant_scope(tenant):
            assert store.snapshot_identity(tenant_id=tenant, scan_id="qualification", for_paging=True)[1] == expected["revision"]
            graph = store.load_graph(tenant_id=tenant, scan_id="qualification")
            assert len(graph.nodes) == expected["nodes"] and len(graph.edges) == expected["nodes"] - 1
            assert all(n.label.startswith(tenant + ":") for n in graph.nodes.values())
            if expected.get("content_sha256"):
                assert content_digest(graph) == expected["content_sha256"], "Persisted graph content changed"
    return {"verified_tenants": len(checkpoint), "status": "passed"}


def qualify(store, seconds, size):
    tenants = ["qualification-" + uuid4().hex for _ in range(2)]
    for tenant in tenants:
        write(store, tenant, size, 0)
    stop = Event()
    started = time.monotonic()

    with ThreadPoolExecutor(max_workers=4) as workers:
        futures = [workers.submit(run_worker, store, tenant, size, kind, stop) for tenant in tenants for kind in ("writer", "reader")]
        deadline = started + seconds
        while time.monotonic() < deadline and not any(future.done() for future in futures):
            stop.wait(min(0.25, max(0, deadline - time.monotonic())))
        early = any(future.done() for future in futures)
        stop.set()
        outcomes = [future.result() for future in futures]
    if early or any("error_type" in outcome for outcome in outcomes):
        raise QualificationError(outcomes)
    checkpoint = checkpoint_for(store, tenants, size)
    verify_checkpoint(store, checkpoint)
    return {
        "duration_s": round(time.monotonic() - started, 3),
        "nodes_per_snapshot": size,
        "tenants": len(tenants),
        "workers": 4,
        "executor": "threads",
        "outcomes": outcomes,
        "checkpoint": checkpoint,
        "scope": "bounded synthetic concurrency; not a production capacity or long soak claim",
    }


@contextmanager
def open_store(sqlite, pool_size=2):
    pool = None if sqlite else _new_application_pool(min_size=1, max_size=pool_size)
    try:
        yield SQLiteGraphStore(sqlite) if sqlite else PostgresGraphStore(pool=pool)
    finally:
        if pool:
            pool.close()


def error_details(exc):
    """Allowlisted driver metadata only; never persist exception messages."""
    details = {"error_type": type(exc).__name__}
    frames = []
    trace = exc.__traceback__
    while trace is not None:
        module = trace.tb_frame.f_globals.get("__name__", "")
        if isinstance(module, str) and module.startswith("agent_bom."):
            frames.append({"module": module, "function": trace.tb_frame.f_code.co_name, "line": trace.tb_lineno})
        trace = trace.tb_next
    if frames:
        details["frames"] = frames[-8:]
    if isinstance(exc, sqlite3.Error):
        code = getattr(exc, "sqlite_errorcode", None)
        name = getattr(exc, "sqlite_errorname", None)
        if type(code) is int:
            details["sqlite_errorcode"] = code
            if isinstance(name, str) and name.startswith("SQLITE_") and getattr(sqlite3, name, None) == code:
                details["sqlite_errorname"] = name
    return details


def run_worker(store, tenant, size, kind, stop):
    """Use the same content, revision and failure checks in both executors."""
    began = time.monotonic()
    result = {
        "kind": kind,
        "pid": os.getpid(),
        "operations": 0,
        "completed_read_pairs": 0,
        "generation_restarts": 0,
        "max_operation_ms": 0.0,
    }
    stage = "start"
    revisions = set()
    read_samples = []
    operation_samples = []
    progress_by_second = {}
    try:
        with tenant_scope(tenant):
            while not stop.is_set():
                operation_started = time.monotonic()
                if kind == "writer":
                    stage = "write"
                    write(store, tenant, size, result["operations"] + 1)
                    stage = "read_revision"
                    revision = store.snapshot_identity(tenant_id=tenant, scan_id="qualification", for_paging=True)[1]
                    stage = "validate_revision"
                    assert revision and revision not in revisions, "Repeated committed revision"
                    revisions.add(revision)
                else:
                    try:
                        stage = "read_first_page"
                        first = store.incident_edges_page(tenant_id=tenant, scan_id="qualification", node_id="asset:0", limit=24)
                        assert first and first["next_cursor"], "Expected non-empty paged evidence"
                        stage = "read_next_page"
                        second = store.incident_edges_page(
                            tenant_id=tenant,
                            scan_id="qualification",
                            node_id="asset:0",
                            limit=24,
                            cursor=first["next_cursor"],
                            snapshot_generation=first["snapshot_generation"],
                        )
                        stage = "validate_pages"
                        assert second and second["snapshot_generation"] == first["snapshot_generation"], "Mixed revisions"
                        nodes = [*first["nodes"], *second["nodes"]]
                        assert all(n.label.startswith(tenant + ":") for n in nodes), "Tenant boundary failed"
                        assert len({n.label.rsplit(":", 1)[0] for n in nodes}) == 1, "Mixed evidence content"
                        assert not ({e.id for e in first["edges"]} & {e.id for e in second["edges"]}), "Repeated page edges"
                        result["completed_read_pairs"] += 1
                        read_ms = (time.monotonic() - operation_started) * 1000
                        if len(read_samples) < 512:
                            payload = [
                                {
                                    key: [item.to_dict() for item in value]
                                    if key in {"nodes", "edges"}
                                    else value.to_dict()
                                    if key == "node"
                                    else value
                                    for key, value in page.items()
                                }
                                for page in (first, second)
                            ]
                            payload_bytes = len(json.dumps(payload, separators=(",", ":")).encode())
                            read_samples.append((read_ms, payload_bytes))
                    except ValueError as exc:
                        if "snapshot" not in str(exc).lower():
                            raise
                        result["generation_restarts"] += 1
                operation_samples.append((time.monotonic() - operation_started) * 1000)
                second = int(time.monotonic() - began)
                progress_by_second[second] = progress_by_second.get(second, 0) + 1
                if len(operation_samples) > 1_000_000:
                    raise RuntimeError("Qualification sample bound exceeded")
                result["operations"] += 1
                result["max_operation_ms"] = max(result["max_operation_ms"], (time.monotonic() - operation_started) * 1000)
            stage = "shutdown"
            assert result["operations"] > 0, "Worker performed no operations"
    except Exception as exc:  # Persist structured diagnostics, never raw provider text.
        result.update(error_details(exc), stage=stage)
        stop.set()
    result["elapsed_s"] = round(time.monotonic() - began, 3)
    result["max_operation_ms"] = round(result["max_operation_ms"], 3)
    ordered_operations = sorted(operation_samples)
    result["operation_measurements"] = {
        "samples": len(ordered_operations),
        "sampling": "all completed operations including generation restarts and serialization; bounded to 1000000",
        "p50_ms": statistics.median(ordered_operations) if ordered_operations else None,
        "p95_ms": ordered_operations[min(len(ordered_operations) - 1, int(len(ordered_operations) * 0.95))] if ordered_operations else None,
        "max_ms": max(ordered_operations) if ordered_operations else None,
        "progress_by_second": progress_by_second,
    }
    if kind == "reader":
        ordered = sorted(value[0] for value in read_samples)
        sizes = [value[1] for value in read_samples]
        result["read_measurements"] = {
            "samples": len(ordered),
            "sample_limit": 512,
            "sampling": "first completed read pairs; latency excludes payload serialization",
            "p50_ms": round(statistics.median(ordered), 3) if ordered else None,
            "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3) if ordered else None,
            "mean_payload_bytes": round(statistics.fmean(sizes), 1) if sizes else None,
            "max_payload_bytes": max(sizes) if sizes else None,
            "representation": "two incident-edge pages serialized as compact JSON; not HTTP wire bytes",
        }
    # Retain the original thread receipt counters for existing consumers.
    result["writes" if kind == "writer" else "read_pairs"] = result["operations"] if kind == "writer" else result["completed_read_pairs"]
    return result


def process_worker(sqlite, tenant, size, kind, ready, start, stop, outcomes):
    """Spawn creates each connection pool in its owning process, never by fork."""
    stage = "open_store"
    try:
        with open_store(sqlite) as store:
            ready.put({"kind": kind, "status": "ready"})
            stage = "start"
            if not start.wait(30):
                raise RuntimeError("Worker start deadline exceeded")
            outcomes.put(run_worker(store, tenant, size, kind, stop))
    except Exception as exc:  # Worker boundary: persist only allowlisted diagnostics.
        outcomes.put({"kind": kind, "pid": os.getpid(), "stage": stage, **error_details(exc)})
        if stage == "open_store":
            ready.put({"kind": kind, "status": "failed"})
        stop.set()


class QualificationError(RuntimeError):
    def __init__(self, outcomes):
        super().__init__("Qualification worker failed")
        self.outcomes = outcomes


def qualify_processes(store, sqlite, seconds, size):
    tenants = ["qualification-" + uuid4().hex for _ in range(2)]
    for tenant in tenants:
        write(store, tenant, size, 0)
    context = multiprocessing.get_context("spawn")
    ready, outcomes = context.Queue(), context.Queue()
    start, stop = context.Event(), context.Event()
    workers = [
        context.Process(target=process_worker, args=(sqlite, tenant, size, kind, ready, start, stop, outcomes))
        for tenant in tenants
        for kind in ("writer", "reader")
    ]
    results = []
    try:
        for worker in workers:
            worker.start()
        for _ in workers:
            if ready.get(timeout=30)["status"] == "failed":
                raise QualificationError([outcomes.get(timeout=5)])
        began = time.monotonic()
        start.set()
        # A worker returning before the deadline is a failure, even without an exception.
        try:
            results.append(outcomes.get(timeout=seconds))
        except queue.Empty:
            pass
        stop.set()
        early = bool(results)
        for _ in range(len(workers) - len(results)):
            try:
                results.append(outcomes.get(timeout=30))
            except queue.Empty:
                raise QualificationError(results + [{"error_type": "WorkerResultTimeout"}]) from None
        if early or any("error_type" in result for result in results):
            raise QualificationError(results)
        assert len({result["pid"] for result in results}) == 4, "Workers were not independent"
        for worker in workers:
            worker.join(timeout=10)
            if worker.is_alive() or worker.exitcode != 0:
                raise QualificationError(results + [{"pid": worker.pid, "error_type": "WorkerShutdownError"}])
        checkpoint = checkpoint_for(store, tenants, size)
        verify_checkpoint(store, checkpoint)
        return {
            "duration_s": round(time.monotonic() - began, 3),
            "nodes_per_snapshot": size,
            "tenants": len(tenants),
            "workers": 4,
            "executor": "processes",
            "outcomes": results,
            "checkpoint": checkpoint,
            "scope": "bounded synthetic concurrency; not a production capacity or long soak claim",
        }
    finally:
        stop.set()
        start.set()
        for worker in workers:
            if worker.pid is not None:
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=5)
        ready.close()
        outcomes.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", type=Path)
    parser.add_argument("--executor", choices=("threads", "processes"), default="threads")
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--nodes", type=int, default=1000)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify-checkpoint", type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error("Qualification requires assertions; do not use optimized Python")
    if args.seconds <= 0 or args.nodes < 50:
        parser.error("seconds must be positive and nodes must be at least 50")
    # Open exclusively before running: receipts must not silently replace previous evidence.
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        stage = "open_store"
        try:
            with open_store(args.sqlite, pool_size=8) as store:
                stage = "verify_checkpoint" if args.verify_checkpoint else "qualify"
                if args.verify_checkpoint:
                    result = verify_checkpoint(store, json.loads(args.verify_checkpoint.read_text())["checkpoint"])
                elif args.executor == "processes":
                    result = qualify_processes(store, args.sqlite, args.seconds, args.nodes)
                else:
                    result = qualify(store, args.seconds, args.nodes)
            result["status"] = "passed"
        except Exception as exc:  # Qualification boundary: persist failure without connection strings or credentials.
            result = {"status": "failed", "stage": stage, **error_details(exc), "outcomes": getattr(exc, "outcomes", [])}
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "checkpoint"}))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
