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

    def writer(tenant):
        revisions = set()
        count = 0
        while not stop.is_set():
            count += 1
            write(store, tenant, size, count)
            with tenant_scope(tenant):
                revision = store.snapshot_identity(tenant_id=tenant, scan_id="qualification", for_paging=True)[1]
            assert revision and revision not in revisions
            revisions.add(revision)
        return {"writes": count}

    def reader(tenant):
        reads, restarts = 0, 0
        with tenant_scope(tenant):
            while not stop.is_set():
                first = store.incident_edges_page(tenant_id=tenant, scan_id="qualification", node_id="asset:0", limit=24)
                assert first and all(n.label.startswith(tenant + ":") for n in first["nodes"])
                try:
                    second = store.incident_edges_page(
                        tenant_id=tenant,
                        scan_id="qualification",
                        node_id="asset:0",
                        limit=24,
                        cursor=first["next_cursor"],
                        snapshot_generation=first["snapshot_generation"],
                    )
                    assert second and second["snapshot_generation"] == first["snapshot_generation"]
                    assert all(n.label.startswith(tenant + ":") for n in second["nodes"])
                except ValueError as exc:
                    # A changed snapshot must refuse continuation, never mix it.
                    assert "snapshot" in str(exc).lower()
                    restarts += 1
                reads += 1
        return {"read_pairs": reads, "generation_restarts": restarts}

    with ThreadPoolExecutor(max_workers=4) as workers:
        futures = [workers.submit(fn, tenant) for tenant in tenants for fn in (writer, reader)]
        try:
            deadline = started + seconds
            while time.monotonic() < deadline:
                for future in futures:
                    if future.done():
                        future.result()
                        raise AssertionError("qualification worker stopped early")
                stop.wait(min(0.25, max(0, deadline - time.monotonic())))
        finally:
            stop.set()
        outcomes = [future.result() for future in futures]
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


def process_worker(sqlite, tenant, size, kind, ready, start, stop, outcomes):
    """Spawn creates each connection pool in its owning process, never by fork."""
    try:
        with open_store(sqlite) as store, tenant_scope(tenant):
            ready.put(kind)
            if not start.wait(30):
                raise RuntimeError("Worker start deadline exceeded")
            operations = restarts = completed_reads = 0
            revisions = set()
            max_latency_ms = 0.0
            while not stop.is_set():
                began = time.monotonic()
                if kind == "writer":
                    write(store, tenant, size, operations + 1)
                    revision = store.snapshot_identity(tenant_id=tenant, scan_id="qualification", for_paging=True)[1]
                    assert revision and revision not in revisions, "Repeated committed revision"
                    revisions.add(revision)
                else:
                    try:
                        first = store.incident_edges_page(tenant_id=tenant, scan_id="qualification", node_id="asset:0", limit=24)
                        assert first and first["next_cursor"], "Expected non-empty paged evidence"
                        assert all(n.label.startswith(tenant + ":") for n in first["nodes"]), "Tenant boundary failed"
                        second = store.incident_edges_page(
                            tenant_id=tenant,
                            scan_id="qualification",
                            node_id="asset:0",
                            limit=24,
                            cursor=first["next_cursor"],
                            snapshot_generation=first["snapshot_generation"],
                        )
                        assert second and second["snapshot_generation"] == first["snapshot_generation"], "Mixed revisions"
                        assert all(n.label.startswith(tenant + ":") for n in second["nodes"]), "Tenant boundary failed"
                        assert len({n.label.rsplit(":", 1)[0] for n in [*first["nodes"], *second["nodes"]]}) == 1, "Mixed evidence content"
                        assert not ({e.id for e in first["edges"]} & {e.id for e in second["edges"]}), "Repeated page edges"
                        completed_reads += 1
                    except ValueError as exc:
                        # Includes replacement during first-page hydration.
                        if "snapshot" not in str(exc).lower():
                            raise
                        restarts += 1
                operations += 1
                max_latency_ms = max(max_latency_ms, (time.monotonic() - began) * 1000)
            assert operations > 0, "Worker performed no operations"
            outcomes.put(
                {
                    "kind": kind,
                    "pid": os.getpid(),
                    "operations": operations,
                    "completed_read_pairs": completed_reads,
                    "generation_restarts": restarts,
                    "max_operation_ms": round(max_latency_ms, 3),
                }
            )
    except Exception as exc:  # Worker boundary: report only the error class, never credentials or raw provider text.
        outcomes.put({"kind": kind, "pid": os.getpid(), "error_type": type(exc).__name__})


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
            ready.get(timeout=30)
        began = time.monotonic()
        start.set()
        # A worker returning before the deadline is a failure, even without an exception.
        try:
            results.append(outcomes.get(timeout=seconds))
            raise QualificationError(results)
        except queue.Empty:
            pass
        stop.set()
        for _ in workers:
            results.append(outcomes.get(timeout=30))
        if any("error_type" in result for result in results):
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
        try:
            with open_store(args.sqlite, pool_size=8) as store:
                if args.verify_checkpoint:
                    result = verify_checkpoint(store, json.loads(args.verify_checkpoint.read_text())["checkpoint"])
                elif args.executor == "processes":
                    result = qualify_processes(store, args.sqlite, args.seconds, args.nodes)
                else:
                    result = qualify(store, args.seconds, args.nodes)
            result["status"] = "passed"
        except Exception as exc:  # Qualification boundary: persist failure without connection strings or credentials.
            result = {"status": "failed", "error_type": type(exc).__name__, "outcomes": getattr(exc, "outcomes", [])}
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "checkpoint"}))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
