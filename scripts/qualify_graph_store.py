#!/usr/bin/env python3
"""Bounded concurrent graph write/read qualification against a task-owned store.

Uses explicit --sqlite or AGENT_BOM_POSTGRES_URL credentials. Run migrations
before PostgreSQL qualification. Never point this at a production database:
uniquely named qualification tenants and snapshots are retained as evidence.
"""

from __future__ import annotations

import argparse
import json
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


def verify_checkpoint(store, checkpoint):
    for tenant, expected in checkpoint.items():
        with tenant_scope(tenant):
            assert store.snapshot_identity(tenant_id=tenant, scan_id="qualification", for_paging=True)[1] == expected["revision"]
            graph = store.load_graph(tenant_id=tenant, scan_id="qualification")
            assert len(graph.nodes) == expected["nodes"] and len(graph.edges) == expected["nodes"] - 1
            assert all(n.label.startswith(tenant + ":") for n in graph.nodes.values())
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
    checkpoint = {}
    for tenant in tenants:
        with tenant_scope(tenant):
            checkpoint[tenant] = {
                "revision": store.snapshot_identity(tenant_id=tenant, scan_id="qualification", for_paging=True)[1],
                "nodes": size,
            }
    verify_checkpoint(store, checkpoint)
    return {
        "duration_s": round(time.monotonic() - started, 3),
        "nodes_per_snapshot": size,
        "tenants": len(tenants),
        "workers": 4,
        "outcomes": outcomes,
        "checkpoint": checkpoint,
        "scope": "bounded synthetic concurrency; not a production capacity or long soak claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", type=Path)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--nodes", type=int, default=1000)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify-checkpoint", type=Path)
    args = parser.parse_args()
    if args.seconds <= 0 or args.nodes < 50:
        parser.error("seconds must be positive and nodes must be at least 50")
    pool = None if args.sqlite else _new_application_pool(min_size=1, max_size=8)
    try:
        store = SQLiteGraphStore(args.sqlite) if args.sqlite else PostgresGraphStore(pool=pool)
        result = (
            verify_checkpoint(store, json.loads(args.verify_checkpoint.read_text())["checkpoint"])
            if args.verify_checkpoint
            else qualify(store, args.seconds, args.nodes)
        )
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({k: v for k, v in result.items() if k != "checkpoint"}))
    finally:
        if pool:
            pool.close()


if __name__ == "__main__":
    main()
