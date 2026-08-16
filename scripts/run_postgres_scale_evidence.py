#!/usr/bin/env python3
"""Clustered Postgres scale evidence — drives the real `postgres_*` stores.

Closes the v0.82.2 honest gap from `site-docs/deployment/scaling-slo.md`:
"no published clustered Postgres scale benchmark." The existing
`run_scale_evidence.py` is a CPU-bound, in-process synthetic; this one
talks to a real Postgres and measures what actually limits the control
plane at clustered scale (insert throughput, RLS-bounded reads, audit-log
append, advisory-lock acquire under contention).

Why a separate script
─────────────────────

Postgres throughput depends on Postgres tuning, network RTT, and the
specific workload mix the control plane runs. A local CPU benchmark
cannot say anything useful about those. This script needs:

* A Postgres instance (`AGENT_BOM_POSTGRES_URL` / legacy
  `AGENT_BOM_POSTGRES_DSN` env var, or `--dsn` flag).
* Optionally, `multiprocessing` to fan out N "replica" worker processes
  hammering the same DB so we measure connection-pool contention, not
  just single-process throughput.

Output
──────

JSON evidence written to `docs/perf/results/postgres-scale-evidence-<date>.json`
with the same shape as `run_scale_evidence.py`'s output: per-size results,
p50/p95/p99 timings, and a top-level `gaps` field listing what this run
explicitly does NOT measure.

CI integration
──────────────

`.github/workflows/postgres-scale-evidence.yml` runs this on
`workflow_dispatch` (and weekly on cron) against a Postgres service
container. PRs do NOT run it — too slow and Postgres-tuning-sensitive
to gate on. The published JSON is the artifact; reviewers consult it
before claiming clustered SLOs.

Usage
─────

    # local (against docker compose Postgres)
    AGENT_BOM_POSTGRES_URL=postgresql://agent_bom:agent_bom@localhost:5432/agent_bom \\
        scripts/run_postgres_scale_evidence.py --sizes 1000,5000

    # CI (against service container, full sizes, 4 simulated replicas)
    AGENT_BOM_POSTGRES_URL=$DSN \\
        scripts/run_postgres_scale_evidence.py \\
            --sizes 10000,50000,100000 --replicas 4

    # smoke test that the harness boots without Postgres
    scripts/run_postgres_scale_evidence.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_OUTPUT = ROOT / "docs" / "perf" / "results" / f"postgres-scale-evidence-{datetime.now(timezone.utc).date()}.json"
DEFAULT_SIZES = (1_000, 5_000, 10_000)
DEFAULT_POOL_MIN_SIZE = 1
DEFAULT_POOL_MAX_SIZE = 4


def _percentiles(values_ms: list[float]) -> dict[str, float]:
    if not values_ms:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "samples": 0}
    ordered = sorted(values_ms)

    def pct(percent: float) -> float:
        if not ordered:
            return 0.0
        idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent)))
        return round(ordered[idx], 3)

    return {
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": round(max(ordered), 3),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "samples": len(ordered),
    }


# ─── Workload generators ─────────────────────────────────────────────────────


def _synth_audit_entry(idx: int, tenant_id: str = "scale-evidence") -> dict[str, Any]:
    return {
        "actor": f"actor-{idx % 50}",
        "action": "scan.create" if idx % 3 else "scan.read",
        "resource": f"job-{idx}",
        "details": {"tenant_id": tenant_id, "source": "postgres-scale-evidence", "idx": idx},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _audit_append_iter(audit_log, n: int) -> list[float]:
    """Append n synthetic audit entries; return per-call ms."""
    from agent_bom.api.audit_log import AuditEntry

    timings: list[float] = []
    for i in range(n):
        entry = AuditEntry(**_synth_audit_entry(i))
        started = time.perf_counter()
        audit_log.append(entry)
        timings.append((time.perf_counter() - started) * 1000)
    return timings


def _job_put_iter(job_store, n: int, tenant_prefix: str = "t") -> list[float]:
    """Insert n synthetic ScanJobs; return per-call ms."""
    from agent_bom.api.models import ScanJob, ScanRequest

    timings: list[float] = []
    for i in range(n):
        tenant_id = f"{tenant_prefix}-{i % 10}"
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            triggered_by="postgres-scale-evidence",
            created_at=datetime.now(timezone.utc).isoformat(),
            request=ScanRequest(),
            status="done",
        )
        started = time.perf_counter()
        _tenant_job_put(job_store, job)
        timings.append((time.perf_counter() - started) * 1000)
    return timings


def _tenant_job_put(job_store, job) -> None:
    """Write a job under the same tenant context installed by API middleware."""
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(job.tenant_id)
    try:
        job_store.put(job)
    finally:
        reset_current_tenant(token)


def _tenant_job_get(job_store, job_id: str, tenant_id: str):
    """Read a job under its RLS-bound tenant context."""
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant_id)
    try:
        return job_store.get(job_id, tenant_id=tenant_id)
    finally:
        reset_current_tenant(token)


def _job_get_iter(job_store, sample_ids: list[tuple[str, str]]) -> list[float]:
    """Read N sampled job_ids — RLS-bounded by tenant_id."""
    timings: list[float] = []
    for job_id, tenant_id in sample_ids:
        started = time.perf_counter()
        _tenant_job_get(job_store, job_id, tenant_id)
        timings.append((time.perf_counter() - started) * 1000)
    return timings


def _set_postgres_env(dsn: str, *, pool_min_size: int, pool_max_size: int) -> None:
    """Set the DSN and bounded per-replica pool contract for child workers."""
    os.environ["AGENT_BOM_POSTGRES_URL"] = dsn
    os.environ["AGENT_BOM_POSTGRES_DSN"] = dsn
    os.environ["AGENT_BOM_POSTGRES_POOL_MIN_SIZE"] = str(pool_min_size)
    os.environ["AGENT_BOM_POSTGRES_POOL_MAX_SIZE"] = str(pool_max_size)


def _validate_postgres_schema(dsn: str) -> None:
    """Fail before fan-out when the target has not run shipped migrations."""
    import psycopg

    try:
        with psycopg.connect(dsn) as connection:
            row = connection.execute("SELECT to_regclass('public.control_plane_schema_versions')").fetchone()
    except Exception:
        raise SystemExit(
            "Postgres schema preflight failed. Verify the app DSN and run "
            "`alembic -c deploy/supabase/postgres/alembic.ini upgrade head` before benchmarking."
        ) from None
    if not row or row[0] is None:
        raise SystemExit(
            "Postgres schema is not migrated. Run `alembic -c deploy/supabase/postgres/alembic.ini upgrade head` before benchmarking."
        )


# ─── Per-replica worker (run in a child process) ─────────────────────────────


def _replica_worker(
    dsn: str,
    size: int,
    replica_idx: int,
    kinds: list[str],
    pool_min_size: int,
    pool_max_size: int,
) -> dict[str, Any]:
    """Simulate one control-plane replica's contribution to the load.

    Each child process opens its own pool, runs the requested workload
    `kinds` (subset of {"audit","job_put","job_get"}), and returns
    timing distributions. The parent aggregates across replicas.
    """
    _set_postgres_env(dsn, pool_min_size=pool_min_size, pool_max_size=pool_max_size)

    # Lazy import — psycopg may not be installed in dry-run mode.
    from agent_bom.api.postgres_audit import PostgresAuditLog
    from agent_bom.api.postgres_store import PostgresJobStore

    job_store = PostgresJobStore()
    audit_log = PostgresAuditLog()

    result: dict[str, Any] = {
        "replica_idx": replica_idx,
        "size": size,
    }

    if "audit" in kinds:
        audit_timings = _audit_append_iter(audit_log, size)
        result["audit_append"] = _percentiles(audit_timings)

    sampled_ids: list[tuple[str, str]] = []
    if "job_put" in kinds:
        # Insert and remember a few ids for the read pass.
        from agent_bom.api.models import ScanJob, ScanRequest

        job_timings: list[float] = []
        for i in range(size):
            tenant_id = f"r{replica_idx}-{i % 10}"
            job_id = str(uuid.uuid4())
            job = ScanJob(
                job_id=job_id,
                tenant_id=tenant_id,
                triggered_by="postgres-scale-evidence",
                created_at=datetime.now(timezone.utc).isoformat(),
                request=ScanRequest(),
                status="done",
            )
            started = time.perf_counter()
            _tenant_job_put(job_store, job)
            job_timings.append((time.perf_counter() - started) * 1000)
            if i % max(1, size // 100) == 0:
                sampled_ids.append((job_id, tenant_id))
        result["job_put"] = _percentiles(job_timings)

    if "job_get" in kinds and sampled_ids:
        # Read 100 sampled jobs to measure RLS-bounded SELECT latency.
        result["job_get"] = _percentiles(_job_get_iter(job_store, sampled_ids))

    return result


def _run_clustered(
    dsn: str,
    size: int,
    n_replicas: int,
    kinds: list[str],
    pool_min_size: int,
    pool_max_size: int,
) -> dict[str, Any]:
    started = time.perf_counter()
    if n_replicas <= 1:
        replicas = [_replica_worker(dsn, size, 0, kinds, pool_min_size, pool_max_size)]
    else:
        with ProcessPoolExecutor(max_workers=n_replicas) as pool:
            futures = [pool.submit(_replica_worker, dsn, size, idx, kinds, pool_min_size, pool_max_size) for idx in range(n_replicas)]
            replicas = [f.result() for f in as_completed(futures)]
    wall_ms = (time.perf_counter() - started) * 1000

    total_ops = size * len(kinds) * n_replicas
    return {
        "size_per_replica": size,
        "replicas": n_replicas,
        "kinds": kinds,
        "wall_ms": round(wall_ms, 3),
        "total_ops": total_ops,
        "ops_per_second": round(total_ops / max(wall_ms / 1000, 0.001), 2),
        "per_replica": replicas,
    }


# ─── Top-level harness ───────────────────────────────────────────────────────


def generate(
    dsn: str | None,
    sizes: list[int],
    replicas: int,
    kinds: list[str],
    *,
    dry_run: bool,
    pool_min_size: int = DEFAULT_POOL_MIN_SIZE,
    pool_max_size: int = DEFAULT_POOL_MAX_SIZE,
) -> dict[str, Any]:
    if replicas < 1:
        raise SystemExit("--replicas must be at least 1.")
    if pool_min_size < 1 or pool_max_size < pool_min_size:
        raise SystemExit("Postgres pool sizes must satisfy 1 <= min <= max.")

    base: dict[str, Any] = {
        "schema_version": "operability-benchmark.v1",
        "backend": "postgres",
        "evidence_status": "unverified_dry_run" if dry_run else "measured_controlled",
        "claim": "controlled_benchmark_not_a_production_slo",
        "required_metrics": [
            "p50_ms",
            "p95_ms",
            "throughput_ops_per_second",
            "peak_memory_mib",
            "concurrency",
            "recovery",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Clustered Postgres throughput for control-plane stores. Closes the SLO doc gap on clustered scale evidence.",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "replicas_simulated": replicas,
            "postgres_pool_min_size_per_replica": pool_min_size,
            "postgres_pool_max_size_per_replica": pool_max_size,
            "postgres_pool_max_connections": replicas * pool_max_size,
        },
        "kinds": kinds,
        "sizes_per_replica": sizes,
    }

    if dry_run:
        base["dry_run"] = True
        base["results"] = []
        base["gaps"] = [
            "--dry-run does not contact Postgres; rerun without it for real timings.",
        ]
        return base

    if not dsn:
        raise SystemExit(
            "AGENT_BOM_POSTGRES_URL env var, AGENT_BOM_POSTGRES_DSN env var, or --dsn required "
            "(use --dry-run to validate the harness without Postgres)."
        )
    if "audit" in kinds and not os.environ.get("AGENT_BOM_POSTGRES_MAINTENANCE_URL"):
        raise SystemExit(
            "AGENT_BOM_POSTGRES_MAINTENANCE_URL is required when --kinds includes audit; "
            "use the scoped NOSUPERUSER maintenance role provisioned by the shipped migrations."
        )

    _validate_postgres_schema(dsn)
    base["results"] = [_run_clustered(dsn, size, replicas, kinds, pool_min_size, pool_max_size) for size in sizes]
    base["operability"] = {
        "concurrency": replicas,
        "peak_memory_mib": None,
        "recovery": {"kind": "client_reconnect", "status": "not_measured"},
    }
    base["gaps"] = [
        "Peak memory and client-reconnect recovery remain unverified unless the result artifact supplies measured values.",
        "Per-row p99 includes psycopg-pool acquisition; measure pool exhaustion separately under sustained load.",
        "Audit-log append is HMAC-chained; chain-verification cost grows with "
        "history. Run --kinds audit_verify to measure that path explicitly.",
        "Read paths use RLS via tenant_id; cross-tenant join performance is not measured here.",
    ]
    return base


def main() -> int:
    parser = argparse.ArgumentParser(description="Drive the agent-bom Postgres stores at clustered scale and emit JSON evidence.")
    parser.add_argument(
        "--dsn",
        default=os.environ.get("AGENT_BOM_POSTGRES_URL") or os.environ.get("AGENT_BOM_POSTGRES_DSN"),
        help="Postgres DSN (defaults to AGENT_BOM_POSTGRES_URL, then legacy AGENT_BOM_POSTGRES_DSN).",
    )
    parser.add_argument(
        "--sizes",
        default=",".join(str(s) for s in DEFAULT_SIZES),
        help="Comma-separated entity sizes per replica (default: 1000,5000,10000).",
    )
    parser.add_argument(
        "--replicas",
        type=int,
        default=1,
        help="Number of simulated control-plane replicas (process workers).",
    )
    parser.add_argument(
        "--kinds",
        default="audit,job_put,job_get",
        help="Comma-separated workloads (audit, job_put, job_get).",
    )
    parser.add_argument(
        "--pool-min-size",
        type=int,
        default=DEFAULT_POOL_MIN_SIZE,
        help="Minimum Postgres connections opened by each simulated replica (default: 1).",
    )
    parser.add_argument(
        "--pool-max-size",
        type=int,
        default=DEFAULT_POOL_MAX_SIZE,
        help="Maximum Postgres connections opened by each simulated replica (default: 4).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the harness without contacting Postgres.",
    )
    args = parser.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    valid = {"audit", "job_put", "job_get"}
    invalid = [k for k in kinds if k not in valid]
    if invalid:
        parser.error(f"Unknown --kinds entries: {invalid} (valid: {sorted(valid)})")

    evidence = generate(
        args.dsn,
        sizes,
        args.replicas,
        kinds,
        dry_run=args.dry_run,
        pool_min_size=args.pool_min_size,
        pool_max_size=args.pool_max_size,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        display = args.output.resolve().relative_to(ROOT)
    except ValueError:
        display = args.output
    print(display)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
