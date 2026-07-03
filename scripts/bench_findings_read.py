#!/usr/bin/env python3
"""Benchmark findings list/read latency after bulk ingest.

Usage
-----
Seed the in-process API (default, no running server required)::

    uv run python scripts/bench_findings_read.py

Larger sample with a generous CI threshold::

    uv run python scripts/bench_findings_read.py --count 10000 --p50-threshold-ms 2000

Time only the compliance-hub store ``list()`` path (no HTTP/sort)::

    uv run python scripts/bench_findings_read.py --mode store --count 10000

Against a live control plane::

    AGENT_BOM_API_TOKEN=... uv run python scripts/bench_findings_read.py \\
        --mode api --base-url http://127.0.0.1:8000 --tenant-id tenant-alpha

Exit code is non-zero when the measured p50 exceeds ``--p50-threshold-ms``.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

PROXY_SECRET = "bench-findings-read-proxy-secret-32b"


def _synthetic_findings(count: int, *, batch_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for ordinal in range(1, count + 1):
        severity = ("critical", "high", "medium", "low")[ordinal % 4]
        findings.append(
            {
                "id": f"bench:{batch_id}:{ordinal}",
                "title": f"Synthetic finding {ordinal}",
                "severity": severity,
                "cvss_score": float(ordinal % 10),
                "epss_score": float((ordinal % 100) / 100),
                "cisa_kev": ordinal % 17 == 0,
                "origin": "bulk_ingest",
                "source": "bench_findings_read",
                "batch_id": batch_id,
                "bulk_ordinal": ordinal,
            }
        )
    return findings


def _percentile_ms(values_ms: list[float], percent: float) -> float:
    if not values_ms:
        return 0.0
    ordered = sorted(values_ms)
    idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent)))
    return round(ordered[idx], 3)


def _seed_inmemory_store(count: int, *, tenant_id: str) -> str:
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store

    batch_id = f"bench-{uuid.uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    store.add(tenant_id, _synthetic_findings(count, batch_id=batch_id))
    return batch_id


def _enable_proxy_auth_env() -> None:
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET


def _proxy_headers(*, tenant_id: str) -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": "viewer",
        "X-Agent-Bom-Tenant-ID": tenant_id,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def _bench_api_inprocess(
    *,
    tenant_id: str,
    limit: int,
    samples: int,
    warmup: int,
) -> list[float]:
    from starlette.testclient import TestClient

    from agent_bom.api.server import app

    client = TestClient(app)
    headers = _proxy_headers(tenant_id=tenant_id)
    for _ in range(warmup):
        client.get("/v1/findings", params={"limit": limit, "offset": 0}, headers=headers)

    timings: list[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        response = client.get("/v1/findings", params={"limit": limit, "offset": 0}, headers=headers)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if response.status_code != 200:
            raise RuntimeError(f"GET /v1/findings failed: {response.status_code} {response.text}")
        timings.append(elapsed_ms)
    return timings


def _bench_store_list(
    *,
    tenant_id: str,
    limit: int,
    samples: int,
    warmup: int,
) -> list[float]:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    store = get_compliance_hub_store()
    for _ in range(warmup):
        rows = store.list(tenant_id)
        _ = rows[:limit]

    timings: list[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        rows = store.list(tenant_id)
        _ = rows[:limit]
        timings.append((time.perf_counter() - started) * 1000)
    return timings


def _bench_live_api(
    *,
    base_url: str,
    tenant_id: str,
    token: str,
    limit: int,
    samples: int,
    warmup: int,
    timeout: float,
    count: int,
) -> list[float]:
    _ingest_live_api(base_url=base_url, tenant_id=tenant_id, token=token, count=count, timeout=timeout)

    query = urlencode({"limit": str(limit), "offset": "0"})
    url = base_url.rstrip("/") + "/v1/findings?" + query
    headers = {
        "Accept": "application/json",
        "X-Agent-Bom-Tenant-ID": tenant_id,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _request() -> None:
        request = Request(url, headers=headers, method="GET")
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - user-supplied benchmark target
            response.read()

    for _ in range(warmup):
        _request()

    timings: list[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        _request()
        timings.append((time.perf_counter() - started) * 1000)
    return timings


def _ingest_live_api(*, base_url: str, tenant_id: str, token: str, count: int, timeout: float) -> None:
    batch_id = f"bench-{uuid.uuid4().hex}"
    chunk = 500
    findings = _synthetic_findings(count, batch_id=batch_id)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Agent-Bom-Tenant-ID": tenant_id,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for offset in range(0, len(findings), chunk):
        body = json.dumps({"source": "bench_findings_read", "findings": findings[offset : offset + chunk]}).encode("utf-8")
        request = Request(base_url.rstrip("/") + "/v1/findings/bulk", data=body, headers=headers, method="POST")
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            if response.status not in {200, 201}:
                raise RuntimeError(f"bulk ingest failed with status {response.status}")


def _run(args: argparse.Namespace) -> dict[str, Any]:
    tenant_id = args.tenant_id
    if args.mode in {"api", "store"}:
        _enable_proxy_auth_env()
        _seed_inmemory_store(args.count, tenant_id=tenant_id)

    if args.mode == "store":
        timings = _bench_store_list(tenant_id=tenant_id, limit=args.limit, samples=args.samples, warmup=args.warmup)
    elif args.mode == "api" and args.base_url:
        timings = _bench_live_api(
            base_url=args.base_url,
            tenant_id=tenant_id,
            token=args.token,
            limit=args.limit,
            samples=args.samples,
            warmup=args.warmup,
            timeout=args.timeout,
            count=args.count,
        )
    else:
        timings = _bench_api_inprocess(tenant_id=tenant_id, limit=args.limit, samples=args.samples, warmup=args.warmup)

    return {
        "mode": args.mode if not (args.mode == "api" and args.base_url) else "live_api",
        "count": args.count,
        "limit": args.limit,
        "samples": args.samples,
        "p50_ms": _percentile_ms(timings, 0.50),
        "p95_ms": _percentile_ms(timings, 0.95),
        "mean_ms": round(statistics.fmean(timings), 3) if timings else 0.0,
        "max_ms": round(max(timings), 3) if timings else 0.0,
        "threshold_ms": args.p50_threshold_ms,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=10_000, help="Synthetic findings to seed (default: 10000)")
    parser.add_argument("--limit", type=int, default=50, help="Page size for list/read (default: 50)")
    parser.add_argument("--samples", type=int, default=7, help="Timed iterations after warmup (default: 7)")
    parser.add_argument("--warmup", type=int, default=2, help="Warmup iterations (default: 2)")
    parser.add_argument(
        "--p50-threshold-ms",
        type=float,
        default=2000.0,
        help="Fail when p50 exceeds this many milliseconds (default: 2000)",
    )
    parser.add_argument(
        "--mode",
        choices=("api", "store"),
        default="api",
        help="api=GET /v1/findings (in-process TestClient unless --base-url); store=direct hub list()",
    )
    parser.add_argument("--base-url", default="", help="Live API base URL (optional; enables live HTTP mode)")
    parser.add_argument("--tenant-id", default="bench-findings-tenant", help="Tenant scope for seeded findings")
    parser.add_argument("--token", default=os.environ.get("AGENT_BOM_API_TOKEN", ""), help="Bearer token for live API mode")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout for live API mode")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary")
    args = parser.parse_args(argv)

    if args.count < 1:
        parser.error("--count must be >= 1")
    if args.limit < 1:
        parser.error("--limit must be >= 1")

    try:
        summary = _run(args)
    except (HTTPError, URLError, RuntimeError) as exc:
        print(f"bench_findings_read: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(
            "findings read bench: "
            f"mode={summary['mode']} count={summary['count']} limit={summary['limit']} "
            f"p50={summary['p50_ms']}ms p95={summary['p95_ms']}ms "
            f"threshold={summary['threshold_ms']}ms"
        )

    if summary["p50_ms"] > summary["threshold_ms"]:
        print(
            f"FAIL: p50 {summary['p50_ms']}ms exceeds threshold {summary['threshold_ms']}ms",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
