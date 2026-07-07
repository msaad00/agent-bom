#!/usr/bin/env python3
"""Postgres/EKS scale bench for agent-bom control-plane findings ingest + read paths.

Stdlib-only — no pip installs required on the runner host.

Environment:
  AGENT_BOM_URL          Base URL (default http://127.0.0.1:8422)
  AGENT_BOM_API_KEY      Bearer token with ingest + read scope

Examples:
  TARGET=1000000 BATCH=1000 python3 scripts/bench/agent_bom_scale_bench.py
  INGEST_CONC=8 TARGET=200000 python3 scripts/bench/agent_bom_scale_bench.py
  PHASES=read TARGET=0 python3 scripts/bench/agent_bom_scale_bench.py
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_BATCH = int(os.environ.get("BATCH", "1000"))
DEFAULT_TARGET = int(os.environ.get("TARGET", "20000"))
DEFAULT_INGEST_CONC = int(os.environ.get("INGEST_CONC", "1"))
DEFAULT_READ_PAGES = int(os.environ.get("READ_PAGES", "15"))
DEFAULT_PAGE_LIMIT = int(os.environ.get("PAGE_LIMIT", "500"))
PHASES = {part.strip().lower() for part in os.environ.get("PHASES", "ingest,read,idempotency,health").split(",") if part.strip()}
REGRESSION_RATIO = float(os.environ.get("REGRESSION_RATIO", "1.5"))


@dataclass
class BenchResult:
    name: str
    ok: bool
    detail: str
    samples_ms: list[float] = field(default_factory=list)


class Client:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base = base_url.rstrip("/")
        self.api_key = api_key

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any], float]:
        url = f"{self.base}{path}"
        payload = None
        req_headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)
        if body is not None:
            payload = json.dumps(body).encode()
            req_headers["Content-Type"] = "application/json"
        req = Request(url, data=payload, headers=req_headers, method=method)
        started = time.perf_counter()
        try:
            with urlopen(req, timeout=120) as resp:  # nosec B310 — operator-controlled base URL
                raw = resp.read().decode()
                elapsed_ms = (time.perf_counter() - started) * 1000
                return resp.status, json.loads(raw) if raw else {}, elapsed_ms
        except HTTPError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            raw = exc.read().decode(errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"detail": raw[:500]}
            return exc.code, parsed, elapsed_ms
        except URLError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000
            return 0, {"detail": str(exc.reason)}, elapsed_ms


def _finding(idx: int) -> dict[str, Any]:
    return {
        "id": f"scale-bench:{idx}",
        "title": f"Scale bench finding {idx}",
        "severity": "medium",
        "effective_reach_score": float(idx % 100),
        "cvss_score": float((idx % 10) + 1),
        "evidence": {"package_name": "bench-pkg", "package_version": "1.0.0", "ecosystem": "pypi"},
    }


def _batch(start: int, size: int) -> list[dict[str, Any]]:
    return [_finding(start + offset) for offset in range(size)]


def _ingest_batch(client: Client, start: int, size: int, idem_key: str | None = None) -> tuple[float, dict[str, Any]]:
    headers = {"Idempotency-Key": idem_key} if idem_key else None
    status, body, elapsed_ms = client.request(
        "POST",
        "/v1/findings/bulk",
        body={"source": "scale-bench", "findings": _batch(start, size)},
        headers=headers,
    )
    if status != 201:
        raise RuntimeError(f"ingest failed ({status}): {body}")
    return elapsed_ms, body


def run_ingest(client: Client, target: int, batch: int, concurrency: int) -> list[BenchResult]:
    results: list[BenchResult] = []
    if target <= 0:
        return results

    latencies: list[float] = []
    started = time.perf_counter()
    batches = [(idx, min(batch, target - idx)) for idx in range(0, target, batch)]

    def _worker(item: tuple[int, int]) -> float:
        start, size = item
        elapsed, _body = _ingest_batch(client, start, size)
        return elapsed

    if concurrency <= 1:
        for item in batches:
            latencies.append(_worker(item))
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(_worker, item) for item in batches]
            for future in as_completed(futures):
                latencies.append(future.result())

    total_s = time.perf_counter() - started
    first10 = latencies[:10]
    last10 = latencies[-10:] if len(latencies) >= 10 else latencies
    first_mean = statistics.mean(first10) if first10 else 0.0
    last_mean = statistics.mean(last10) if last10 else 0.0
    ratio = (last_mean / first_mean) if first_mean else 1.0
    ok = ratio < REGRESSION_RATIO
    results.append(
        BenchResult(
            name="ingest_flatness",
            ok=ok,
            detail=(
                f"ingested {target} findings in {len(latencies)} batches over {total_s:.1f}s; "
                f"first10_mean={first_mean:.1f}ms last10_mean={last_mean:.1f}ms ratio={ratio:.2f}"
            ),
            samples_ms=latencies,
        )
    )
    return results


def run_idempotency(client: Client, batch: int) -> BenchResult:
    key = f"scale-bench-idem-{uuid.uuid4()}"
    _ingest_batch(client, 0, batch, idem_key=key)
    _, replay_body = _ingest_batch(client, 0, batch, idem_key=key)
    status, list_body, _ = client.request("GET", "/v1/findings?limit=1")
    total = list_body.get("total") if status == 200 else None
    ok = replay_body.get("idempotent_replay") is True and total == batch
    return BenchResult(
        name="idempotency",
        ok=ok,
        detail=f"replay={replay_body.get('idempotent_replay')} tenant_total={total} expected={batch}",
    )


def run_reads(client: Client, pages: int, limit: int) -> list[BenchResult]:
    results: list[BenchResult] = []
    seen: set[str] = set()
    cursor: str | None = None
    latencies: list[float] = []

    for page_idx in range(pages):
        path = f"/v1/findings?limit={limit}&sort=effective_reach"
        if cursor:
            path += f"&cursor={cursor}"
        status, body, elapsed_ms = client.request("GET", path)
        latencies.append(elapsed_ms)
        if status != 200:
            results.append(BenchResult("keyset_walk", False, f"page {page_idx} failed: {body}"))
            return results
        for row in body.get("findings", []):
            fid = str(row.get("id") or row.get("finding_id") or row.get("canonical_id") or "")
            if fid in seen:
                results.append(BenchResult("keyset_walk", False, f"duplicate id on page {page_idx}: {fid}"))
                return results
            if fid:
                seen.add(fid)
        cursor = body.get("next_cursor")
        if not cursor:
            break

    exact_status, exact_body, exact_ms = client.request("GET", "/v1/findings?limit=1&offset=0")
    approx_status, approx_body, approx_ms = client.request("GET", "/v1/findings?limit=1&offset=0&approximate_total=true")
    count_ok = exact_status == 200 and approx_status == 200
    results.append(
        BenchResult(
            name="keyset_walk",
            ok=True,
            detail=f"walked {len(latencies)} pages, {len(seen)} unique ids, mean={statistics.mean(latencies):.1f}ms",
            samples_ms=latencies,
        )
    )
    results.append(
        BenchResult(
            name="first_page_count",
            ok=count_ok,
            detail=(
                f"exact_total={exact_body.get('total')} exact_ms={exact_ms:.1f} "
                f"approx_total={approx_body.get('total')} approx_ms={approx_ms:.1f} "
                f"approx_flag={approx_body.get('total_approximate')}"
            ),
        )
    )
    return results


def run_health(client: Client) -> BenchResult:
    status, body, elapsed_ms = client.request("GET", "/health")
    ok = status == 200 and body.get("status") in {None, "ok", "healthy", "degraded"}
    return BenchResult("health", ok, f"status={status} body={body} latency_ms={elapsed_ms:.1f}")


def main() -> int:
    base_url = os.environ.get("AGENT_BOM_URL", "http://127.0.0.1:8422").strip()
    api_key = os.environ.get("AGENT_BOM_API_KEY", "").strip()
    if not api_key:
        print("AGENT_BOM_API_KEY is required", file=sys.stderr)
        return 2

    client = Client(base_url, api_key)
    results: list[BenchResult] = []

    if "health" in PHASES:
        results.append(run_health(client))
    if "ingest" in PHASES:
        results.extend(run_ingest(client, DEFAULT_TARGET, DEFAULT_BATCH, DEFAULT_INGEST_CONC))
    if "idempotency" in PHASES and DEFAULT_TARGET > 0:
        results.append(run_idempotency(client, min(DEFAULT_BATCH, DEFAULT_TARGET)))
    if "read" in PHASES:
        results.extend(run_reads(client, DEFAULT_READ_PAGES, DEFAULT_PAGE_LIMIT))
    if "health" in PHASES:
        results.append(run_health(client))

    print(f"agent-bom scale bench @ {base_url}")
    print(f"phases={','.join(sorted(PHASES))} target={DEFAULT_TARGET} batch={DEFAULT_BATCH} conc={DEFAULT_INGEST_CONC}")
    failed = 0
    for result in results:
        flag = "PASS" if result.ok else "FAIL"
        if not result.ok:
            failed += 1
        print(f"[{flag}] {result.name}: {result.detail}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
