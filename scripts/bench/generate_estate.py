#!/usr/bin/env python3
"""Synthetic-estate data generator for agent-bom GB→TB scale testing.

Feeds the ingest+read latency harness (``scripts/bench/agent_bom_scale_bench.py``)
and any other target with *realistic*, non-uniform findings — a weighted severity
distribution, varied CVE/GHSA ids, packages across eight ecosystems, cvss/epss/kev
flags, present-or-null fixed versions, reachability states and compliance tags —
so that indexes, sorts and keyset cursors are exercised the way production data
exercises them (the existing bench emits trivial all-identical rows).

Design constraints
------------------
* **Stdlib only** for core paths; ``pyarrow`` is imported lazily and only for
  ``--out parquet``. No heavy deps.
* **Streaming**: rows are produced by a generator and flushed in batches. Nothing
  buffers the whole set, so ``--target-gb 100`` runs in constant memory.
* **Deterministic**: every random draw is seeded from ``--seed`` and the row index
  (never wall-clock), so a run is byte-reproducible and resumable — but rows still
  *vary* (seed makes a run reproducible, not uniform).

Output modes
------------
* ``--out ndjson PATH``   newline-delimited JSON, streamed (``-`` = stdout).
* ``--out parquet PATH``  columnar file matching agent-bom's 27-col finding
                          schema (``src/agent_bom/output/parquet_fmt.py``); needs
                          the ``lake`` extra (pyarrow).
* ``--out bulk``          POST batches to ``/v1/findings/bulk`` on ``--url`` with a
                          deterministic ``Idempotency-Key`` per batch and optional
                          ``--concurrency``.

Examples
--------
    # 5k findings to a JSONL file
    python3 scripts/bench/generate_estate.py --findings 5000 --out ndjson estate.jsonl

    # ~10 GB of findings straight into a running control plane
    python3 scripts/bench/generate_estate.py --target-gb 10 \\
        --out bulk --url http://127.0.0.1:8422 --concurrency 8

    # lake-testable parquet
    python3 scripts/bench/generate_estate.py --findings 1000000 --out parquet estate.parquet
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ─── Realism vocabularies ────────────────────────────────────────────────────

# Ecosystem → representative package names. Kept small but plausible; the row
# generator combines these with generated versions so cardinality is high without
# a huge static table.
_ECOSYSTEM_PACKAGES: dict[str, list[str]] = {
    "pypi": [
        "requests",
        "urllib3",
        "cryptography",
        "pyyaml",
        "jinja2",
        "flask",
        "django",
        "numpy",
        "torch",
        "transformers",
        "langchain",
        "pydantic",
        "aiohttp",
        "sqlalchemy",
        "pillow",
    ],
    "npm": [
        "lodash",
        "axios",
        "express",
        "react",
        "webpack",
        "minimist",
        "node-fetch",
        "next",
        "vue",
        "moment",
        "chalk",
        "debug",
        "ws",
        "semver",
        "tar",
    ],
    "go": [
        "github.com/gin-gonic/gin",
        "golang.org/x/crypto",
        "github.com/gorilla/websocket",
        "google.golang.org/grpc",
        "github.com/prometheus/client_golang",
        "github.com/hashicorp/consul",
        "github.com/spf13/cobra",
        "github.com/aws/aws-sdk-go",
    ],
    "maven": [
        "org.apache.logging.log4j:log4j-core",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.springframework:spring-core",
        "com.google.guava:guava",
        "org.apache.commons:commons-lang3",
        "io.netty:netty-all",
        "org.hibernate:hibernate-core",
    ],
    "cargo": ["tokio", "serde", "hyper", "reqwest", "clap", "openssl", "rand", "regex", "actix-web", "rocket"],
    "nuget": ["Newtonsoft.Json", "Serilog", "Microsoft.AspNetCore.App", "System.Text.Json", "AutoMapper", "Dapper", "Polly", "xunit"],
    "composer": [
        "symfony/http-kernel",
        "laravel/framework",
        "guzzlehttp/guzzle",
        "monolog/monolog",
        "doctrine/orm",
        "twig/twig",
        "phpunit/phpunit",
    ],
    "rubygems": ["rails", "rack", "nokogiri", "devise", "puma", "sidekiq", "sinatra", "actionpack", "activerecord"],
}
_ECOSYSTEMS = list(_ECOSYSTEM_PACKAGES)

# Severity distribution: mostly low/medium, a long tail of high, few critical —
# roughly what a real estate looks like. Weights need not sum to 1.
_SEVERITY_WEIGHTS: list[tuple[str, float]] = [
    ("low", 0.42),
    ("medium", 0.34),
    ("high", 0.17),
    ("critical", 0.07),
]
_SEVERITY_CVSS_RANGE: dict[str, tuple[float, float]] = {
    "low": (0.1, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}

_SYMBOL_REACH_STATES = ["confirmed", "unconfirmed", "not_analyzed"]

_COMPLIANCE_TAGS = [
    "owasp:A06:2021",
    "owasp-llm:LLM05",
    "nist-csf:PR.IP",
    "iso-27001:A.12.6",
    "soc2:CC7.1",
    "pci-dss:6.2",
    "cis:7.1",
    "fedramp:RA-5",
    "nist-800-53:SI-2",
    "eu-ai-act:Art15",
    "atlas:AML.T0010",
    "cwe:CWE-79",
]

_CWES = ["CWE-79", "CWE-89", "CWE-22", "CWE-352", "CWE-502", "CWE-190", "CWE-400", "CWE-787", "CWE-125", "CWE-94", "CWE-611", "CWE-918"]

# Approximate serialized size of one finding row as compact NDJSON incl. newline.
# Empirically ~990 B/row for the row shape below (compact json.dumps, sort_keys).
# Used only for ``--target-gb`` → findings-count sizing; the actual written size
# is reported at runtime and asserted within ~2x in the sizing self-test.
_APPROX_BYTES_PER_FINDING = 990


# ─── Deterministic row generation ────────────────────────────────────────────


def _rng_for(seed: int, idx: int) -> random.Random:
    """A Random seeded purely from (seed, idx) — never wall-clock.

    Deriving one RNG per row keeps generation resumable: row ``idx`` is identical
    regardless of where a run starts or stops.
    """
    return random.Random((seed * 0x9E3779B1) ^ (idx * 0x85EBCA77))


def _weighted_choice(rng: random.Random, weighted: list[tuple[str, float]]) -> str:
    total = sum(w for _, w in weighted)
    r = rng.random() * total
    upto = 0.0
    for value, weight in weighted:
        upto += weight
        if r <= upto:
            return value
    return weighted[-1][0]


def make_finding(seed: int, idx: int, *, agents: int, servers: int, packages: int, cloud_resources: int, identities: int) -> dict[str, Any]:
    """Build one realistic finding dict, deterministic in (seed, idx).

    The dict carries both top-level finding fields (consumed by
    ``/v1/findings/bulk`` and NDJSON) and an ``evidence`` sub-dict, plus the graph
    axis (affected agents/servers, exposed credentials) sized off the estate knobs
    so the row exercises reach/blast-radius columns.
    """
    rng = _rng_for(seed, idx)

    ecosystem = _ECOSYSTEMS[idx % len(_ECOSYSTEMS)]
    pkg_pool = _ECOSYSTEM_PACKAGES[ecosystem]
    package = pkg_pool[rng.randrange(len(pkg_pool))]
    # High-cardinality but deterministic version.
    version = f"{rng.randint(0, 9)}.{rng.randint(0, 40)}.{rng.randint(0, 20)}"

    severity = _weighted_choice(rng, _SEVERITY_WEIGHTS)
    lo, hi = _SEVERITY_CVSS_RANGE[severity]
    cvss = round(rng.uniform(lo, hi), 1)

    # Vuln id: mostly CVE, some GHSA — both realistic-looking.
    year = 2016 + (idx % 10)
    if rng.random() < 0.78:
        cve_id = f"CVE-{year}-{rng.randint(1000, 99999)}"
    else:
        cve_id = "GHSA-" + "-".join("".join(rng.choice("23456789cdefghjkmnpqrstuvwxyz") for _ in range(4)) for _ in range(3))

    # EPSS: skewed low, occasional spike; KEV rare and correlated with high epss.
    epss = round(min(1.0, rng.betavariate(1.5, 12.0)), 5)
    is_kev = severity in {"high", "critical"} and epss > 0.4 and rng.random() < 0.35
    is_malicious = ecosystem in {"npm", "pypi"} and rng.random() < 0.015

    # fixed_version present ~70% of the time, null otherwise (unpatched tail).
    fixed_version = None
    if rng.random() < 0.70:
        parts = [int(p) for p in version.split(".")]
        parts[-1] += rng.randint(1, 5)
        fixed_version = ".".join(str(p) for p in parts)

    reachability = _weighted_choice(
        rng,
        [("not_reachable", 0.5), ("potentially_reachable", 0.25), ("reachable", 0.15), ("unknown", 0.1)],
    )
    graph_reachable = reachability == "reachable"
    graph_min_hop = rng.randint(1, 6) if graph_reachable else None

    # Graph axis: spread findings across the estate deterministically.
    agent_id = idx % max(agents, 1)
    server_id = idx % max(servers, 1)
    n_agents = rng.randint(0, 3) if graph_reachable else rng.randint(0, 1)
    n_servers = rng.randint(0, 2)
    affected_agents = [f"agent-{(agent_id + k) % max(agents, 1):06d}" for k in range(n_agents)]
    affected_servers = [f"mcp-server-{(server_id + k) % max(servers, 1):05d}" for k in range(n_servers)]
    n_creds = rng.randint(0, 2) if severity in {"high", "critical"} else 0
    exposed_credentials = [f"CRED_{(idx + k) % max(identities, 1):05d}" for k in range(n_creds)]

    n_tags = rng.randint(0, 3)
    compliance_tags = sorted({_COMPLIANCE_TAGS[rng.randrange(len(_COMPLIANCE_TAGS))] for _ in range(n_tags)})
    cwe_ids = sorted({_CWES[rng.randrange(len(_CWES))] for _ in range(rng.randint(0, 2))})

    pub_year = year
    pub_month = rng.randint(1, 12)
    pub_day = rng.randint(1, 28)
    published_at = f"{pub_year:04d}-{pub_month:02d}-{pub_day:02d}T00:00:00Z"
    modified_at = f"{pub_year:04d}-{min(12, pub_month + rng.randint(0, 3)):02d}-{pub_day:02d}T00:00:00Z"

    # effective_reach_score drives the read-path sort in the bench harness.
    reach_score = round(cvss * (2.0 if graph_reachable else 1.0) + epss * 10, 3)

    return {
        "id": f"estate:{seed}:{idx}",
        "title": f"{cve_id} in {package} {version}",
        "description": f"{severity.title()} severity vulnerability in {ecosystem} package {package} ({version}).",
        "cve_id": cve_id,
        "severity": severity,
        "cvss_score": cvss,
        "epss_score": epss,
        "is_kev": is_kev,
        "is_malicious": is_malicious,
        "malicious_reason": "typosquat heuristic" if is_malicious else None,
        "fixed_version": fixed_version,
        "cwe_ids": cwe_ids,
        "reachability": reachability,
        "effective_reach_score": reach_score,
        "risk_score": reach_score,
        "compliance_tags": compliance_tags,
        "affected_agents": affected_agents,
        "affected_servers": affected_servers,
        "exposed_credentials": exposed_credentials,
        "evidence": {
            "package_name": package,
            "package_version": version,
            "ecosystem": ecosystem,
            "published_at": published_at,
            "modified_at": modified_at,
            "epss_percentile": round(min(1.0, epss * rng.uniform(1.0, 3.0)), 5),
            "kev_date_added": published_at if is_kev else "",
            "kev_due_date": modified_at if is_kev else "",
            "severity_source": "cvss" if rng.random() < 0.8 else "vendor",
            "symbol_reachability": _SYMBOL_REACH_STATES[rng.randrange(len(_SYMBOL_REACH_STATES))],
            "reachable_affected_symbols": [
                f"{package}.func_{rng.randint(0, 50)}" for _ in range(rng.randint(0, 2) if graph_reachable else 0)
            ],
            "graph_reachable": graph_reachable,
            "graph_min_hop_distance": graph_min_hop,
            "cloud_resource_id": f"arn:res:{idx % max(cloud_resources, 1):07d}",
        },
    }


def iter_findings(seed: int, count: int, **estate: int) -> Iterator[dict[str, Any]]:
    """Yield ``count`` findings lazily — the core streaming primitive."""
    for idx in range(count):
        yield make_finding(seed, idx, **estate)


# ─── Parquet projection (27-col schema parity) ───────────────────────────────

# Mirrors src/agent_bom/output/parquet_fmt.py::_COLUMNS exactly so a generated
# file is byte-compatible with agent-bom's own parquet export for lake tests.
_PARQUET_COLUMNS = [
    "cve_id",
    "package",
    "version",
    "ecosystem",
    "severity",
    "cvss_score",
    "epss_score",
    "is_kev",
    "is_malicious",
    "malicious_reason",
    "published_at",
    "modified_at",
    "fixed_version",
    "cwe_ids",
    "affected_agents",
    "affected_servers",
    "exposed_credentials",
    "summary",
    "severity_source",
    "epss_percentile",
    "kev_date_added",
    "kev_due_date",
    "compliance_tags",
    "symbol_reachability",
    "reachable_affected_symbols",
    "graph_reachable",
    "graph_min_hop_distance",
]


def to_parquet_row(finding: dict[str, Any]) -> dict[str, Any]:
    """Project a finding dict onto agent-bom's 27-column parquet schema."""
    ev = finding.get("evidence", {})
    return {
        "cve_id": finding.get("cve_id") or finding.get("id"),
        "package": ev.get("package_name"),
        "version": ev.get("package_version"),
        "ecosystem": ev.get("ecosystem"),
        "severity": finding.get("severity"),
        "cvss_score": finding.get("cvss_score"),
        "epss_score": finding.get("epss_score"),
        "is_kev": bool(finding.get("is_kev")),
        "is_malicious": bool(finding.get("is_malicious")),
        "malicious_reason": finding.get("malicious_reason") or None,
        "published_at": ev.get("published_at") or None,
        "modified_at": ev.get("modified_at") or None,
        "fixed_version": finding.get("fixed_version") or None,
        "cwe_ids": ";".join(finding.get("cwe_ids") or []) or None,
        "affected_agents": ";".join(finding.get("affected_agents") or []),
        "affected_servers": ";".join(finding.get("affected_servers") or []),
        "exposed_credentials": len(finding.get("exposed_credentials") or []),
        "summary": finding.get("description") or None,
        "severity_source": ev.get("severity_source") or None,
        "epss_percentile": ev.get("epss_percentile"),
        "kev_date_added": ev.get("kev_date_added") or None,
        "kev_due_date": ev.get("kev_due_date") or None,
        "compliance_tags": ";".join(finding.get("compliance_tags") or []) or None,
        "symbol_reachability": ev.get("symbol_reachability") or None,
        "reachable_affected_symbols": ";".join(ev.get("reachable_affected_symbols") or []) or None,
        "graph_reachable": bool(ev.get("graph_reachable")),
        "graph_min_hop_distance": ev.get("graph_min_hop_distance"),
    }


def _parquet_schema(pa):
    return pa.schema(
        [
            ("cve_id", pa.string()),
            ("package", pa.string()),
            ("version", pa.string()),
            ("ecosystem", pa.string()),
            ("severity", pa.string()),
            ("cvss_score", pa.float64()),
            ("epss_score", pa.float64()),
            ("is_kev", pa.bool_()),
            ("is_malicious", pa.bool_()),
            ("malicious_reason", pa.string()),
            ("published_at", pa.string()),
            ("modified_at", pa.string()),
            ("fixed_version", pa.string()),
            ("cwe_ids", pa.string()),
            ("affected_agents", pa.string()),
            ("affected_servers", pa.string()),
            ("exposed_credentials", pa.int64()),
            ("summary", pa.string()),
            ("severity_source", pa.string()),
            ("epss_percentile", pa.float64()),
            ("kev_date_added", pa.string()),
            ("kev_due_date", pa.string()),
            ("compliance_tags", pa.string()),
            ("symbol_reachability", pa.string()),
            ("reachable_affected_symbols", pa.string()),
            ("graph_reachable", pa.bool_()),
            ("graph_min_hop_distance", pa.int64()),
        ]
    )


# ─── Sizing ──────────────────────────────────────────────────────────────────


def findings_for_target_gb(target_gb: float) -> int:
    """Convert a GB target into a findings count via the approx bytes/finding."""
    total_bytes = target_gb * (1024**3)
    return max(1, int(total_bytes / _APPROX_BYTES_PER_FINDING))


def default_estate(count: int) -> dict[str, int]:
    """Sensible estate-axis defaults scaled to the findings count.

    A real estate has far fewer agents/servers than findings; ratios below give
    each agent/server/package a plausible fan-in of findings.
    """
    return {
        "agents": max(1, count // 200),
        "servers": max(1, count // 500),
        "packages": max(1, count // 20),
        "cloud_resources": max(1, count // 100),
        "identities": max(1, count // 50),
    }


# ─── Output modes ────────────────────────────────────────────────────────────


def _iter_batches(it: Iterator[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    batch: list[dict[str, Any]] = []
    for row in it:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def write_ndjson(findings: Iterator[dict[str, Any]], path: str) -> tuple[int, int]:
    """Stream findings as newline-delimited JSON. Returns (rows, bytes)."""
    rows = 0
    nbytes = 0
    fh = sys.stdout if path == "-" else open(path, "w", encoding="utf-8")
    try:
        for row in findings:
            line = json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
            fh.write(line)
            rows += 1
            nbytes += len(line.encode("utf-8"))
    finally:
        if fh is not sys.stdout:
            fh.close()
    return rows, nbytes


def write_parquet(findings: Iterator[dict[str, Any]], path: str, batch_size: int) -> tuple[int, int]:
    """Stream findings into a Parquet file via row-group batches (constant mem)."""
    try:
        import pyarrow as pa  # noqa: PLC0415
        import pyarrow.parquet as pq  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Parquet output requires pyarrow. Install with: pip install 'agent-bom[lake]'") from exc

    schema = _parquet_schema(pa)
    rows = 0
    writer = pq.ParquetWriter(path, schema, compression="snappy")
    try:
        for batch in _iter_batches(findings, batch_size):
            table = pa.Table.from_pylist([to_parquet_row(f) for f in batch], schema=schema)
            writer.write_table(table)
            rows += len(batch)
    finally:
        writer.close()
    nbytes = os.path.getsize(path)
    return rows, nbytes


def _batch_idempotency_key(seed: int, source: str, batch_index: int) -> str:
    """Deterministic per-batch key so retries collapse server-side."""
    raw = f"{source}:{seed}:{batch_index}"
    return f"estate-{hashlib.sha256(raw.encode()).hexdigest()[:32]}"


def _post_bulk(
    url: str, api_key: str, source: str, seed: int, batch_index: int, batch: list[dict[str, Any]], timeout: int
) -> tuple[int, str]:
    body = json.dumps({"source": source, "findings": batch}).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Idempotency-Key": _batch_idempotency_key(seed, source, batch_index),
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = Request(f"{url.rstrip('/')}/v1/findings/bulk", data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:  # nosec B310 — operator-controlled URL
            return resp.status, resp.read().decode(errors="replace")[:300]
    except HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:300]
    except URLError as exc:
        return 0, str(exc.reason)


def write_bulk(
    findings: Iterator[dict[str, Any]], *, url: str, api_key: str, source: str, seed: int, batch_size: int, concurrency: int, timeout: int
) -> tuple[int, int]:
    """POST batches to /v1/findings/bulk. Returns (rows_sent, failed_batches)."""
    rows = 0
    failed = 0
    batches = enumerate(_iter_batches(findings, batch_size))

    if concurrency <= 1:
        for batch_index, batch in batches:
            status, detail = _post_bulk(url, api_key, source, seed, batch_index, batch, timeout)
            if status not in (200, 201):
                failed += 1
                print(f"[batch {batch_index}] HTTP {status}: {detail}", file=sys.stderr)
            else:
                rows += len(batch)
        return rows, failed

    # Bounded concurrency: keep at most `concurrency` batches in flight so memory
    # stays constant even for a huge target.
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        in_flight: dict[Any, tuple[int, int]] = {}
        for batch_index, batch in batches:
            fut = pool.submit(_post_bulk, url, api_key, source, seed, batch_index, batch, timeout)
            in_flight[fut] = (batch_index, len(batch))
            if len(in_flight) >= concurrency:
                done = next(as_completed(in_flight))
                bidx, blen = in_flight.pop(done)
                status, detail = done.result()
                if status not in (200, 201):
                    failed += 1
                    print(f"[batch {bidx}] HTTP {status}: {detail}", file=sys.stderr)
                else:
                    rows += blen
        for done in as_completed(in_flight):
            bidx, blen = in_flight[done]
            status, detail = done.result()
            if status not in (200, 201):
                failed += 1
                print(f"[batch {bidx}] HTTP {status}: {detail}", file=sys.stderr)
            else:
                rows += blen
    return rows, failed


# ─── CLI ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="generate_estate.py",
        description="Synthetic-estate generator for agent-bom GB/TB scale testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scale = p.add_mutually_exclusive_group(required=True)
    scale.add_argument("--findings", type=int, help="Number of findings to generate.")
    scale.add_argument("--target-gb", type=float, help="Approx uncompressed size target in GB (computes findings count).")

    p.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducibility (default: 1337).")
    p.add_argument("--batch-size", type=int, default=1000, help="Rows per output batch / parquet row-group / bulk POST (default: 1000).")

    # Estate axis (defaults scale off findings count).
    p.add_argument("--agents", type=int, default=None, help="Distinct agents in the estate.")
    p.add_argument("--servers", type=int, default=None, help="Distinct MCP servers.")
    p.add_argument("--packages", type=int, default=None, help="Distinct packages.")
    p.add_argument("--cloud-resources", type=int, default=None, help="Distinct cloud resources.")
    p.add_argument("--identities", type=int, default=None, help="Distinct identities/credentials.")

    p.add_argument("--out", choices=["ndjson", "parquet", "bulk"], required=True, help="Output mode.")
    p.add_argument("path", nargs="?", help="Output path for ndjson/parquet ('-' = stdout for ndjson).")

    # Bulk mode.
    p.add_argument("--url", help="Base URL of agent-bom control plane (bulk mode).")
    p.add_argument("--api-key", default=os.environ.get("AGENT_BOM_API_KEY", ""), help="Bearer token (or AGENT_BOM_API_KEY env).")
    p.add_argument("--source", default="estate-bench", help="Finding source label (bulk mode).")
    p.add_argument("--concurrency", type=int, default=1, help="Concurrent bulk POSTs in flight (bulk mode).")
    p.add_argument("--timeout", type=int, default=120, help="HTTP timeout seconds (bulk mode).")
    return p


def resolve_count(args: argparse.Namespace) -> int:
    return args.findings if args.findings is not None else findings_for_target_gb(args.target_gb)


def resolve_estate(args: argparse.Namespace, count: int) -> dict[str, int]:
    defaults = default_estate(count)
    return {
        "agents": args.agents if args.agents is not None else defaults["agents"],
        "servers": args.servers if args.servers is not None else defaults["servers"],
        "packages": args.packages if args.packages is not None else defaults["packages"],
        "cloud_resources": args.cloud_resources if args.cloud_resources is not None else defaults["cloud_resources"],
        "identities": args.identities if args.identities is not None else defaults["identities"],
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    count = resolve_count(args)
    estate = resolve_estate(args, count)
    findings = iter_findings(args.seed, count, **estate)

    started = time.perf_counter()
    if args.out == "ndjson":
        if not args.path:
            print("ndjson mode requires a PATH ('-' for stdout)", file=sys.stderr)
            return 2
        rows, nbytes = write_ndjson(findings, args.path)
    elif args.out == "parquet":
        if not args.path:
            print("parquet mode requires a PATH", file=sys.stderr)
            return 2
        rows, nbytes = write_parquet(findings, args.path, args.batch_size)
    else:  # bulk
        if not args.url:
            print("bulk mode requires --url", file=sys.stderr)
            return 2
        rows, failed = write_bulk(
            findings,
            url=args.url,
            api_key=args.api_key,
            source=args.source,
            seed=args.seed,
            batch_size=args.batch_size,
            concurrency=args.concurrency,
            timeout=args.timeout,
        )
        elapsed = time.perf_counter() - started
        rate = rows / elapsed if elapsed else 0
        print(
            f"bulk: sent {rows}/{count} findings, {failed} failed batches, {elapsed:.1f}s, {rate:,.0f} findings/s → {args.url}",
            file=sys.stderr,
        )
        return 1 if failed else 0

    elapsed = time.perf_counter() - started
    gb = nbytes / (1024**3)
    print(
        f"{args.out}: wrote {rows} findings ({gb:.4f} GB, {nbytes:,} bytes, "
        f"{nbytes / max(rows, 1):.0f} B/row) in {elapsed:.1f}s → {args.path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
