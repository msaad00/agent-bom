#!/usr/bin/env python3
"""Measure synthetic tenant graph reads plus finding ingestion in disposable Docker.

The fixture contains graph vulnerability nodes, not pre-existing finding ledger
rows. All attempts, including throttling and timeouts, remain in the receipt.
CPU and memory are measured resource usage, not cloud prices or capacity claims.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode
from agent_bom.security import sanitize_text

ROOT = Path(__file__).resolve().parents[1]
IMAGE_REPOSITORY = "agent-bom-mixed-scale-evidence"
IMAGE_EXTRAS = "api"
# Everything the root Dockerfile COPYs besides src/. The server image is built
# from this frozen checkout so its dependencies always match the measured
# source's lockfile; a pinned release image silently drifts behind it.
BUILD_INPUTS = (
    "Dockerfile",
    "pyproject.toml",
    "uv.lock",
    "README.md",
    "docs/registry/PYPI_README.md",
    "LICENSE",
    "deploy/supabase/postgres",
    "deploy/docker/runtime-security-requirements.txt",
    "deploy/docker/vendor",
)


def seed(db: Path, *, tenants: int, findings: int, assets: int, agents: int, servers: int) -> list[dict]:
    """Create a fresh fixture with the same identifiers in independent tenants."""
    if db.exists():
        raise FileExistsError("Scale evidence requires a fresh database")
    store = SQLiteGraphStore(db)
    receipts = []
    for tenant_index in range(tenants):
        tenant = f"scale-{tenant_index}"

        def nodes():
            for kind, count, entity_type in (
                ("asset", assets, EntityType.CLOUD_RESOURCE),
                ("agent", agents, EntityType.AGENT),
                ("mcp", servers, EntityType.SERVER),
                ("finding", findings, EntityType.VULNERABILITY),
            ):
                for index in range(count):
                    if index % 10000 == 0 and shutil.disk_usage(db.parent).free < 1024**3:
                        raise OSError("Scale fixture disk reserve reached")
                    yield UnifiedNode(
                        id=f"{kind}:{index:07}",
                        entity_type=entity_type,
                        label=f"{tenant} {kind} {index:07}",
                        severity="critical" if kind in {"asset", "finding"} else "",
                        risk_score=100 if kind == "asset" and index == 0 else 50 if kind == "finding" else 0,
                        data_sources=["synthetic_scale_fixture"],
                        attributes={"fixture": True, "owner": tenant},
                    )

        def edges():
            for index in range(agents):
                yield UnifiedEdge(source=f"agent:{index:07}", target=f"mcp:{index % servers:07}", relationship=RelationshipType.USES)
                yield UnifiedEdge(source=f"asset:{index % assets:07}", target=f"agent:{index:07}", relationship=RelationshipType.HOSTS)
            for index in range(findings):
                asset = 0 if index % 4 == 0 else 1 + index % (assets - 1)
                yield UnifiedEdge(source=f"asset:{asset:07}", target=f"finding:{index:07}", relationship=RelationshipType.VULNERABLE_TO)

        started = time.perf_counter()
        counts = store.save_graph_streaming(tenant_id=tenant, scan_id="scale", nodes=nodes(), edges=edges())
        # A Connection context commits/rolls back but does not close. Leaving
        # host-owned WAL handles alive can make the container's different UID
        # see a read-only database until nondeterministic garbage collection.
        with closing(sqlite3.connect(db)) as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        receipts.append({"tenant": tenant, "counts": counts, "seconds": time.perf_counter() - started, "db_bytes": db.stat().st_size})
    return receipts


def percentiles(values: list[float]) -> dict:
    values = sorted(values)
    return {
        "samples": len(values),
        **{f"p{p}": round(values[math.ceil(len(values) * p / 100) - 1], 3) if values else None for p in (50, 95, 99)},
    }


def summarize(rows: list[dict]) -> dict:
    result = {}
    for operation in sorted({row["operation"] for row in rows}):
        attempts = [row for row in rows if row["operation"] == operation]
        result[operation] = {
            "requests": len(attempts),
            "failures": sum(not row["ok"] for row in attempts),
            "all_attempts_ms": percentiles([row["ms"] for row in attempts]),
            "successful_ms": percentiles([row["ms"] for row in attempts if row["ok"]]),
            "max_bytes": max(row["bytes"] for row in attempts),
        }
    return result


def rejection_diagnostics(body: object) -> dict:
    """Retain known admission outcomes without arbitrary response text."""
    detail = body.get("detail") if isinstance(body, dict) else None
    if not isinstance(detail, dict) or detail.get("path") != "graph":
        return {}
    if detail.get("reason") not in {"p99_latency_threshold", "concurrency_limit", "latency_degraded"}:
        return {}
    result = {"path": "graph", "reason": detail["reason"]}
    retry = detail.get("retry_after_seconds")
    if type(retry) is int and 0 < retry <= 86400:
        result["retry_after_seconds"] = retry
    return result


def valid_response(operation: str, body: object, tenant: str, *, batch: int) -> bool:
    if not isinstance(body, dict):
        return False
    # Search does not return a top-level tenant ID. Its recorded fixture owner
    # and label must both agree for every result, not merely the first match.
    if operation != "search" and body.get("tenant_id") != tenant:
        return False
    if operation == "ingest":
        return body.get("ingested") == batch
    nodes = body.get("nodes" if operation == "page" else "results", [])
    edges = body.get("edges", [])
    return (
        isinstance(nodes, list)
        and bool(nodes)
        and all(
            isinstance(node, dict)
            and isinstance(node.get("label"), str)
            and node["label"].startswith(tenant + " ")
            and (operation != "search" or (isinstance(node.get("attributes"), dict) and node["attributes"].get("owner") == tenant))
            for node in nodes
        )
        and isinstance(edges, list)
        and len(edges) <= 1000
    )


def tree_digest(source: Path) -> str:
    """Hash source bytes and relative names, excluding interpreter caches."""
    digest = hashlib.sha256()
    for path in sorted(source.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError("Runtime source must not contain symlinks")
        if path.is_file():
            name = path.relative_to(source).as_posix().encode()
            content = path.read_bytes()
            digest.update(len(name).to_bytes(8, "big") + name)
            digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


def freeze_source(source: Path, destination: Path) -> str:
    """Measure a private immutable copy, never a changing working-tree mount."""
    before = tree_digest(source)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if tree_digest(source) != before or tree_digest(destination) != before:
        raise ValueError("Runtime source changed while copying")
    return before


def overlap_summary(rows: list[dict]) -> dict:
    """Report client-observed request overlap, not simultaneous DB execution."""
    reads = [row for row in rows if row["operation"] != "ingest"]
    writes = [row for row in rows if row["operation"] == "ingest"]

    def intersection(a, b):
        return max(a["start_offset_ms"], b["start_offset_ms"]), min(a["end_offset_ms"], b["end_offset_ms"])

    def overlaps(row, candidates):
        return any(left < right for left, right in (intersection(row, other) for other in candidates))

    intervals = sorted((left, right) for read in reads for write in writes for left, right in [intersection(read, write)] if left < right)
    merged: list[list[float]] = []
    for left, right in intervals:
        if merged and left <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], right)
        else:
            merged.append([left, right])
    return {
        "basis": "client request intervals; does not prove simultaneous database execution",
        "read_attempts": len(reads),
        "read_attempts_overlapping_ingest": sum(overlaps(row, writes) for row in reads),
        "read_attempts_overlapping_successful_ingest": sum(overlaps(row, [item for item in writes if item["ok"]]) for row in reads),
        "same_tenant_read_attempts_overlapping_ingest": sum(
            overlaps(row, [item for item in writes if item["tenant"] == row["tenant"]]) for row in reads
        ),
        "read_write_overlap_ms": round(sum(right - left for left, right in merged), 3),
        "by_operation": {
            operation: {
                "attempts": sum(row["operation"] == operation for row in reads),
                "overlapping_ingest": sum(overlaps(row, writes) for row in reads if row["operation"] == operation),
            }
            for operation in ("page", "search")
        },
    }


def freeze_build_context(root: Path, context: Path) -> None:
    """Copy the Dockerfile's non-source inputs next to the frozen ``src`` copy."""
    for relative in BUILD_INPUTS:
        source, destination = root / relative, context / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(source, destination)


def build_image(context: Path) -> dict:
    """Build the API image from the frozen context; the tag is its content digest."""
    context_digest = tree_digest(context)
    tag = f"{IMAGE_REPOSITORY}:{context_digest[:20]}"
    docker("build", "--quiet", "--build-arg", f"AGENT_BOM_EXTRAS={IMAGE_EXTRAS}", "--tag", tag, str(context), timeout=1800)
    image_id = docker("image", "inspect", "--format", "{{.Id}}", tag).strip()
    return {"tag": tag, "id": image_id, "extras": IMAGE_EXTRAS, "build_context_sha256": context_digest}


def docker(*args: str, env: dict[str, str] | None = None, timeout: int = 180) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=timeout, env=env).stdout


def sanitized_diagnostics(text: str, secret: str) -> str:
    """Keep bounded diagnostic lines without minted or credential-shaped secrets."""
    return "\n".join(sanitize_text(line, max_len=4096) for line in text.replace(secret, "<redacted>").splitlines()) + "\n"


def resources(name: str) -> dict:
    return json.loads(
        docker(
            "exec",
            name,
            "python",
            "-c",
            (
                "import json,pathlib,platform,sqlite3,agent_bom;"
                "print(json.dumps({'sqlite_version':sqlite3.sqlite_version,'python_version':platform.python_version(),"
                "'source_file':agent_bom.__file__,"
                "'memory_peak_bytes':int(pathlib.Path('/sys/fs/cgroup/memory.peak').read_text()),"
                "'cpu_stat':pathlib.Path('/sys/fs/cgroup/cpu.stat').read_text()}))"
            ),
        )
    )


def run(args: argparse.Namespace) -> int:
    output = args.output.resolve()
    if output.is_relative_to(ROOT.resolve()):
        raise ValueError("Evidence output must be outside the source checkout")
    duration = getattr(args, "duration_seconds", 0)
    ingest_interval = getattr(args, "ingest_interval", 1.0)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    state = output / "state"
    state.mkdir(mode=0o777)
    state.chmod(0o777)
    fixture = output / "fixture"
    fixture.mkdir(mode=0o777)
    fixture.chmod(0o777)
    name = "agent-bom-scale-" + secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    receipt: dict[str, Any] = {
        "status": "running",
        "image": None,
        "container_name": name,
        "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": (
            "Synthetic graph nodes plus concurrent finding-ledger ingestion; "
            "no customer, provider, production capacity or cloud-price proof"
        ),
        "host": {"system": platform.system(), "machine": platform.machine(), "cpu_count": os.cpu_count()},
        "quota": {"cpus": 2, "memory_bytes": 2 * 1024**3, "api_workers": 1},
        "configuration": {key: value for key, value in vars(args).items() if key != "output"},
        "rows": [],
        "expected_attempts": None if duration else args.tenants * (args.read_requests * 2 + args.ingest_batches),
        "workload": {
            "mode": "duration" if duration else "count",
            "duration_seconds": duration,
            "ingest_interval_seconds": ingest_interval if duration else 0,
        },
        "workers": [],
        "worker_errors": [],
        "persistence_errors": [],
    }
    receipt_lock = threading.Lock()
    container_attempted = False

    def save():
        # Caller holds receipt_lock whenever worker threads are active. Atomic
        # replacement leaves the last complete checkpoint readable on failure.
        try:
            temporary = output / "receipt.json.tmp"
            temporary.write_text(json.dumps(receipt, indent=2) + "\n")
            temporary.replace(output / "receipt.json")
        except OSError as exc:
            receipt["status"] = "failed"
            error_type = type(exc).__name__
            if error_type not in receipt["persistence_errors"]:
                receipt["persistence_errors"].append(error_type)

    save()
    try:
        build_context = output / "build-context"
        runtime_source = build_context / "src"
        receipt["source"] = {
            "runtime_tree_sha256": freeze_source(ROOT / "src", runtime_source),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--", "src"], cwd=ROOT, text=True).strip()),
            "mount": "private-copy-read-only",
        }
        freeze_build_context(ROOT, build_context)
        receipt["image"] = build_image(build_context)
        save()
        receipt["fixture"] = seed(
            fixture / "graph.db",
            tenants=args.tenants,
            findings=args.findings_per_tenant,
            assets=args.assets_per_tenant,
            agents=args.agents_per_tenant,
            servers=args.servers_per_tenant,
        )
        (fixture / "graph.db").chmod(0o666)
        save()
        # Docker inherits only the named variable from this private child
        # environment; never put the credential in argv or evidence files.
        # Container metadata remains visible to Docker administrators.
        container_attempted = True
        docker(
            "run",
            "-d",
            "--name",
            name,
            "--cpus",
            "2",
            "--memory",
            "2g",
            "--env",
            "AGENT_BOM_TRUST_PROXY_AUTH_SECRET",
            "--env",
            "AGENT_BOM_TRUST_PROXY_AUTH=1",
            "--env",
            "AGENT_BOM_DB=/state/api.db",
            "--env",
            "AGENT_BOM_GRAPH_DB=/fixture/graph.db",
            "--env",
            "AGENT_BOM_STATE_DIR=/state",
            "--env",
            "PYTHONPATH=/candidate",
            "-p",
            "127.0.0.1::8422",
            "-v",
            f"{state}:/state",
            "-v",
            f"{fixture}:/fixture",
            "-v",
            f"{runtime_source}:/candidate:ro",
            "--entrypoint",
            "python",
            receipt["image"]["tag"],
            "-m",
            "uvicorn",
            "agent_bom.api.server:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8422",
            env={**os.environ, "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": secret},
        )
        base_url = "http://127.0.0.1:" + docker("port", name, "8422/tcp").strip().split(":")[-1]
        with httpx.Client(base_url=base_url, timeout=2) as client:
            for _ in range(150):
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.2)
            else:
                raise TimeoutError("API startup did not finish")
            denied = client.get("/v1/graph", headers={"X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": "scale-0"})
            if denied.status_code != 401:
                raise AssertionError("Unsigned proxy identity was accepted")
            receipt["unsigned_identity_status"] = denied.status_code
        barrier = threading.Barrier(args.tenants * 3, timeout=30)

        def worker(tenant_index: int, operation: str) -> None:
            tenant = f"scale-{tenant_index}"
            with httpx.Client(
                base_url=base_url,
                timeout=args.timeout,
                headers={
                    "X-Agent-Bom-Role": "admin",
                    "X-Agent-Bom-Tenant-ID": tenant,
                    "X-Agent-Bom-Proxy-Secret": secret,
                },
            ) as client:
                barrier.wait()
                index = 0
                count = args.ingest_batches if operation == "ingest" else args.read_requests
                while time.perf_counter() < started + duration if duration else index < count:
                    start = time.perf_counter()
                    row = {
                        "tenant": tenant,
                        "operation": operation,
                        "attempt": index,
                        "ok": False,
                        "bytes": 0,
                        "start_offset_ms": (start - started) * 1000,
                    }
                    try:
                        if operation == "ingest":
                            response = client.post(
                                "/v1/findings/bulk",
                                json={
                                    "source": "synthetic-scale",
                                    "findings": [
                                        {
                                            "id": f"{tenant}:{index}:{item}",
                                            "canonical_id": f"{tenant}:{index}:{item}",
                                            "title": f"{tenant} synthetic finding",
                                            "severity": "high",
                                            "asset": {"name": f"{tenant}:asset:{item}", "asset_type": "cloud_resource"},
                                        }
                                        for item in range(args.batch_size)
                                    ],
                                },
                            )
                        else:
                            response = client.get(
                                "/v1/graph" + ("/search" if operation == "search" else ""),
                                params={
                                    "scan_id": "scale",
                                    "limit": 50 if operation == "search" else 100,
                                    **({"q": "finding"} if operation == "search" else {}),
                                },
                            )
                        row.update(status=response.status_code, bytes=len(response.content))
                        if response.status_code in {200, 201}:
                            row["ok"] = valid_response(operation, response.json(), tenant, batch=args.batch_size)
                        elif response.status_code == 429:
                            row["rejection"] = rejection_diagnostics(response.json())
                    except Exception as exc:
                        # Preserve unexpected decoder/client faults as attempts,
                        # without copying exception messages or response secrets.
                        row["error_type"] = type(exc).__name__
                    finally:
                        end = time.perf_counter()
                        row["ms"] = (end - start) * 1000
                        row["end_offset_ms"] = (end - started) * 1000
                        with receipt_lock:
                            receipt["rows"].append(row)
                            save()
                    index += 1
                    if duration and operation == "ingest":
                        delay = min(start + ingest_interval, started + duration) - time.perf_counter()
                        if delay > 0:
                            time.sleep(delay)
                with receipt_lock:
                    receipt["workers"].append(
                        {
                            "tenant": tenant,
                            "operation": operation,
                            "attempts": index,
                            "finished_offset_ms": (time.perf_counter() - started) * 1000,
                        }
                    )
                    save()

        receipt["before"] = resources(name)
        if receipt["before"].get("source_file") != "/candidate/agent_bom/__init__.py":
            raise RuntimeError("Container did not import the frozen candidate")
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.tenants * 3) as pool:
            futures = {
                pool.submit(worker, tenant, operation): {"tenant": f"scale-{tenant}", "operation": operation}
                for tenant in range(args.tenants)
                for operation in ("page", "search", "ingest")
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    with receipt_lock:
                        receipt["worker_errors"].append({**futures[future], "error_type": type(exc).__name__})
                        save()
        receipt["elapsed_seconds"] = time.perf_counter() - started
        receipt["after"] = resources(name)
        receipt["source"]["runtime_tree_unchanged"] = tree_digest(runtime_source) == receipt["source"]["runtime_tree_sha256"]
        receipt["source"]["harness_unchanged"] = (
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == receipt["source"]["harness_sha256"]
        )
        receipt["status"] = (
            "passed"
            if (
                (
                    (len(receipt["rows"]) == receipt["expected_attempts"])
                    if not duration
                    else (
                        len(receipt["workers"]) == args.tenants * 3
                        and all(worker["attempts"] > 0 and worker["finished_offset_ms"] >= duration * 1000 for worker in receipt["workers"])
                    )
                )
                and all(row["ok"] for row in receipt["rows"])
                and not receipt["worker_errors"]
                and not receipt["persistence_errors"]
                and receipt["source"]["runtime_tree_unchanged"]
                and receipt["source"]["harness_unchanged"]
            )
            else "failed"
        )
    except Exception as exc:
        receipt.update(status="failed", error_type=type(exc).__name__)
    finally:
        # Cleanup is independent of persistence: disk-full/permission errors
        # must never skip removal of the container and its environment metadata.
        cleanup: dict[str, dict[str, Any]] = {"container": {"attempted": container_attempted, "ok": True}}
        if container_attempted:
            try:
                result = subprocess.run(["docker", "logs", "--tail", "2000", name], capture_output=True, text=True, check=False, timeout=30)
                (output / "server.log").write_text(sanitized_diagnostics(result.stdout + result.stderr, secret))
                receipt["diagnostics"] = {"ok": result.returncode == 0, "returncode": result.returncode, "path": "server.log"}
            except Exception as exc:
                receipt["diagnostics"] = {"ok": False, "error_type": type(exc).__name__}
            try:
                removed = subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)
                cleanup["container"].update(ok=removed.returncode == 0, returncode=removed.returncode)
            except Exception as exc:
                cleanup["container"].update(ok=False, error_type=type(exc).__name__)
        receipt["cleanup"] = cleanup
        if not all(item["ok"] for item in cleanup.values()):
            receipt["status"] = "failed"
        receipt["summary"] = summarize(receipt["rows"])
        receipt["overlap"] = overlap_summary(receipt["rows"])
        receipt["recorded_attempts"] = len(receipt["rows"])
        save()
    print(json.dumps({"status": receipt["status"], "summary": receipt["summary"]}))
    return 0 if receipt["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Fresh directory; existing evidence is never overwritten")
    for name, default in (
        ("tenants", 4),
        ("findings-per-tenant", 250000),
        ("assets-per-tenant", 2500),
        ("agents-per-tenant", 1000),
        ("servers-per-tenant", 1000),
        ("read-requests", 25),
        ("ingest-batches", 12),
        ("batch-size", 100),
        ("timeout", 30),
    ):
        parser.add_argument("--" + name, type=int, default=default)
    parser.add_argument(
        "--duration-seconds", type=int, default=0, help="Run every worker to one deadline instead of fixed counts (0 disables; max 600)"
    )
    parser.add_argument(
        "--ingest-interval", type=float, default=1.0, help="Minimum seconds between per-tenant ingestion starts in duration mode"
    )
    args = parser.parse_args()
    if (
        any(value < 1 for key, value in vars(args).items() if key not in {"output", "duration_seconds", "ingest_interval"})
        or args.assets_per_tenant < 2
    ):
        parser.error("Counts must be positive; assets-per-tenant must be at least two")
    if not 0 <= args.duration_seconds <= 600 or not math.isfinite(args.ingest_interval) or args.ingest_interval <= 0:
        parser.error("Duration must be 0–600 seconds and ingest-interval must be finite and positive")
    if args.tenants > 16:
        parser.error("At most sixteen tenants are supported by this bounded harness")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
