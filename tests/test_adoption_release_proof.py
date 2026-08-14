from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sqlite_findings_benchmark_emits_honest_operability_evidence(tmp_path: Path) -> None:
    benchmark = _load_script("bench_findings_read.py")
    args = argparse.Namespace(
        mode="store",
        base_url="",
        tenant_id="bench-tenant",
        token="",
        timeout=30.0,
        count=50,
        limit=10,
        samples=5,
        warmup=1,
        sqlite_db=str(tmp_path / "findings.sqlite"),
        p50_threshold_ms=2000.0,
        concurrency=2,
    )

    summary = benchmark._run(args)

    assert summary["schema_version"] == "operability-benchmark.v1"
    assert summary["backend"] == "sqlite"
    assert summary["dataset"] == {"findings": 50, "page_size": 10}
    assert summary["latency_ms"]["p50"] >= 0
    assert summary["latency_ms"]["p95"] >= summary["latency_ms"]["p50"]
    assert summary["throughput_ops_per_second"] > 0
    assert summary["peak_memory_mib"] > 0
    assert summary["concurrency"] == 2
    assert summary["recovery"] == {"kind": "store_reopen", "status": "passed"}
    assert summary["claim"] == "synthetic_local_not_a_production_slo"


def test_postgres_benchmark_contract_marks_unrun_proof_unverified() -> None:
    benchmark = _load_script("run_postgres_scale_evidence.py")

    evidence = benchmark.generate(None, [1000], 4, ["audit", "job_put", "job_get"], dry_run=True)

    assert evidence["schema_version"] == "operability-benchmark.v1"
    assert evidence["backend"] == "postgres"
    assert evidence["evidence_status"] == "unverified_dry_run"
    assert evidence["required_metrics"] == [
        "p50_ms",
        "p95_ms",
        "throughput_ops_per_second",
        "peak_memory_mib",
        "concurrency",
        "recovery",
    ]
    assert evidence["claim"] == "controlled_benchmark_not_a_production_slo"


def test_release_evidence_matrix_is_machine_checked() -> None:
    checker = _load_script("check_release_evidence_matrix.py")

    assert checker.check() == []
    matrix = json.loads((ROOT / "docs" / "release" / "release-evidence-matrix.json").read_text())
    surfaces = {row["surface"] for row in matrix["surfaces"]}
    assert surfaces == {
        "python",
        "dashboard",
        "docker_api",
        "docker_ui",
        "docker_collector",
        "helm_oci",
        "github_action",
        "mcp_metadata",
        "registries",
        "sbom",
        "signatures",
        "provenance",
        "live_demo",
    }
    assert "python scripts/check_release_evidence_matrix.py" in (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "python scripts/check_release_evidence_matrix.py" in (ROOT / ".github" / "workflows" / "release.yml").read_text()
