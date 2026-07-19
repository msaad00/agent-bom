"""Live kind-cluster proof for KSPM (#4134 stage 4 lock-in).

Guarded end-to-end test: against a real Kubernetes cluster it applies the
risky + hardened fixtures, runs the live posture collectors, and asserts the
run produces REAL findings with HONEST per-collector states (never a fabricated
clean pass). Skipped unless ``ABOM_LIVE_KIND=1`` and a reachable kube context.

Run locally against the kind cluster::

    ABOM_LIVE_KIND=1 ABOM_KIND_CONTEXT=kind-abom-kspm \\
        .venv/bin/pytest tests/test_kspm_live_kind.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_bom.k8s import (
    CollectorState,
    K8sPostureStatus,
    scan_live_cluster_posture_with_evidence,
)

pytestmark = pytest.mark.skipif(
    os.getenv("ABOM_LIVE_KIND") != "1",
    reason="live kind cluster proof — set ABOM_LIVE_KIND=1 to run",
)

CONTEXT = os.getenv("ABOM_KIND_CONTEXT", "kind-abom-kspm")
FIXTURES = Path(__file__).resolve().parents[1] / "deploy" / "k8s" / "kspm-fixtures.yaml"


def _kubectl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["kubectl", "--context", CONTEXT, *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.fixture(scope="module", autouse=True)
def _fixtures() -> None:
    if shutil.which("kubectl") is None:
        pytest.skip("kubectl not installed")
    if _kubectl("cluster-info").returncode != 0:
        pytest.skip(f"kube context {CONTEXT} not reachable")
    applied = _kubectl("apply", "-f", str(FIXTURES))
    assert applied.returncode == 0, applied.stderr
    _kubectl("-n", "kspm-risky", "wait", "--for=condition=Ready", "pod/risky-workload", "--timeout=60s")
    _kubectl("-n", "kspm-hardened", "wait", "--for=condition=Ready", "pod/hardened-workload", "--timeout=60s")


def _run_posture():
    return scan_live_cluster_posture_with_evidence(all_namespaces=True, context=CONTEXT)


def test_live_posture_produces_real_findings_with_honest_states():
    result = _run_posture()

    # The run reached the cluster and evaluated the core collectors honestly.
    assert result.status in (K8sPostureStatus.COMPLETE, K8sPostureStatus.PARTIAL)
    by_id = {c.collector_id: c for c in result.collectors}
    for required in ("pods", "networkpolicies", "clusterrolebindings", "clusterroles", "roles"):
        assert required in by_id, sorted(by_id)
        assert by_id[required].state is CollectorState.EXECUTED, (required, by_id[required].message)

    # Real evidence, not fabricated: the risky fixtures must be flagged.
    rules = {f.rule_id for f in result.findings}
    risky_refs = {f.file_path for f in result.findings if "kspm-risky" in f.file_path}
    assert "K8S-LIVE-007" in rules, "privileged container not detected"  # privileged
    assert "K8S-LIVE-006" in rules, "live cluster-admin binding not detected"  # cluster-admin
    assert "K8S-LIVE-005" in rules, "namespace without NetworkPolicy not detected"  # no netpol
    assert risky_refs, "no findings attributed to the risky namespace"

    # The hardened namespace must NOT be flagged privileged / no-netpol (honest,
    # differentiated evidence — the hardened side is genuinely clean there).
    hardened_privileged = [
        f for f in result.findings if "kspm-hardened" in f.file_path and f.rule_id in {"K8S-LIVE-007", "K8S-LIVE-005"}
    ]
    assert not hardened_privileged, [f.rule_id for f in hardened_privileged]


def test_live_posture_evidence_envelope_carries_versioned_benchmark():
    result = _run_posture()
    envelope = result.to_evidence_dict()
    benchmark = envelope["benchmark"]
    assert benchmark["benchmark_version"], benchmark
    assert benchmark["benchmark_name"]
    # Every collector reports an explicit executed/skipped/unevaluable/failed
    # state — no silent gaps that could read as a clean pass.
    states = {c["state"] for c in envelope["collectors"]}
    assert states <= {"executed", "skipped", "unevaluable", "failed"}, states
    assert "executed" in states


def test_live_posture_bridges_to_scan_run_contract():
    """The posture result projects onto the canonical ScanRun evidence contract."""
    result = _run_posture()
    to_scan_run = getattr(result, "to_scan_run", None)
    if to_scan_run is None:
        pytest.skip("ScanRun bridge (stage 3) not present on this branch")
    run = to_scan_run()
    from agent_bom.evidence.scan_run import ScanOutcome

    assert run.outcome in (ScanOutcome.COMPLETE, ScanOutcome.PARTIAL, ScanOutcome.FAILED)
    if result.status is K8sPostureStatus.PARTIAL:
        assert run.outcome is ScanOutcome.PARTIAL
