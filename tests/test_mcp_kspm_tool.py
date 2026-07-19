"""KSPM cluster-posture MCP tool (issue #4134 stage 3).

The tool returns the SAME evidence envelope as the REST route and CLI evidence
dict — benchmark version, per-collector states, canonical ScanRun outcome, and a
findings summary — all derived from one K8sPostureResult, so the three surfaces
reconcile 1:1. A denied collector must render 'unevaluable' and 'partial', never
a clean pass.
"""

from __future__ import annotations

import asyncio
import json

import agent_bom.mcp_tools.kspm as kspm_tool
from agent_bom.iac.models import IaCFinding
from agent_bom.k8s import (
    CollectorState,
    K8sCollectorEvidence,
    K8sPostureResult,
    K8sPostureStatus,
)


def _trunc(s: str) -> str:
    return s


def _run(coro) -> dict:
    raw = asyncio.run(coro)
    assert isinstance(raw, str)
    assert "Traceback (most recent call last)" not in raw
    data = json.loads(raw)
    assert isinstance(data, dict)
    return data


def _partial_result() -> K8sPostureResult:
    return K8sPostureResult(
        findings=[
            IaCFinding(
                rule_id="K8S-LIVE-007",
                severity="critical",
                title="privileged",
                message="m",
                file_path="k8s://prod/p",
                line_number=1,
                category="kubernetes-live",
            )
        ],
        collectors=[
            K8sCollectorEvidence(collector_id="pods", state=CollectorState.EXECUTED, object_count=3),
            K8sCollectorEvidence(
                collector_id="networkpolicies",
                state=CollectorState.UNEVALUABLE,
                message="forbidden: cannot list networkpolicies",
            ),
        ],
        status=K8sPostureStatus.PARTIAL,
        transport="in_cluster",
    )


def test_tool_returns_evidence_envelope_with_honest_states(monkeypatch) -> None:
    monkeypatch.setattr(kspm_tool, "_collect_posture", lambda **_kw: _partial_result())

    data = _run(kspm_tool.kspm_cluster_posture_impl(namespace="prod", _truncate_response=_trunc))

    assert data["schema_version"] == "kspm.cluster.posture.v1"
    assert data["resource"] == "cluster_posture"
    assert "images" not in data
    assert data["benchmark"]["benchmark_name"] == "CIS Kubernetes Benchmark"
    assert data["benchmark"]["benchmark_version"]

    states = {c["collector_id"]: c["state"] for c in data["collectors"]}
    assert states["pods"] == "executed"
    assert states["networkpolicies"] == "unevaluable"

    assert data["status"] == "partial"
    assert data["scan_run"]["outcome"] == "partial"
    codes = {i["code"] for i in data["scan_run"]["issues"]}
    assert "k8s_collector_unevaluable" in codes


def test_tool_reconciles_1to1_with_evidence_dict_and_scan_run(monkeypatch) -> None:
    result = _partial_result()
    monkeypatch.setattr(kspm_tool, "_collect_posture", lambda **_kw: result)

    data = _run(kspm_tool.kspm_cluster_posture_impl(namespace="prod", _truncate_response=_trunc))

    # Same numbers as the canonical result methods (one source of truth).
    assert data["finding_count"] == len(result.findings)
    assert data["severity_summary"] == result.severity_summary()
    assert data["scan_run"] == result.to_scan_run().to_dict()
    assert data["collectors"] == result.to_evidence_dict()["collectors"]


def test_tool_never_leaks_stack_on_failure(monkeypatch) -> None:
    def _boom(**_kw):
        raise RuntimeError("kubeconfig read failed at /home/user/.kube/secret-token")

    monkeypatch.setattr(kspm_tool, "_collect_posture", _boom)
    data = _run(kspm_tool.kspm_cluster_posture_impl(namespace="prod", _truncate_response=_trunc))
    assert "error" in data
    # Absolute filesystem paths (which can carry secret material) are stripped.
    assert "/home/user/.kube" not in json.dumps(data)
