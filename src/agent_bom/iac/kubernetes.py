"""Kubernetes manifest misconfiguration scanner.

Scans YAML manifests for common security misconfigurations using
``yaml.safe_load``.  Handles multi-document YAML (``---`` separators).
No external tools required.

Rules
-----
K8S-001  privileged: true in securityContext
K8S-002  hostNetwork: true
K8S-003  hostPID: true or hostIPC: true
K8S-004  No resource limits (missing resources.limits)
K8S-005  runAsUser: 0 or runAsNonRoot: false
K8S-006  Missing readOnlyRootFilesystem: true
K8S-007  Secrets in env values (not secretKeyRef)
K8S-008  Using default namespace
K8S-009  allowPrivilegeEscalation: true
K8S-010  Missing automountServiceAccountToken: false
K8S-011  Container image uses :latest tag
K8S-012  No NetworkPolicy defined
K8S-013  No securityContext at pod level
K8S-014  hostPath volume mount
K8S-015  Writable /etc or /var mount
K8S-016  Container port 22 exposed (SSH)
K8S-017  No PodDisruptionBudget for Deployment
K8S-018  Capability NET_RAW or SYS_ADMIN added
K8S-019  emptyDir without sizeLimit
K8S-020  Service type LoadBalancer without annotation
K8S-021  Missing PodDisruptionBudget for Deployments
K8S-022  Container without liveness probe
K8S-023  Container without readiness probe
K8S-024  ServiceAccount with automountServiceAccountToken: true
K8S-025  ClusterRoleBinding with cluster-admin role
K8S-026  Pod with hostPort specified
K8S-027  Container with writable /var/run/docker.sock mount
K8S-028  NetworkPolicy missing egress rules
K8S-029  Container image from untrusted registry
K8S-030  Deployment without PodAntiAffinity (single point of failure)
K8S-031  Missing seccompProfile
K8S-032  Container with NET_ADMIN capability
K8S-033  Pod with shareProcessNamespace: true
K8S-034  GPU container with privileged mode or allowPrivilegeEscalation (GPU escape pattern)
K8S-035  hostPath volume mounting /dev/nvidia or /proc/driver/nvidia (direct device exposure)
K8S-036  nvidia-device-plugin ClusterRole with mutation verbs (least-privilege RBAC violation)
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from agent_bom.iac import kubernetes_containers as _containers
from agent_bom.iac import kubernetes_resources as _resources
from agent_bom.iac.kubernetes_common import K8sContainer, K8sDocument, K8sWorkload
from agent_bom.iac.models import IaCFinding

# Workload kinds that have a pod spec
_WORKLOAD_KINDS = frozenset(
    {
        "Pod",
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    }
)

_DocumentCheck = Callable[[K8sDocument], list[IaCFinding]]
_WorkloadCheck = Callable[[K8sWorkload], list[IaCFinding]]
_ContainerCheck = Callable[[K8sContainer], list[IaCFinding]]

_KIND_CHECKS: dict[str, _DocumentCheck] = {
    "ServiceAccount": _resources.k8s_024,
    "ClusterRoleBinding": _resources.k8s_025,
    "ClusterRole": _resources.k8s_036,
    "NetworkPolicy": _resources.k8s_028,
}
_POD_CHECKS: tuple[_WorkloadCheck, ...] = (
    _resources.k8s_002,
    _resources.k8s_003,
    _resources.k8s_008,
    _resources.k8s_010,
    _resources.k8s_033,
    _resources.k8s_030,
)
_CONTAINER_CHECKS: tuple[_ContainerCheck, ...] = (
    _containers.k8s_001,
    _containers.k8s_005,
    _containers.k8s_006,
    _containers.k8s_009,
    _containers.k8s_004,
    _containers.k8s_007,
    _containers.k8s_011,
    _containers.k8s_016,
    _containers.k8s_018,
    _containers.k8s_022,
    _containers.k8s_023,
    _containers.k8s_026,
    _containers.k8s_027,
    _containers.k8s_029,
    _containers.k8s_031,
    _containers.k8s_032,
    _containers.k8s_034,
)
_VOLUME_AND_POD_CONTEXT_CHECKS: tuple[_WorkloadCheck, ...] = (
    _resources.k8s_014_019,
    _resources.k8s_013,
)


def _get_pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Extract the pod spec from a workload resource."""
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec", {})
    if kind == "CronJob":
        return doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    if kind in _WORKLOAD_KINDS:
        return doc.get("spec", {}).get("template", {}).get("spec", {})
    return None


def _scan_workload(workload: K8sWorkload) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for pod_check in _POD_CHECKS:
        findings.extend(pod_check(workload))

    containers = workload.pod_spec.get("containers", []) or []
    init_containers = workload.pod_spec.get("initContainers", []) or []
    for container in containers + init_containers:
        if not isinstance(container, dict):
            continue
        ctx = K8sContainer(
            workload=workload,
            container=container,
            cname=container.get("name", "unnamed"),
            sec_ctx=container.get("securityContext", {}) or {},
        )
        for container_check in _CONTAINER_CHECKS:
            findings.extend(container_check(ctx))

    for tail_check in _VOLUME_AND_POD_CONTEXT_CHECKS:
        findings.extend(tail_check(workload))
    return findings


def _scan_document(doc: dict[str, Any], content: str, rel_path: str) -> list[IaCFinding]:
    kind = doc.get("kind", "")
    metadata = doc.get("metadata", {}) or {}
    name = metadata.get("name", kind)
    document = K8sDocument(doc=doc, kind=kind, name=name, name_lower=(name or "").lower(), content=content, rel_path=rel_path)

    findings: list[IaCFinding] = []
    kind_check = _KIND_CHECKS.get(kind)
    if kind_check is not None:
        findings.extend(kind_check(document))

    if kind not in _WORKLOAD_KINDS:
        return findings
    pod_spec = _get_pod_spec(doc)
    if not pod_spec:
        return findings

    workload = K8sWorkload(
        kind=kind,
        name=name,
        namespace=metadata.get("namespace", ""),
        pod_spec=pod_spec,
        content=content,
        rel_path=rel_path,
    )
    findings.extend(_scan_workload(workload))
    return findings


def scan_k8s_manifest(file_path: str | Path) -> list[IaCFinding]:
    """Scan a single Kubernetes YAML manifest for misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a Kubernetes YAML manifest.

    Returns
    -------
    list[IaCFinding]
        Detected misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    rel_path = str(path)
    findings: list[IaCFinding] = []

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return []

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        findings.extend(_scan_document(doc, content, rel_path))

    findings.extend(_resources.k8s_021(docs, content, rel_path))
    return findings
