"""Live-cluster proof for KSPM posture against a real Kubernetes API.

These tests exercise :func:`agent_bom.k8s.scan_live_cluster_posture_with_evidence`
against an actual cluster (a local ``kind`` cluster in CI/dev) instead of fixture
payloads. They prove two things the fixture suite cannot:

1. the read-only checks evaluate a *live* cluster and catch seeded risky objects
   (permissive cluster-admin binding, a privileged running pod, a namespace with
   running pods but no NetworkPolicy); and
2. a genuinely *denied* read (a least-privilege service account forbidden from
   cluster-scoped resources) is recorded as ``unevaluable`` — never a clean pass —
   and does not abort the collectors it is allowed to read.

The suite is marked ``live_cluster`` and self-skips when no cluster is reachable,
so it stays opt-in and never breaks the offline unit run. Set
``ABOM_KSPM_KIND_CONTEXT`` to target a different kubeconfig context.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from agent_bom.k8s import (
    CollectorState,
    K8sPostureStatus,
    scan_live_cluster_posture_with_evidence,
)

pytestmark = pytest.mark.live_cluster

CONTEXT = os.environ.get("ABOM_KSPM_KIND_CONTEXT", "kind-abom-kspm")
RISKY_NAMESPACE = "abom-kspm-risky"
CLUSTER_ADMIN_BINDING = "abom-kspm-overbroad-admin"
RESTRICTED_SA = "abom-kspm-restricted"

_SEED_MANIFEST = textwrap.dedent(
    f"""
    apiVersion: v1
    kind: Namespace
    metadata:
      name: {RISKY_NAMESPACE}
    ---
    apiVersion: v1
    kind: Pod
    metadata:
      name: privileged-pod
      namespace: {RISKY_NAMESPACE}
    spec:
      terminationGracePeriodSeconds: 1
      containers:
      - name: app
        image: busybox:1.36
        command: ["sh", "-c", "sleep 3600"]
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: {CLUSTER_ADMIN_BINDING}
    subjects:
    - kind: Group
      name: abom-kspm-test-devs
      apiGroup: rbac.authorization.k8s.io
    roleRef:
      kind: ClusterRole
      name: cluster-admin
      apiGroup: rbac.authorization.k8s.io
    """
).strip()

_RESTRICTED_RBAC = textwrap.dedent(
    f"""
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: {RESTRICTED_SA}
      namespace: {RISKY_NAMESPACE}
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: {RESTRICTED_SA}-reader
      namespace: {RISKY_NAMESPACE}
    rules:
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get", "list"]
    - apiGroups: ["networking.k8s.io"]
      resources: ["networkpolicies"]
      verbs: ["get", "list"]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: {RESTRICTED_SA}-reader-binding
      namespace: {RISKY_NAMESPACE}
    subjects:
    - kind: ServiceAccount
      name: {RESTRICTED_SA}
      namespace: {RISKY_NAMESPACE}
    roleRef:
      kind: Role
      name: {RESTRICTED_SA}-reader
      apiGroup: rbac.authorization.k8s.io
    """
).strip()


def _kubectl(*args: str, stdin: str | None = None, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    cmd = ["kubectl", "--context", CONTEXT, *args]
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=check, timeout=timeout)


def _cluster_reachable() -> bool:
    if shutil.which("kubectl") is None:
        return False
    try:
        result = _kubectl("get", "--raw", "/healthz", check=False, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "ok"


pytest.importorskip("httpx")

if not _cluster_reachable():
    pytest.skip(f"kind cluster context {CONTEXT!r} not reachable", allow_module_level=True)


@pytest.fixture(scope="module")
def seeded_cluster() -> Iterator[None]:
    _kubectl("apply", "-f", "-", stdin=_SEED_MANIFEST)
    try:
        _kubectl(
            "-n",
            RISKY_NAMESPACE,
            "wait",
            "--for=condition=Ready",
            "pod/privileged-pod",
            "--timeout=90s",
        )
        yield
    finally:
        _kubectl("delete", "clusterrolebinding", CLUSTER_ADMIN_BINDING, "--ignore-not-found", check=False)
        _kubectl("delete", "namespace", RISKY_NAMESPACE, "--ignore-not-found", "--wait=false", check=False)


def test_live_kind_flags_seeded_risky_objects(seeded_cluster: None) -> None:
    result = scan_live_cluster_posture_with_evidence(all_namespaces=True, context=CONTEXT)

    # Every posture collector completed against the live cluster.
    states = {collector.collector_id: collector.state for collector in result.collectors}
    for collector_id in ("pods", "networkpolicies", "clusterrolebindings", "clusterroles"):
        assert states[collector_id] is CollectorState.EXECUTED, (collector_id, states[collector_id])
    assert result.status is K8sPostureStatus.COMPLETE

    # The evidence envelope pins the versioned, vendor-asserted benchmark provenance.
    envelope = result.to_evidence_dict()
    assert envelope["benchmark"]["benchmark_name"] == "CIS Kubernetes Benchmark"
    assert envelope["benchmark"]["benchmark_version"]
    assert envelope["benchmark"]["benchmark_type"] == "cis"
    assert envelope["benchmark"]["catalog_repository_provenance"] is False

    findings_by_ref = {(finding.rule_id, finding.file_path) for finding in result.findings}
    # Seeded privileged pod → critical privileged-container finding on the live pod.
    assert ("K8S-LIVE-007", f"k8s://{RISKY_NAMESPACE}/privileged-pod") in findings_by_ref
    # Seeded cluster-admin binding → live cluster-admin RBAC finding.
    assert ("K8S-LIVE-006", f"k8s://clusterrolebinding/{CLUSTER_ADMIN_BINDING}") in findings_by_ref
    # Seeded namespace with a running pod and no NetworkPolicy → coverage-gap finding.
    assert ("K8S-LIVE-005", f"k8s://namespace/{RISKY_NAMESPACE}") in findings_by_ref


def _restricted_kubeconfig(tmp_path: str) -> tuple[str, str]:
    """Provision a least-privilege SA and return (kubeconfig_path, context_name)."""
    _kubectl("apply", "-f", "-", stdin=_RESTRICTED_RBAC)
    token = _kubectl("create", "token", RESTRICTED_SA, "-n", RISKY_NAMESPACE, "--duration=1h").stdout.strip()

    raw = json.loads(_kubectl("config", "view", "--raw", "-o", "json").stdout)
    ctx = next(item for item in raw["contexts"] if item["name"] == CONTEXT)
    cluster_name = ctx["context"]["cluster"]
    cluster = next(item for item in raw["clusters"] if item["name"] == cluster_name)["cluster"]
    server = cluster["server"]
    ca_data = cluster.get("certificate-authority-data")
    if not ca_data:
        ca_data = base64.b64encode(Path(cluster["certificate-authority"]).read_bytes()).decode()

    context_name = "abom-kspm-restricted-ctx"
    kubeconfig = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "abom-kspm", "cluster": {"server": server, "certificate-authority-data": ca_data}}],
        "users": [{"name": RESTRICTED_SA, "user": {"token": token}}],
        "contexts": [
            {
                "name": context_name,
                "context": {"cluster": "abom-kspm", "user": RESTRICTED_SA, "namespace": RISKY_NAMESPACE},
            }
        ],
        "current-context": context_name,
    }
    path = os.path.join(tmp_path, "restricted.kubeconfig")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(kubeconfig, handle)
    return path, context_name


def test_live_kind_denied_read_is_unevaluable_not_pass_and_does_not_abort(
    seeded_cluster: None,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kubeconfig_path, restricted_ctx = _restricted_kubeconfig(str(tmp_path))
    monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
    try:
        result = scan_live_cluster_posture_with_evidence(
            namespace=RISKY_NAMESPACE,
            all_namespaces=False,
            context=restricted_ctx,
        )
    finally:
        _kubectl("delete", "-f", "-", stdin=_RESTRICTED_RBAC, check=False)

    states = {collector.collector_id: collector for collector in result.collectors}

    # The reads the SA is allowed still execute…
    assert states["pods"].state is CollectorState.EXECUTED
    assert states["networkpolicies"].state is CollectorState.EXECUTED
    # …while the forbidden cluster-scoped reads are explicitly unevaluable, never
    # a silent clean pass, and they do not abort the allowed collectors.
    assert states["clusterrolebindings"].state is CollectorState.UNEVALUABLE
    assert states["clusterroles"].state is CollectorState.UNEVALUABLE
    assert result.status is K8sPostureStatus.PARTIAL

    rule_ids = {finding.rule_id for finding in result.findings}
    # The evaluated pods collector still yields the privileged-pod finding…
    assert "K8S-LIVE-007" in rule_ids
    # …and the denied clusterrolebinding read fabricates no cluster-admin finding.
    assert "K8S-LIVE-006" not in rule_ids

    # The envelope surfaces the denied read as unevaluable for downstream consumers.
    envelope = result.to_evidence_dict()
    denied = {item["collector_id"]: item["state"] for item in envelope["collectors"]}
    assert denied["clusterrolebindings"] == "unevaluable"
    assert envelope["status"] == "partial"
