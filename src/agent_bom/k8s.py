"""Kubernetes live-cluster helpers.

Runs ``kubectl get pods`` to list running containers, then returns their image
references so the caller can pass them to ``image.scan_image()`` for package
extraction.

Usage from cli.py::

    from agent_bom.k8s import discover_images, K8sDiscoveryError
    images = discover_images(namespace="default", context="my-cluster")
    for image_ref, pod_name, container_name in images:
        packages, strategy = scan_image(image_ref)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

from agent_bom.iac.models import IaCFinding


class K8sDiscoveryError(Exception):
    """Raised when kubectl discovery fails."""


def _kubectl_available() -> bool:
    return shutil.which("kubectl") is not None


ImageRecord = tuple[str, str, str]  # (image_ref, pod_name, container_name)


def _run_kubectl_json(args: list[str], *, context: Optional[str] = None, timeout: int = 60) -> dict:
    """Run kubectl and parse JSON output."""
    if not _kubectl_available():
        raise K8sDiscoveryError(
            "'kubectl' not found on PATH. Install kubectl and ensure it is configured with access to the target cluster."
        )

    cmd = ["kubectl", *args]
    if context:
        cmd += ["--context", context]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise K8sDiscoveryError("kubectl not found")
    except subprocess.TimeoutExpired:
        raise K8sDiscoveryError("kubectl timed out — check cluster connectivity")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise K8sDiscoveryError(f"kubectl exited {result.returncode}: {stderr[:300]}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise K8sDiscoveryError(f"kubectl produced invalid JSON: {exc}")


def discover_images(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
    label_selector: Optional[str] = None,
) -> list[ImageRecord]:
    """Discover container images running in a Kubernetes cluster.

    Uses ``kubectl get pods`` with ``-o json`` output.

    Args:
        namespace: Kubernetes namespace to query (ignored when ``all_namespaces=True``).
        all_namespaces: Query all namespaces (``kubectl get pods -A``).
        context: kubectl context to use (uses current context if ``None``).
        label_selector: Label selector string, e.g. ``"app=myapp"``.

    Returns:
        List of ``(image_ref, pod_name, container_name)`` tuples.
        Deduplication is applied — the same image reference is only returned once,
        attributed to the first pod/container where it was seen.

    Raises:
        K8sDiscoveryError: If kubectl is not available or the API call fails.
    """
    cmd = ["get", "pods", "-o", "json"]

    if all_namespaces:
        cmd.append("-A")
    else:
        cmd += ["-n", namespace]

    if label_selector:
        cmd += ["-l", label_selector]

    data = _run_kubectl_json(cmd, context=context, timeout=60)

    records: list[ImageRecord] = []
    seen_images: set[str] = set()

    for pod in data.get("items", []):
        pod_name = pod.get("metadata", {}).get("name", "unknown")
        pod_ns = pod.get("metadata", {}).get("namespace", namespace)
        qualified_pod = f"{pod_ns}/{pod_name}" if all_namespaces else pod_name

        # Prefer spec.containers; also check initContainers and ephemeralContainers
        container_lists = [
            pod.get("spec", {}).get("containers", []),
            pod.get("spec", {}).get("initContainers", []),
            pod.get("spec", {}).get("ephemeralContainers", []),
        ]

        for container_list in container_lists:
            for container in container_list:
                image_ref = container.get("image", "").strip()
                container_name = container.get("name", "unknown")
                if image_ref and image_ref not in seen_images:
                    seen_images.add(image_ref)
                    records.append((image_ref, qualified_pod, container_name))

    return records


def list_namespaces(context: Optional[str] = None) -> list[str]:
    """Return the list of namespaces in the cluster.

    Useful for ``--k8s --all-namespaces`` mode UI feedback.

    Raises:
        K8sDiscoveryError: If kubectl is not available or the call fails.
    """
    try:
        data = _run_kubectl_json(["get", "namespaces", "-o", "json"], context=context, timeout=30)
        return [item["metadata"]["name"] for item in data.get("items", [])]
    except K8sDiscoveryError as exc:
        if "invalid JSON" in str(exc):
            return []
        raise
    except KeyError:
        return []


def scan_live_cluster_posture(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
) -> list[IaCFinding]:
    """Inspect runtime Kubernetes posture through the live API via kubectl.

    This complements manifest scanning. It does not attempt full policy
    evaluation across the cluster; it inspects live workload, RBAC, and
    namespace state that static manifests cannot prove.
    """
    ns_args = ["-A"] if all_namespaces else ["-n", namespace]
    findings: list[IaCFinding] = []

    pods = _run_kubectl_json(["get", "pods", *ns_args, "-o", "json"], context=context, timeout=60)
    network_policies = _run_kubectl_json(["get", "networkpolicies", *ns_args, "-o", "json"], context=context, timeout=30)
    cluster_role_bindings = _run_kubectl_json(["get", "clusterrolebindings", "-o", "json"], context=context, timeout=30)

    policy_namespaces = {
        item.get("metadata", {}).get("namespace", namespace)
        for item in network_policies.get("items", [])
        if item.get("metadata", {}).get("namespace")
    }
    namespaces_with_pods: set[str] = set()

    for pod in pods.get("items", []):
        metadata = pod.get("metadata", {})
        pod_name = metadata.get("name", "unknown")
        pod_ns = metadata.get("namespace", namespace)
        namespaces_with_pods.add(pod_ns)
        pod_ref = f"k8s://{pod_ns}/{pod_name}"
        spec = pod.get("spec", {}) or {}
        status = pod.get("status", {}) or {}
        phase = status.get("phase", "Unknown")

        if phase != "Running":
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-001",
                    severity="medium",
                    title="Live pod not running",
                    message=(
                        f"Pod '{pod_ns}/{pod_name}' is currently in phase '{phase}'. "
                        "Investigate runtime drift, crash loops, or image/config rollout health."
                    ),
                    file_path=pod_ref,
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.7.4", "NIST-SI-4"],
                )
            )

        container_statuses = status.get("containerStatuses", []) or []
        for container_status in container_statuses:
            waiting = (container_status.get("state", {}) or {}).get("waiting", {}) or {}
            if waiting.get("reason") == "CrashLoopBackOff":
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-002",
                        severity="high",
                        title="Live pod is crash looping",
                        message=(
                            f"Pod '{pod_ns}/{pod_name}' container '{container_status.get('name', 'unknown')}' "
                            "is in CrashLoopBackOff. Runtime drift or bad rollout is already impacting availability."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.7.4", "NIST-SI-4"],
                    )
                )
            if not container_status.get("ready", False):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-003",
                        severity="medium",
                        title="Live pod container not ready",
                        message=(
                            f"Pod '{pod_ns}/{pod_name}' container '{container_status.get('name', 'unknown')}' "
                            "is not ready. Live readiness drift may bypass assumptions in static manifests."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.7.4", "NIST-SI-4"],
                    )
                )

        if spec.get("automountServiceAccountToken", True):
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-004",
                    severity="medium",
                    title="Live pod mounts service-account token",
                    message=(
                        f"Pod '{pod_ns}/{pod_name}' is running with service-account token auto-mount enabled. "
                        "Disable token mounting unless the workload needs Kubernetes API access."
                    ),
                    file_path=pod_ref,
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
                )
            )

    for ns in sorted(namespaces_with_pods):
        if ns not in policy_namespaces:
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-005",
                    severity="high",
                    title="Namespace lacks live NetworkPolicy coverage",
                    message=(
                        f"Namespace '{ns}' has running pods but no live NetworkPolicy objects. "
                        "This is a runtime posture gap even if manifests exist elsewhere in Git."
                    ),
                    file_path=f"k8s://namespace/{ns}",
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.3.2", "NIST-SC-7"],
                )
            )

    for binding in cluster_role_bindings.get("items", []):
        metadata = binding.get("metadata", {}) or {}
        role_ref = binding.get("roleRef", {}) or {}
        if role_ref.get("name") != "cluster-admin":
            continue
        subjects = binding.get("subjects", []) or []
        subject_names = (
            ", ".join(
                f"{subject.get('kind', 'Subject')}:{subject.get('namespace', '')}/{subject.get('name', 'unknown')}".strip("/")
                for subject in subjects
            )
            or "unknown subject"
        )
        binding_name = metadata.get("name", "unknown")
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-006",
                severity="critical",
                title="Live cluster-admin RBAC binding detected",
                message=(
                    f"ClusterRoleBinding '{binding_name}' grants cluster-admin to {subject_names}. "
                    "Review live RBAC drift and replace with least-privilege bindings."
                ),
                file_path=f"k8s://clusterrolebinding/{binding_name}",
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-5.1.1", "NIST-AC-6"],
            )
        )

    return findings
