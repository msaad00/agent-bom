"""Kubernetes pod discovery — extract container image references from a cluster.

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


class K8sDiscoveryError(Exception):
    """Raised when kubectl discovery fails."""


def _kubectl_available() -> bool:
    return shutil.which("kubectl") is not None


ImageRecord = tuple[str, str, str]  # (image_ref, pod_name, container_name)


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
    if not _kubectl_available():
        raise K8sDiscoveryError(
            "'kubectl' not found on PATH. Install kubectl and ensure it is configured with access to the target cluster."
        )

    cmd = ["kubectl", "get", "pods", "-o", "json"]

    if all_namespaces:
        cmd.append("-A")
    else:
        cmd += ["-n", namespace]

    if context:
        cmd += ["--context", context]

    if label_selector:
        cmd += ["-l", label_selector]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        raise K8sDiscoveryError("kubectl not found")
    except subprocess.TimeoutExpired:
        raise K8sDiscoveryError("kubectl timed out — check cluster connectivity")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise K8sDiscoveryError(f"kubectl exited {result.returncode}: {stderr[:300]}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise K8sDiscoveryError(f"kubectl produced invalid JSON: {e}")

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
    if not _kubectl_available():
        raise K8sDiscoveryError("kubectl not found")

    cmd = ["kubectl", "get", "namespaces", "-o", "json"]
    if context:
        cmd += ["--context", context]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise K8sDiscoveryError(str(e))

    if result.returncode != 0:
        raise K8sDiscoveryError(result.stderr.strip()[:200])

    try:
        data = json.loads(result.stdout)
        return [item["metadata"]["name"] for item in data.get("items", [])]
    except (json.JSONDecodeError, KeyError):
        return []
