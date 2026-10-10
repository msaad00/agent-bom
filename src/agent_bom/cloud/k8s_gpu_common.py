"""Shared Kubernetes pod-scanning helpers for GPU cloud providers.

CoreWeave and Nebius both read ``kubectl get pods -o json`` payloads to find
GPU containers and InfiniBand (``rdma/ib``) training pods. These helpers are
pure functions over that payload; running ``kubectl`` and handling its
failures stays in each provider module.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

from .normalization import build_cloud_origin, build_package_purl, parse_container_image_package


def container_image_packages(image_ref: str) -> list[Package]:
    """Return the ``container-image`` package for an image reference, if parseable."""
    image_parts = parse_container_image_package(image_ref)
    if not image_parts:
        return []
    return [
        Package(
            name=image_parts[0],
            version=image_parts[1],
            ecosystem="container-image",
            purl=build_package_purl(ecosystem="container-image", name=image_parts[0], version=image_parts[1]),
        )
    ]


def iter_gpu_containers(
    pods: Iterable[dict],
    *,
    include_init_containers: bool = False,
) -> Iterator[tuple[str, str, dict, str, Any, Any]]:
    """Yield containers requesting ``nvidia.com/gpu``, first occurrence of each image only.

    Yields ``(namespace, pod_name, container, image_ref, gpu_limit, gpu_request)``
    where the GPU values are the raw resource quantities (default ``"0"``).
    """
    seen_images: set[str] = set()
    for pod in pods:
        meta = pod.get("metadata", {})
        pod_name = meta.get("name", "unknown")
        pod_ns = meta.get("namespace", "default")

        container_lists = [pod.get("spec", {}).get("containers", [])]
        if include_init_containers:
            container_lists.append(pod.get("spec", {}).get("initContainers", []))

        for container_list in container_lists:
            for container in container_list:
                resources = container.get("resources", {})
                gpu_limit = resources.get("limits", {}).get("nvidia.com/gpu", "0")
                gpu_request = resources.get("requests", {}).get("nvidia.com/gpu", "0")
                if str(gpu_limit) == "0" and str(gpu_request) == "0":
                    continue

                image_ref = container.get("image", "").strip()
                if not image_ref or image_ref in seen_images:
                    continue
                seen_images.add(image_ref)
                yield pod_ns, pod_name, container, image_ref, gpu_limit, gpu_request


def iter_infiniband_pods(pods: Iterable[dict]) -> Iterator[tuple[str, str, str, str]]:
    """Yield pods with a container requesting ``rdma/ib``, once per pod.

    Yields ``(namespace, pod_name, image_ref, gpu_limits)`` from the first
    InfiniBand container of each pod; ``gpu_limits`` is the stringified
    ``nvidia.com/gpu`` limit (``"0"`` when absent).
    """
    seen_jobs: set[str] = set()
    for pod in pods:
        meta = pod.get("metadata", {})
        pod_name = meta.get("name", "unknown")
        pod_ns = meta.get("namespace", "default")

        for container in pod.get("spec", {}).get("containers", []):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            requests_res = resources.get("requests", {})

            ib_limit = str(limits.get("rdma/ib", "0"))
            ib_request = str(requests_res.get("rdma/ib", "0"))
            if ib_limit == "0" and ib_request == "0":
                continue

            # Deduplicate by pod (multi-container training pods)
            job_key = f"{pod_ns}/{pod_name}"
            if job_key in seen_jobs:
                continue
            seen_jobs.add(job_key)

            image_ref = container.get("image", "").strip()
            gpu_limits = str(limits.get("nvidia.com/gpu", "0"))
            yield pod_ns, pod_name, image_ref, gpu_limits


def build_training_agent(
    *,
    provider: str,
    pod_ns: str,
    pod_name: str,
    image_ref: str,
    gpu_limits: str,
    config_path: str,
    project_id: str | None = None,
) -> Agent:
    """Build the ``<provider>-training`` agent for an InfiniBand training pod."""
    label = f"{provider}-training"
    server = MCPServer(
        name=f"{label}:{pod_ns}/{pod_name}",
        transport=TransportType.UNKNOWN,
        packages=container_image_packages(image_ref),
    )
    return Agent(
        name=f"{label}:{pod_ns}/{pod_name}",
        agent_type=AgentType.CUSTOM,
        config_path=config_path,
        source=label,
        version=f"infiniband+gpu:{gpu_limits}" if gpu_limits != "0" else "infiniband",
        mcp_servers=[server],
        metadata={
            "training_job": True,
            "infiniband": True,
            "gpu_count": int(gpu_limits) if gpu_limits != "0" else 0,
            "image": image_ref,
            "kind": "Pod",
            "cloud_origin": build_cloud_origin(
                provider=provider,
                service="kubernetes",
                resource_type="training-pod",
                resource_id=f"{pod_ns}/{pod_name}",
                resource_name=pod_name,
                project_id=project_id,
                raw_identity={"namespace": pod_ns, "pod": pod_name, "image": image_ref},
            ),
        },
    )
