"""CoreWeave cloud discovery — GPU VMs, NVIDIA NIM inference, InfiniBand training.

CoreWeave is NVIDIA's primary GPU cloud partner. Discovery uses ``kubectl``
to query CoreWeave-specific Kubernetes CRDs and standard K8s resources:

- **VirtualServer CRDs**: GPU VMs with H100/A100/L40S accelerators
- **InferenceService CRDs**: KServe model serving (vLLM, Triton)
- **NVIDIA NIM pods**: Containers from ``nvcr.io/nim/*``
- **InfiniBand training jobs**: Multi-node NCCL with ``rdma/ib`` resources

No additional pip packages required — ``kubectl`` with CoreWeave cluster
credentials is the only prerequisite.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_origin, build_package_purl, parse_container_image_package

logger = logging.getLogger(__name__)

# NVIDIA NIM image prefix — containers from NGC Inference Microservices
_NIM_IMAGE_PREFIX = "nvcr.io/nim/"

# Kubernetes CRD fully-qualified names
_CRD_VIRTUALSERVER = "virtualservers.virtualserver.coreweave.com"
_CRD_INFERENCESERVICE = "inferenceservices.serving.kserve.io"


def _kubectl(
    args: list[str],
    context: str | None = None,
    timeout: int = 60,
) -> dict:
    """Run a kubectl command and return parsed JSON output.

    Raises:
        CloudDiscoveryError: if kubectl is not installed or returns an error.
    """
    cmd = ["kubectl"]
    if context:
        cmd.extend(["--context", context])
    cmd.extend(args)
    cmd.extend(["-o", "json"])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    if result.returncode != 0:
        stderr = result.stderr.strip()[:200]
        raise CloudDiscoveryError(f"kubectl failed: {stderr}")

    return json.loads(result.stdout)


def discover(
    context: str | None = None,
    namespace: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover GPU workloads from CoreWeave Kubernetes clusters.

    Runs four discovery passes:
    1. VirtualServer CRDs — GPU VMs
    2. InferenceService CRDs — KServe model serving
    3. GPU pods — NVIDIA NIM container detection
    4. InfiniBand training jobs — multi-node NCCL

    Args:
        context: kubectl context name (defaults to current context).
        namespace: limit discovery to a specific namespace (default: all).

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.
    """
    if not shutil.which("kubectl"):
        return [], ["kubectl not found — install kubectl and configure CoreWeave cluster credentials"]

    agents: list[Agent] = []
    warnings: list[str] = []

    # ── VirtualServer CRDs ────────────────────────────────────────────
    try:
        vs_agents, vs_warns = _discover_virtual_servers(context, namespace)
        agents.extend(vs_agents)
        warnings.extend(vs_warns)
    except CloudDiscoveryError as exc:
        warnings.append(f"CoreWeave VirtualServer discovery: {exc}")
    except subprocess.TimeoutExpired:
        warnings.append("kubectl timed out during VirtualServer discovery")
    except Exception as exc:
        warnings.append(f"CoreWeave VirtualServer error: {exc}")

    # ── InferenceService CRDs ─────────────────────────────────────────
    try:
        is_agents, is_warns = _discover_inference_services(context, namespace)
        agents.extend(is_agents)
        warnings.extend(is_warns)
    except CloudDiscoveryError as exc:
        warnings.append(f"CoreWeave InferenceService discovery: {exc}")
    except subprocess.TimeoutExpired:
        warnings.append("kubectl timed out during InferenceService discovery")
    except Exception as exc:
        warnings.append(f"CoreWeave InferenceService error: {exc}")

    # ── GPU pods + NIM detection ──────────────────────────────────────
    try:
        gpu_agents, gpu_warns = _discover_gpu_pods(context, namespace)
        agents.extend(gpu_agents)
        warnings.extend(gpu_warns)
    except CloudDiscoveryError as exc:
        warnings.append(f"CoreWeave GPU pod discovery: {exc}")
    except subprocess.TimeoutExpired:
        warnings.append("kubectl timed out during GPU pod discovery")
    except Exception as exc:
        warnings.append(f"CoreWeave GPU pod error: {exc}")

    # ── InfiniBand training jobs ──────────────────────────────────────
    try:
        ib_agents, ib_warns = _discover_infiniband_jobs(context, namespace)
        agents.extend(ib_agents)
        warnings.extend(ib_warns)
    except CloudDiscoveryError as exc:
        warnings.append(f"CoreWeave InfiniBand discovery: {exc}")
    except subprocess.TimeoutExpired:
        warnings.append("kubectl timed out during InfiniBand discovery")
    except Exception as exc:
        warnings.append(f"CoreWeave InfiniBand error: {exc}")

    # Per-run discovery envelope (#2083 PR B). CoreWeave reads through kubectl
    # against the user's kubeconfig context; the kube RBAC verbs we exercise
    # are documented here so operators can audit the role bindings.
    scope: list[str] = []
    if context:
        scope.append(f"coreweave:context/{context}")
    if namespace:
        scope.append(f"coreweave:namespace/{namespace}")
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=tuple(scope),
        permissions_used=(
            "kube:virtualservers.virtualization.coreweave.com:list",
            "kube:inferenceservices.serving.kserve.io:list",
            "kube:pods:list",
            "kube:jobs.batch:list",
        ),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )
    return agents, warnings


# ── VirtualServer CRDs ────────────────────────────────────────────────────


def _discover_virtual_servers(
    context: str | None,
    namespace: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover CoreWeave VirtualServer GPU VMs."""
    agents: list[Agent] = []
    warnings: list[str] = []

    ns_args = ["-n", namespace] if namespace else ["-A"]
    try:
        data = _kubectl(
            ["get", _CRD_VIRTUALSERVER, *ns_args],
            context=context,
        )
    except CloudDiscoveryError:
        # CRD not installed — not a CoreWeave cluster or no VirtualServers
        return agents, warnings

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        region = spec.get("region", meta.get("labels", {}).get("topology.kubernetes.io/region", ""))

        # Extract GPU info from resources
        gpu_spec = spec.get("resources", {}).get("gpu", {})
        gpu_type = gpu_spec.get("type", "")
        gpu_count = gpu_spec.get("count", 0)

        server = MCPServer(
            name=f"coreweave-gpu:{ns}/{name}",
            transport=TransportType.UNKNOWN,
        )

        agent = Agent(
            name=f"coreweave-gpu:{ns}/{name}",
            agent_type=AgentType.CUSTOM,
            config_path=f"coreweave://virtualserver/{ns}/{name}",
            source="coreweave-gpu",
            version=f"gpu:{gpu_type}x{gpu_count}" if gpu_type else "gpu-vm",
            mcp_servers=[server],
            metadata={
                "gpu_type": gpu_type,
                "gpu_count": gpu_count,
                "region": region,
                "kind": "VirtualServer",
                "cloud_origin": build_cloud_origin(
                    provider="coreweave",
                    service="kubernetes",
                    resource_type="virtual-server",
                    resource_id=f"{ns}/{name}",
                    resource_name=name,
                    location=region or None,
                    raw_identity={"namespace": ns, "name": name, "kind": "VirtualServer"},
                ),
            },
        )
        agents.append(agent)

    return agents, warnings


# ── InferenceService CRDs ─────────────────────────────────────────────────


def _discover_inference_services(
    context: str | None,
    namespace: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover KServe InferenceServices on CoreWeave."""
    agents: list[Agent] = []
    warnings: list[str] = []

    ns_args = ["-n", namespace] if namespace else ["-A"]
    try:
        data = _kubectl(
            ["get", _CRD_INFERENCESERVICE, *ns_args],
            context=context,
        )
    except CloudDiscoveryError:
        return agents, warnings

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")

        # Extract predictor container info
        predictor = spec.get("predictor", {})
        containers = predictor.get("containers", [])
        runtime_image = ""
        runtime_name = ""
        if containers:
            runtime_image = containers[0].get("image", "")
            runtime_name = containers[0].get("name", "")

        # Detect serving runtime (vLLM, Triton, TGI)
        runtime = _detect_serving_runtime(runtime_image, runtime_name)

        # Check if it's an NVIDIA NIM image
        is_nim = runtime_image.startswith(_NIM_IMAGE_PREFIX)
        nim_model = ""
        if is_nim:
            nim_model = runtime_image.removeprefix(_NIM_IMAGE_PREFIX).split(":")[0]

        # Extract serving URL from status
        status = item.get("status", {})
        serving_url = status.get("url", "")

        packages: list[Package] = []
        if runtime_image:
            image_parts = parse_container_image_package(runtime_image)
            if image_parts:
                packages.append(
                    Package(
                        name=image_parts[0],
                        version=image_parts[1],
                        ecosystem="container-image",
                        purl=build_package_purl(ecosystem="container-image", name=image_parts[0], version=image_parts[1]),
                    )
                )

        server = MCPServer(
            name=f"coreweave-inference:{ns}/{name}",
            transport=TransportType.UNKNOWN,
            url=serving_url,
            packages=packages,
        )

        metadata: dict = {
            "runtime": runtime,
            "serving_url": serving_url,
            "kind": "InferenceService",
            "cloud_origin": build_cloud_origin(
                provider="coreweave",
                service="kubernetes",
                resource_type="inference-service",
                resource_id=f"{ns}/{name}",
                resource_name=name,
                raw_identity={"namespace": ns, "name": name, "kind": "InferenceService", "image": runtime_image},
            ),
        }
        if is_nim:
            metadata["is_nim"] = True
            metadata["nim_model"] = nim_model

        agent = Agent(
            name=f"coreweave-inference:{ns}/{name}",
            agent_type=AgentType.CUSTOM,
            config_path=f"coreweave://inferenceservice/{ns}/{name}",
            source="coreweave-inference",
            version=runtime or "inference",
            mcp_servers=[server],
            metadata=metadata,
        )
        agents.append(agent)

    return agents, warnings


# ── GPU Pods + NIM Detection ──────────────────────────────────────────────


def _discover_gpu_pods(
    context: str | None,
    namespace: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover pods requesting nvidia.com/gpu and detect NVIDIA NIM containers."""
    agents: list[Agent] = []
    warnings: list[str] = []

    ns_args = ["-n", namespace] if namespace else ["-A"]
    data = _kubectl(["get", "pods", *ns_args], context=context)

    seen_images: set[str] = set()

    for pod in data.get("items", []):
        meta = pod.get("metadata", {})
        pod_name = meta.get("name", "unknown")
        pod_ns = meta.get("namespace", "default")

        for container in pod.get("spec", {}).get("containers", []):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            requests_res = resources.get("requests", {})

            gpu_limit = str(limits.get("nvidia.com/gpu", "0"))
            gpu_request = str(requests_res.get("nvidia.com/gpu", "0"))

            if gpu_limit == "0" and gpu_request == "0":
                continue

            image_ref = container.get("image", "").strip()
            if not image_ref or image_ref in seen_images:
                continue
            seen_images.add(image_ref)

            gpu_count = int(gpu_limit) if gpu_limit != "0" else int(gpu_request)
            is_nim = image_ref.startswith(_NIM_IMAGE_PREFIX)
            nim_model = ""
            if is_nim:
                nim_model = image_ref.removeprefix(_NIM_IMAGE_PREFIX).split(":")[0]

            image_parts = parse_container_image_package(image_ref)
            packages = (
                [
                    Package(
                        name=image_parts[0],
                        version=image_parts[1],
                        ecosystem="container-image",
                        purl=build_package_purl(ecosystem="container-image", name=image_parts[0], version=image_parts[1]),
                    )
                ]
                if image_parts
                else []
            )

            server = MCPServer(
                name=f"coreweave-gpu-pod:{pod_ns}/{pod_name}",
                command="docker",
                args=["run", image_ref],
                transport=TransportType.STDIO,
                packages=packages,
            )

            metadata: dict = {
                "gpu_count": gpu_count,
                "image": image_ref,
                "kind": "Pod",
                "cloud_origin": build_cloud_origin(
                    provider="coreweave",
                    service="kubernetes",
                    resource_type="gpu-pod",
                    resource_id=f"{pod_ns}/{pod_name}",
                    resource_name=pod_name,
                    raw_identity={"namespace": pod_ns, "pod": pod_name, "image": image_ref},
                ),
            }
            if is_nim:
                metadata["is_nim"] = True
                metadata["nim_model"] = nim_model

            agent = Agent(
                name=f"coreweave-gpu-pod:{pod_ns}/{pod_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"coreweave://pod/{pod_ns}/{pod_name}",
                source="coreweave-gpu",
                version=f"nim:{nim_model}" if is_nim else f"gpu:{gpu_count}",
                mcp_servers=[server],
                metadata=metadata,
            )
            agents.append(agent)

    return agents, warnings


# ── InfiniBand Training Jobs ─────────────────────────────────────────────


def _discover_infiniband_jobs(
    context: str | None,
    namespace: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover multi-node training jobs using InfiniBand (rdma/ib resources)."""
    agents: list[Agent] = []
    warnings: list[str] = []

    ns_args = ["-n", namespace] if namespace else ["-A"]
    data = _kubectl(["get", "pods", *ns_args], context=context)

    seen_jobs: set[str] = set()

    for pod in data.get("items", []):
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

            packages: list[Package] = []
            if image_ref:
                image_parts = parse_container_image_package(image_ref)
                if image_parts:
                    packages.append(
                        Package(
                            name=image_parts[0],
                            version=image_parts[1],
                            ecosystem="container-image",
                            purl=build_package_purl(ecosystem="container-image", name=image_parts[0], version=image_parts[1]),
                        )
                    )

            server = MCPServer(
                name=f"coreweave-training:{pod_ns}/{pod_name}",
                transport=TransportType.UNKNOWN,
                packages=packages,
            )

            agent = Agent(
                name=f"coreweave-training:{pod_ns}/{pod_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"coreweave://training/{pod_ns}/{pod_name}",
                source="coreweave-training",
                version=f"infiniband+gpu:{gpu_limits}" if gpu_limits != "0" else "infiniband",
                mcp_servers=[server],
                metadata={
                    "training_job": True,
                    "infiniband": True,
                    "gpu_count": int(gpu_limits) if gpu_limits != "0" else 0,
                    "image": image_ref,
                    "kind": "Pod",
                    "cloud_origin": build_cloud_origin(
                        provider="coreweave",
                        service="kubernetes",
                        resource_type="training-pod",
                        resource_id=f"{pod_ns}/{pod_name}",
                        resource_name=pod_name,
                        raw_identity={"namespace": pod_ns, "pod": pod_name, "image": image_ref},
                    ),
                },
            )
            agents.append(agent)

    return agents, warnings


# ── Helpers ───────────────────────────────────────────────────────────────


def _detect_serving_runtime(image: str, container_name: str) -> str:
    """Detect the serving runtime from image or container name."""
    combined = f"{image} {container_name}".lower()
    if "vllm" in combined:
        return "vllm"
    if "triton" in combined:
        return "triton"
    if "tgi" in combined or "text-generation-inference" in combined:
        return "tgi"
    if _NIM_IMAGE_PREFIX.rstrip("/") in combined:
        return "nim"
    return ""
