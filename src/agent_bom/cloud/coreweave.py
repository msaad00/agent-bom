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
from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import CloudDiscoveryError
from .k8s_gpu_common import build_training_agent, container_image_packages, iter_gpu_containers, iter_infiniband_pods
from .normalization import build_cloud_origin

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

    # Each pass is isolated: a failure becomes a warning and the next pass runs.
    stages = (
        ("VirtualServer", _discover_virtual_servers),
        ("InferenceService", _discover_inference_services),
        ("GPU pod", _discover_gpu_pods),
        ("InfiniBand", _discover_infiniband_jobs),
    )
    for label, stage in stages:
        try:
            stage_agents, stage_warns = stage(context, namespace)
            agents.extend(stage_agents)
            warnings.extend(stage_warns)
        except CloudDiscoveryError as exc:
            warnings.append(f"CoreWeave {label} discovery: {exc}")
        except subprocess.TimeoutExpired:
            warnings.append(f"kubectl timed out during {label} discovery")
        except Exception as exc:
            warnings.append(f"CoreWeave {label} error: {exc}")

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
        agents.append(_inference_service_agent(item))

    return agents, warnings


def _inference_service_agent(item: dict) -> Agent:
    """Build the agent for one KServe InferenceService item."""
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

    server = MCPServer(
        name=f"coreweave-inference:{ns}/{name}",
        transport=TransportType.UNKNOWN,
        url=serving_url,
        packages=container_image_packages(runtime_image),
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

    return Agent(
        name=f"coreweave-inference:{ns}/{name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"coreweave://inferenceservice/{ns}/{name}",
        source="coreweave-inference",
        version=runtime or "inference",
        mcp_servers=[server],
        metadata=metadata,
    )


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

    for pod_ns, pod_name, _container, image_ref, gpu_limit, gpu_request in iter_gpu_containers(data.get("items", [])):
        agents.append(_gpu_pod_agent(pod_ns, pod_name, image_ref, str(gpu_limit), str(gpu_request)))

    return agents, warnings


def _gpu_pod_agent(pod_ns: str, pod_name: str, image_ref: str, gpu_limit: str, gpu_request: str) -> Agent:
    """Build the agent for one GPU container, flagging NVIDIA NIM images."""
    gpu_count = int(gpu_limit) if gpu_limit != "0" else int(gpu_request)
    is_nim = image_ref.startswith(_NIM_IMAGE_PREFIX)
    nim_model = ""
    if is_nim:
        nim_model = image_ref.removeprefix(_NIM_IMAGE_PREFIX).split(":")[0]

    server = MCPServer(
        name=f"coreweave-gpu-pod:{pod_ns}/{pod_name}",
        command="docker",
        args=["run", image_ref],
        transport=TransportType.STDIO,
        packages=container_image_packages(image_ref),
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

    return Agent(
        name=f"coreweave-gpu-pod:{pod_ns}/{pod_name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"coreweave://pod/{pod_ns}/{pod_name}",
        source="coreweave-gpu",
        version=f"nim:{nim_model}" if is_nim else f"gpu:{gpu_count}",
        mcp_servers=[server],
        metadata=metadata,
    )


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

    for pod_ns, pod_name, image_ref, gpu_limits in iter_infiniband_pods(data.get("items", [])):
        agents.append(
            build_training_agent(
                provider="coreweave",
                pod_ns=pod_ns,
                pod_name=pod_name,
                image_ref=image_ref,
                gpu_limits=gpu_limits,
                config_path=f"coreweave://training/{pod_ns}/{pod_name}",
            )
        )

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
