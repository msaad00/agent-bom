"""GPU/AI compute infrastructure scanner — multi-vendor container and K8s discovery.

Discovers GPU-enabled workloads from running Docker containers and Kubernetes
clusters. No additional pip packages required — uses ``docker`` and ``kubectl``
CLI tools with subprocess (same pattern as coreweave.py and discovery/__init__.py).

Supported GPU vendors:
- **NVIDIA** (Linux): runtime, DeviceRequests, base images, CUDA/cuDNN labels/env
- **AMD ROCm** (Linux): /dev/kfd device mount, ROCR_VISIBLE_DEVICES env
- **Intel** (Linux): /dev/dri (without /dev/kfd), ONEAPI_DEVICE_SELECTOR env
- **Windows WDDM**: device class GUID 5B45201D-..., process isolation
- **K8s**: nvidia.com/gpu, amd.com/gpu, gpu.intel.com/i915, gpu.intel.com/xe

Detection sources:
- https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/docker-specialized.html
- https://rocm.docs.amd.com/projects/install-on-linux/en/latest/how-to/docker.html
- https://intel.github.io/intel-device-plugins-for-kubernetes/cmd/gpu_plugin/README.html
- https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/gpu-acceleration

Closes: #309, #471
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

logger = logging.getLogger(__name__)

# ─── Vendor detection constants ──────────────────────────────────────────────

# NVIDIA image prefixes — treated as GPU workloads
_NVIDIA_IMAGE_PREFIXES = (
    "nvcr.io/nvidia/",
    "nvcr.io/nim/",
    "nvidia/cuda",
    "nvidia/cudnn",
    "nvidia/tensorrt",
    "nvidia/tritonserver",
    "nvidia/pytorch",
    "nvidia/tensorflow",
)

# AMD ROCm image prefixes
_AMD_IMAGE_PREFIXES = (
    "rocm/",
    "amd/",
    "rocm/pytorch",
    "rocm/tensorflow",
    "rocm/rocm-terminal",
)

# Docker label keys that indicate CUDA/cuDNN version
_CUDA_LABEL_KEYS = (
    "com.nvidia.cuda.version",
    "com.nvidia.cudnn.version",
    "com.nvidia.cuda_version",
    "cuda_version",
    "nvidia_cuda_version",
)

# AMD ROCm env vars that indicate GPU usage
_AMD_ENV_VARS = ("ROCR_VISIBLE_DEVICES", "AMD_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES", "HSA_OVERRIDE_GFX_VERSION")

# Intel GPU env vars
_INTEL_ENV_VARS = ("ONEAPI_DEVICE_SELECTOR", "ZE_AFFINITY_MASK")

# NVIDIA env vars
_NVIDIA_ENV_VARS = ("NVIDIA_VISIBLE_DEVICES", "NVIDIA_DRIVER_CAPABILITIES")

# Windows GPU device class GUID (DirectX/WDDM passthrough)
# https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/gpu-acceleration
_WINDOWS_GPU_DEVICE_CLASS = "5B45201D-F2F2-4F3B-85BB-30FF1F953599"

# K8s resource keys for GPU requests (multi-vendor)
_K8S_GPU_RESOURCES = {
    "nvidia.com/gpu": "nvidia",
    "amd.com/gpu": "amd",
    "gpu.intel.com/i915": "intel",
    "gpu.intel.com/xe": "intel",
}

# Legacy single-vendor constant kept for backward compatibility
_K8S_GPU_RESOURCE = "nvidia.com/gpu"

# DCGM exporter default port
_DCGM_PORT = 9400
_DCGM_METRICS_PATH = "/metrics"
_DCGM_PROBE_TIMEOUT = 3.0


# ─── Data models ──────────────────────────────────────────────────────────────


@dataclass
class GpuContainer:
    """A running container that has GPU access or is a vendor GPU base image."""

    container_id: str
    name: str
    image: str
    status: str  # "running", "exited", etc.
    gpu_vendor: str  # "nvidia", "amd", "intel", "windows", "unknown"
    is_nvidia_base: bool
    cuda_version: str | None
    cudnn_version: str | None
    gpu_requested: bool  # explicit GPU device assignment
    labels: dict[str, str] = field(default_factory=dict)
    env_vars: list[str] = field(default_factory=list)  # names only, no values
    ports: list[str] = field(default_factory=list)


@dataclass
class DcgmEndpoint:
    """A discovered DCGM exporter endpoint."""

    host: str
    port: int
    url: str
    authenticated: bool  # False = unauthenticated metrics leak
    gpu_count: int | None
    sample_metric_keys: list[str] = field(default_factory=list)


@dataclass
class GpuNode:
    """A Kubernetes node with GPU resource capacity."""

    name: str
    gpu_vendor: str  # "nvidia", "amd", "intel", "unknown"
    gpu_capacity: int
    gpu_allocatable: int
    gpu_allocated: int
    cuda_driver_version: str | None
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class GpuInfraReport:
    """Aggregated GPU infrastructure inventory from a scan."""

    gpu_containers: list[GpuContainer]
    dcgm_endpoints: list[DcgmEndpoint]
    gpu_nodes: list[GpuNode]
    warnings: list[str]

    @property
    def total_gpu_containers(self) -> int:
        return len(self.gpu_containers)

    @property
    def unauthenticated_dcgm_count(self) -> int:
        return sum(1 for e in self.dcgm_endpoints if not e.authenticated)

    @property
    def nvidia_base_image_count(self) -> int:
        return sum(1 for c in self.gpu_containers if c.is_nvidia_base)

    @property
    def unique_cuda_versions(self) -> list[str]:
        versions = {c.cuda_version for c in self.gpu_containers if c.cuda_version}
        return sorted(versions)

    @property
    def vendor_breakdown(self) -> dict[str, int]:
        """Count GPU containers by vendor."""
        breakdown: dict[str, int] = {}
        for c in self.gpu_containers:
            breakdown[c.gpu_vendor] = breakdown.get(c.gpu_vendor, 0) + 1
        return breakdown

    @property
    def risk_summary(self) -> dict[str, Any]:
        return {
            "total_gpu_containers": self.total_gpu_containers,
            "nvidia_base_images": self.nvidia_base_image_count,
            "unique_cuda_versions": self.unique_cuda_versions,
            "vendor_breakdown": self.vendor_breakdown,
            "dcgm_endpoints": len(self.dcgm_endpoints),
            "unauthenticated_dcgm": self.unauthenticated_dcgm_count,
            "gpu_k8s_nodes": len(self.gpu_nodes),
        }


# ─── Docker discovery ─────────────────────────────────────────────────────────


def _run_docker(args: list[str], timeout: int = 30) -> Any:
    """Run a docker command and return parsed JSON output.

    Returns None on failure (docker not installed, permission denied, etc.)
    rather than raising — GPU discovery is always best-effort.
    """
    if not shutil.which("docker"):
        return None
    try:
        result = subprocess.run(
            ["docker"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def _is_nvidia_image(image: str) -> bool:
    """Return True if the image is an NVIDIA-published GPU base image."""
    img_lower = image.lower()
    return any(img_lower.startswith(p) for p in _NVIDIA_IMAGE_PREFIXES)


def _is_amd_image(image: str) -> bool:
    """Return True if the image is an AMD ROCm GPU base image."""
    img_lower = image.lower()
    return any(img_lower.startswith(p) for p in _AMD_IMAGE_PREFIXES)


def _extract_cuda_versions(labels: dict[str, str]) -> tuple[str | None, str | None]:
    """Extract CUDA and cuDNN versions from container/image labels."""
    cuda_version: str | None = None
    cudnn_version: str | None = None

    for key, value in labels.items():
        key_lower = key.lower()
        if "cuda" in key_lower and "cudnn" not in key_lower and not cuda_version:
            cuda_version = value.strip()
        elif "cudnn" in key_lower and not cudnn_version:
            cudnn_version = value.strip()

    return cuda_version, cudnn_version


def discover_docker_gpu_containers() -> tuple[list[GpuContainer], list[str]]:
    """Discover GPU-enabled containers from the local Docker daemon.

    Uses ``docker ps`` + ``docker inspect`` — no Docker SDK required.

    Returns:
        (containers, warnings)
    """
    containers: list[GpuContainer] = []
    warnings: list[str] = []

    if not shutil.which("docker"):
        return containers, ["docker not available — GPU container discovery skipped"]

    # List all running containers (plain text output, not JSON)
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}", "--no-trunc"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return containers, ["docker ps failed — Docker not running or no permission"]
        # Validate: container IDs are SHA256 hex strings (64 chars) — defense in depth
        container_ids = [
            cid.strip() for cid in result.stdout.splitlines() if cid.strip() and all(c in "0123456789abcdefABCDEF" for c in cid.strip())
        ]
    except (subprocess.TimeoutExpired, OSError) as exc:
        return containers, [f"Docker discovery skipped: {exc}"]

    if not container_ids:
        return containers, []

    # Inspect each container
    inspect_result = _run_docker(["inspect"] + container_ids, timeout=60)
    if not inspect_result or not isinstance(inspect_result, list):
        warnings.append("docker inspect failed — skipping container GPU analysis")
        return containers, warnings

    for info in inspect_result:
        try:
            cid = info.get("Id", "")[:12]
            name = (info.get("Name") or "").lstrip("/")
            image = (info.get("Config", {}) or {}).get("Image", "")
            status = (info.get("State", {}) or {}).get("Status", "unknown")

            labels: dict[str, str] = (info.get("Config", {}) or {}).get("Labels") or {}
            env_list: list[str] = (info.get("Config", {}) or {}).get("Env") or []

            # Extract env var names (never values — security)
            env_names = [e.split("=", 1)[0] for e in env_list if "=" in e]
            env_name_set = set(env_names)

            cuda_version, cudnn_version = _extract_cuda_versions(labels)

            # Also check env vars for CUDA hints
            if not cuda_version:
                for env in env_list:
                    if env.startswith("CUDA_VERSION="):
                        cuda_version = env.split("=", 1)[1].strip()
                    elif env.startswith("CUDNN_VERSION="):
                        cudnn_version = env.split("=", 1)[1].strip()

            # Check if GPU is explicitly assigned
            host_config = info.get("HostConfig", {}) or {}
            device_requests = host_config.get("DeviceRequests") or []
            gpu_requested = any(
                dr.get("Driver") in ("nvidia", "gpu")
                or dr.get("Capabilities")
                and any("gpu" in cap_list for cap_list in (dr.get("Capabilities") or []))
                for dr in device_requests
            )

            # Also check runtime
            runtime = host_config.get("Runtime", "")
            if runtime in ("nvidia", "nvidia-container-runtime"):
                gpu_requested = True

            # ─── Vendor detection ────────────────────────────────────────
            is_nvidia = _is_nvidia_image(image)
            is_amd = _is_amd_image(image)

            # Device mounts (AMD ROCm = /dev/kfd, Intel/AMD = /dev/dri)
            devices = host_config.get("Devices") or []
            device_paths = [d.get("PathOnHost", "") for d in devices if isinstance(d, dict)]

            has_kfd = any("/dev/kfd" in p for p in device_paths)
            has_dri = any("/dev/dri" in p for p in device_paths)
            has_amd_env = bool(env_name_set & set(_AMD_ENV_VARS))
            has_intel_env = bool(env_name_set & set(_INTEL_ENV_VARS))
            has_nvidia_env = bool(env_name_set & set(_NVIDIA_ENV_VARS))

            # Windows GPU: device class GUID + process isolation
            # https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/gpu-acceleration
            is_windows_gpu = any(_WINDOWS_GPU_DEVICE_CLASS.lower() in p.lower() for p in device_paths)

            # Determine vendor
            gpu_vendor = "unknown"
            if is_nvidia or gpu_requested or has_nvidia_env or cuda_version:
                gpu_vendor = "nvidia"
            elif has_kfd or is_amd or has_amd_env:
                gpu_vendor = "amd"
            elif is_windows_gpu:
                gpu_vendor = "windows"
            elif has_intel_env or (has_dri and not has_kfd and not is_nvidia):
                gpu_vendor = "intel"

            is_gpu = (
                is_nvidia
                or is_amd
                or gpu_requested
                or cuda_version
                or has_kfd
                or has_amd_env
                or has_intel_env
                or has_nvidia_env
                or is_windows_gpu
            )

            # Port bindings
            port_bindings = info.get("HostConfig", {}).get("PortBindings") or {}
            ports = list(port_bindings.keys())

            if is_gpu:
                containers.append(
                    GpuContainer(
                        container_id=cid,
                        name=name,
                        image=image,
                        status=status,
                        gpu_vendor=gpu_vendor,
                        is_nvidia_base=is_nvidia,
                        cuda_version=cuda_version,
                        cudnn_version=cudnn_version,
                        gpu_requested=gpu_requested,
                        labels=labels,
                        env_vars=env_names,
                        ports=ports,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Error parsing container info: %s", exc)
            continue

    return containers, warnings


# ─── Kubernetes discovery ─────────────────────────────────────────────────────


def _run_kubectl(args: list[str], context: str | None = None, timeout: int = 60) -> Any:
    """Run a kubectl command and return parsed JSON output. Returns None on failure."""
    if not shutil.which("kubectl"):
        return None
    cmd = ["kubectl"]
    if context:
        cmd.extend(["--context", context])
    cmd.extend(args + ["-o", "json"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def discover_k8s_gpu_nodes(
    context: str | None = None,
) -> tuple[list[GpuNode], list[str]]:
    """Discover Kubernetes nodes with GPU resources.

    Returns:
        (gpu_nodes, warnings)
    """
    nodes: list[GpuNode] = []
    warnings: list[str] = []

    node_list = _run_kubectl(["get", "nodes"], context=context)
    if node_list is None:
        return nodes, ["kubectl not available — K8s GPU node discovery skipped"]

    items = node_list.get("items") or []
    for node in items:
        try:
            name = (node.get("metadata") or {}).get("name", "")
            labels: dict[str, str] = (node.get("metadata") or {}).get("labels") or {}
            capacity: dict = (node.get("status") or {}).get("capacity") or {}
            allocatable: dict = (node.get("status") or {}).get("allocatable") or {}

            # Check all vendor GPU resources
            gpu_cap = 0
            gpu_alloc = 0
            gpu_vendor = "unknown"
            for resource_key, vendor in _K8S_GPU_RESOURCES.items():
                cap_str = capacity.get(resource_key, "0")
                alloc_str = allocatable.get(resource_key, "0")
                try:
                    cap_val = int(cap_str)
                    alloc_val = int(alloc_str)
                except ValueError:
                    continue
                if cap_val > 0:
                    gpu_cap += cap_val
                    gpu_alloc += alloc_val
                    gpu_vendor = vendor

            if gpu_cap == 0:
                continue  # not a GPU node

            # CUDA driver version from labels (NVIDIA-specific)
            cuda_driver = labels.get("nvidia.com/cuda.driver.major")
            cuda_minor = labels.get("nvidia.com/cuda.driver.minor")
            if cuda_driver and cuda_minor:
                cuda_driver = f"{cuda_driver}.{cuda_minor}"
            else:
                cuda_driver = labels.get("nvidia.com/cuda.driver-version")

            # Collect vendor-relevant labels
            gpu_label_keywords = ("nvidia", "amd", "gpu", "intel", "rocm")
            gpu_labels = {k: v for k, v in labels.items() if any(kw in k.lower() for kw in gpu_label_keywords)}

            nodes.append(
                GpuNode(
                    name=name,
                    gpu_vendor=gpu_vendor,
                    gpu_capacity=gpu_cap,
                    gpu_allocatable=gpu_alloc,
                    gpu_allocated=gpu_cap - gpu_alloc,  # rough estimate
                    cuda_driver_version=cuda_driver,
                    labels=gpu_labels,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Error parsing K8s node: %s", exc)
            continue

    return nodes, warnings


# ─── DCGM endpoint probing ────────────────────────────────────────────────────


async def probe_dcgm_endpoint(host: str, port: int = _DCGM_PORT) -> DcgmEndpoint | None:
    """Probe a potential DCGM exporter metrics endpoint.

    Returns DcgmEndpoint if metrics are accessible, None otherwise.
    Flags unauthenticated = True when metrics are returned without auth.
    """
    url = f"http://{host}:{port}{_DCGM_METRICS_PATH}"
    try:
        async with create_client(timeout=_DCGM_PROBE_TIMEOUT) as client:
            resp = await request_with_retry(client, "GET", url, max_attempts=1)
    except Exception:  # noqa: BLE001
        return None

    if resp is None or resp.status_code not in (200, 206):
        return None

    content = resp.text[:4096]  # first 4KB of metrics

    # DCGM metrics start with HELP/TYPE lines for DCGM_FI_ prefixed metrics
    is_dcgm = "DCGM_FI_" in content or "dcgm_" in content.lower()
    if not is_dcgm:
        return None

    # Count GPUs from DCGM_FI_DEV_COUNT if present
    gpu_count: int | None = None
    for line in content.splitlines():
        if line.startswith("DCGM_FI_DEV_COUNT{") and not line.startswith("#"):
            try:
                gpu_count = int(line.split()[-1])
                break
            except (ValueError, IndexError):
                pass

    # Extract some metric key names for inventory
    metric_keys = [line.split("{")[0].strip() for line in content.splitlines() if line.startswith("DCGM_FI_") and not line.startswith("#")][
        :10
    ]

    # Unauthenticated if we got 200 without any auth header being required
    return DcgmEndpoint(
        host=host,
        port=port,
        url=url,
        authenticated=resp.status_code == 401,
        gpu_count=gpu_count,
        sample_metric_keys=list(dict.fromkeys(metric_keys)),  # dedupe, preserve order
    )


async def probe_dcgm_from_containers(
    containers: list[GpuContainer],
) -> list[DcgmEndpoint]:
    """Probe DCGM on localhost and any containers that expose port 9400."""
    endpoints: list[DcgmEndpoint] = []

    hosts_to_probe: set[str] = {"localhost", "127.0.0.1"}

    for c in containers:
        for port_str in c.ports:
            if str(_DCGM_PORT) in port_str:
                hosts_to_probe.add("localhost")

    for host in hosts_to_probe:
        ep = await probe_dcgm_endpoint(host, _DCGM_PORT)
        if ep:
            endpoints.append(ep)

    return endpoints


# ─── Main entry point ─────────────────────────────────────────────────────────


async def scan_gpu_infra(
    k8s_context: str | None = None,
    probe_dcgm: bool = True,
) -> GpuInfraReport:
    """Discover GPU/AI compute infrastructure from Docker and Kubernetes.

    Args:
        k8s_context: kubectl context to use (default: current context).
        probe_dcgm: whether to probe DCGM exporter endpoints.

    Returns:
        GpuInfraReport with containers, K8s nodes, and DCGM endpoints.
    """
    all_warnings: list[str] = []

    # Docker container discovery
    docker_containers, docker_warnings = discover_docker_gpu_containers()
    all_warnings.extend(docker_warnings)

    # K8s node discovery
    k8s_nodes, k8s_warnings = discover_k8s_gpu_nodes(context=k8s_context)
    all_warnings.extend(k8s_warnings)

    # DCGM endpoint probing
    dcgm_endpoints: list[DcgmEndpoint] = []
    if probe_dcgm:
        try:
            dcgm_endpoints = await probe_dcgm_from_containers(docker_containers)
        except Exception as exc:  # noqa: BLE001
            logger.debug("DCGM probe error: %s", exc)
            all_warnings.append(f"DCGM probe skipped: {exc}")

    return GpuInfraReport(
        gpu_containers=docker_containers,
        dcgm_endpoints=dcgm_endpoints,
        gpu_nodes=k8s_nodes,
        warnings=all_warnings,
    )


# ─── Agent conversion (for scan output) ──────────────────────────────────────


def gpu_infra_to_agents(report: GpuInfraReport) -> list[Agent]:
    """Convert GpuInfraReport to Agent objects for inclusion in AIBOMReport.

    Each GPU container becomes an Agent with its image name as the MCP server.
    K8s GPU nodes appear as a synthetic "k8s-gpu-cluster" agent. Both shapes
    populate ``Agent.metadata["cloud_origin"]`` so the unified-graph builder
    can promote the underlying GPU asset (vendor, runtime, container/node id)
    into ``cloud_resource`` lineage nodes via the existing promoter in
    ``src/agent_bom/graph/builder.py``.
    """
    agents: list[Agent] = []

    for c in report.gpu_containers:
        # Build package list from CUDA/cuDNN versions
        packages: list[Package] = []
        if c.cuda_version:
            packages.append(Package(name="cuda-toolkit", version=c.cuda_version, ecosystem="container"))
        if c.cudnn_version:
            packages.append(Package(name="cudnn", version=c.cudnn_version, ecosystem="container"))

        server = MCPServer(
            name=c.image,
            command="",
            transport=TransportType.STDIO,
            packages=packages,
        )
        cloud_origin = {
            "provider": "gpu",
            "service": "container_runtime",
            "resource_type": c.gpu_vendor or "unknown",
            "resource_id": c.container_id,
            "resource_name": c.name or c.container_id,
            "scope": {
                "image": c.image,
                "gpu_requested": c.gpu_requested,
                "cuda_version": c.cuda_version,
                "cudnn_version": c.cudnn_version,
            },
        }
        agent = Agent(
            name=c.name or c.container_id,
            agent_type=AgentType.CUSTOM,
            config_path=f"docker://{c.container_id}",
            source="gpu_infra",
            mcp_servers=[server],
            metadata={"cloud_origin": cloud_origin},
        )
        agents.append(agent)

    # Aggregate K8s GPU nodes as a single agent. Lineage promotion happens at
    # the cluster level so dashboards see one cloud_resource per cluster, not
    # one per GPU node — node-level facts live in the scope envelope.
    if report.gpu_nodes:
        total_gpus = sum(n.gpu_capacity for n in report.gpu_nodes)
        vendors = sorted({n.gpu_vendor for n in report.gpu_nodes if n.gpu_vendor})
        node_server = MCPServer(
            name=f"k8s-gpu-cluster ({len(report.gpu_nodes)} nodes, {total_gpus} GPUs)",
            command="",
            transport=TransportType.STDIO,
            packages=[],
        )
        cloud_origin = {
            "provider": "gpu",
            "service": "kubernetes",
            "resource_type": vendors[0] if len(vendors) == 1 else "mixed" if vendors else "unknown",
            "resource_id": "k8s-gpu-cluster",
            "resource_name": "k8s-gpu-cluster",
            "scope": {
                "node_count": len(report.gpu_nodes),
                "gpu_capacity_total": total_gpus,
                "vendors": vendors,
            },
        }
        agents.append(
            Agent(
                name="k8s-gpu-cluster",
                agent_type=AgentType.CUSTOM,
                config_path="k8s://gpu-nodes",
                source="gpu_infra",
                mcp_servers=[node_server],
                metadata={"cloud_origin": cloud_origin},
            )
        )

    return agents
