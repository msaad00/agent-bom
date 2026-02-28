"""Nebius cloud discovery — GPU cloud AI workloads, AI Studio, and compute instances.

Requires ``requests``.  Install with::

    pip install 'agent-bom[nebius]'

Authentication uses Nebius credentials (NEBIUS_API_KEY + NEBIUS_PROJECT_ID env vars).
Nebius does not have an official Python SDK, so all API calls use REST via requests.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)

# AI workload image patterns (lowercase) — used to identify GPU/AI instances
_AI_IMAGE_PATTERNS = ("nvidia", "cuda", "pytorch", "tensorflow", "triton", "vllm", "tgi", "deepspeed", "nemo")

_API_TIMEOUT = 15


def _nebius_get(url: str, api_key: str, params: dict | None = None) -> dict:
    """Make an authenticated GET request to a Nebius REST API endpoint."""
    import requests

    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    resp = requests.get(url, headers=headers, params=params, timeout=_API_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def discover(
    api_key: str | None = None,
    project_id: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI workloads from Nebius GPU cloud.

    Discovers AI Studio inference endpoints, GPU compute instances,
    Managed K8s GPU pods, and container services.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``requests`` is not installed.
    """
    try:
        import requests  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError("requests is required for Nebius discovery. Install with: pip install 'agent-bom[nebius]'")

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_key = api_key or os.environ.get("NEBIUS_API_KEY", "")
    resolved_project = project_id or os.environ.get("NEBIUS_PROJECT_ID", "")

    if not resolved_key:
        warnings.append("NEBIUS_API_KEY not set. Provide --nebius-api-key or set the NEBIUS_API_KEY env var.")
        return agents, warnings

    if not resolved_project:
        warnings.append("NEBIUS_PROJECT_ID not set. Provide --nebius-project-id or set the NEBIUS_PROJECT_ID env var.")
        return agents, warnings

    # ── AI Studio inference endpoints ─────────────────────────────────────
    try:
        ai_agents, ai_warns = _discover_ai_studio(resolved_key, resolved_project)
        agents.extend(ai_agents)
        warnings.extend(ai_warns)
    except Exception as exc:
        warnings.append(f"Nebius AI Studio discovery error: {exc}")

    # ── GPU compute instances ─────────────────────────────────────────────
    try:
        gpu_agents, gpu_warns = _discover_gpu_instances(resolved_key, resolved_project)
        agents.extend(gpu_agents)
        warnings.extend(gpu_warns)
    except Exception as exc:
        warnings.append(f"Nebius GPU instance discovery error: {exc}")

    # ── K8s GPU pods ──────────────────────────────────────────────────────
    try:
        k8s_agents, k8s_warns = _discover_k8s_gpu_pods(resolved_key, resolved_project)
        agents.extend(k8s_agents)
        warnings.extend(k8s_warns)
    except Exception as exc:
        warnings.append(f"Nebius K8s GPU pod discovery error: {exc}")

    # ── Container services ────────────────────────────────────────────────
    try:
        cs_agents, cs_warns = _discover_container_services(resolved_key, resolved_project)
        agents.extend(cs_agents)
        warnings.extend(cs_warns)
    except Exception as exc:
        warnings.append(f"Nebius container service discovery error: {exc}")

    return agents, warnings


# ── AI Studio ─────────────────────────────────────────────────────────────


def _discover_ai_studio(
    api_key: str,
    project_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Nebius AI Studio inference endpoints via REST API.

    Calls ``https://api.ai.nebius.cloud/v1/models`` to list deployed
    model endpoints and creates an Agent for each one.
    """
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        data = _nebius_get(
            "https://api.ai.nebius.cloud/v1/models",
            api_key,
            params={"project_id": project_id},
        )

        models = data.get("models", data.get("data", []))

        for model in models:
            model_id = model.get("id", "unknown")
            model_name = model.get("name", model_id)
            model_version = model.get("version", model.get("model_version", "latest"))
            status = model.get("status", model.get("state", "UNKNOWN"))

            tools = [
                MCPTool(
                    name=model_name,
                    description=f"Nebius AI Studio model — status:{status}, version:{model_version}",
                )
            ]

            packages = [
                Package(
                    name=model_name,
                    version=str(model_version),
                    ecosystem="nebius-ai-studio",
                )
            ]

            server = MCPServer(
                name=f"nebius-ai-studio:{model_name}",
                transport=TransportType.UNKNOWN,
                url=f"https://api.ai.nebius.cloud/v1/models/{model_id}",
                tools=tools,
                packages=packages,
                env={"NEBIUS_API_KEY": "***REDACTED***"},
            )

            agent = Agent(
                name=f"nebius-ai-studio:{model_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"nebius://{project_id}/ai-studio/{model_id}",
                source="nebius-ai-studio",
                version=f"{status} (v{model_version})",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Nebius AI Studio models: {exc}")

    return agents, warnings


# ── GPU Compute Instances ─────────────────────────────────────────────────


def _discover_gpu_instances(
    api_key: str,
    project_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Nebius compute instances with GPU accelerators.

    Calls ``https://compute.api.nebius.cloud/v1/instances`` and filters
    for GPU-equipped instances.  Instances running AI workload images
    (NVIDIA, CUDA, PyTorch, TensorFlow, etc.) are flagged.
    """
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        data = _nebius_get(
            "https://compute.api.nebius.cloud/v1/instances",
            api_key,
            params={"project_id": project_id},
        )

        instances = data.get("instances", data.get("data", []))

        for inst in instances:
            inst_id = inst.get("id", "unknown")
            inst_name = inst.get("name", inst_id)
            platform_id = inst.get("platform_id", "")
            status = inst.get("status", "UNKNOWN")

            # Filter for GPU instances
            resources = inst.get("resources", {})
            gpu_count = resources.get("gpus", resources.get("gpu_count", 0))
            is_gpu = gpu_count > 0 or "gpu" in platform_id.lower()

            if not is_gpu:
                continue

            # Check boot disk image for AI workload patterns
            boot_disk = inst.get("boot_disk", {})
            image_id = boot_disk.get("image_id", "")
            image_name = boot_disk.get("image_name", image_id).lower()
            is_ai_workload = any(pat in image_name for pat in _AI_IMAGE_PATTERNS)

            gpu_type = resources.get("gpu_type", platform_id)
            desc_parts = [f"GPU:{gpu_type}x{gpu_count}", f"status:{status}"]
            if is_ai_workload:
                desc_parts.append(f"image:{boot_disk.get('image_name', image_id)}")

            tools = [
                MCPTool(
                    name=inst_name,
                    description=f"Nebius GPU instance — {', '.join(desc_parts)}",
                )
            ]

            packages: list[Package] = []
            if is_ai_workload:
                packages.append(
                    Package(
                        name=boot_disk.get("image_name", image_id),
                        version="detected",
                        ecosystem="nebius-compute-image",
                    )
                )

            server = MCPServer(
                name=f"nebius-gpu:{inst_name}",
                transport=TransportType.UNKNOWN,
                tools=tools,
                packages=packages,
                env={"NEBIUS_INSTANCE_ID": inst_id},
            )

            agent = Agent(
                name=f"nebius-gpu:{inst_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"nebius://{project_id}/compute/{inst_id}",
                source="nebius-gpu",
                version=status,
                mcp_servers=[server],
                metadata={"gpu_count": gpu_count, "gpu_type": gpu_type, "ai_workload": is_ai_workload},
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Nebius GPU instances: {exc}")

    return agents, warnings


# ── K8s GPU Pods ──────────────────────────────────────────────────────────


def _discover_k8s_gpu_pods(
    api_key: str,
    project_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover GPU pods in Nebius Managed Kubernetes clusters.

    Uses ``kubectl`` (same pattern as ``agent_bom.k8s``) to list pods
    requesting ``nvidia.com/gpu`` resources, then extracts container images.
    Requires kubectl configured with Nebius cluster credentials.
    """
    agents: list[Agent] = []
    warnings: list[str] = []

    if not shutil.which("kubectl"):
        logger.debug("kubectl not found — skipping Nebius K8s GPU pod discovery")
        return agents, warnings

    try:
        result = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            warnings.append(f"kubectl failed for Nebius K8s GPU pods: {result.stderr.strip()[:200]}")
            return agents, warnings

        data = json.loads(result.stdout)
        seen_images: set[str] = set()

        for pod in data.get("items", []):
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            pod_ns = pod.get("metadata", {}).get("namespace", "default")

            # Check all container types for GPU resource requests
            container_lists = [
                pod.get("spec", {}).get("containers", []),
                pod.get("spec", {}).get("initContainers", []),
            ]

            for container_list in container_lists:
                for container in container_list:
                    resources = container.get("resources", {})
                    limits = resources.get("limits", {})
                    requests_res = resources.get("requests", {})

                    gpu_limit = limits.get("nvidia.com/gpu", "0")
                    gpu_request = requests_res.get("nvidia.com/gpu", "0")

                    if str(gpu_limit) == "0" and str(gpu_request) == "0":
                        continue

                    image_ref = container.get("image", "").strip()
                    container_name = container.get("name", "unknown")

                    if not image_ref or image_ref in seen_images:
                        continue
                    seen_images.add(image_ref)

                    packages = [
                        Package(
                            name=image_ref.split("/")[-1].split(":")[0],
                            version=image_ref.split(":")[-1] if ":" in image_ref else "latest",
                            ecosystem="container-image",
                        )
                    ]

                    server = MCPServer(
                        name=f"nebius-k8s-gpu:{pod_ns}/{pod_name}/{container_name}",
                        command="docker",
                        args=["run", image_ref],
                        transport=TransportType.STDIO,
                        packages=packages,
                    )

                    agent = Agent(
                        name=f"nebius-k8s-gpu:{pod_ns}/{pod_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"nebius://{project_id}/k8s-gpu/{pod_ns}/{pod_name}",
                        source="nebius-k8s-gpu",
                        version=f"gpu-request:{gpu_request or gpu_limit}",
                        mcp_servers=[server],
                        metadata={"image": image_ref, "container": container_name},
                    )
                    agents.append(agent)

    except json.JSONDecodeError as exc:
        warnings.append(f"kubectl produced invalid JSON for GPU pods: {exc}")
    except subprocess.TimeoutExpired:
        warnings.append("kubectl timed out during Nebius K8s GPU pod discovery")
    except Exception as exc:
        warnings.append(f"Nebius K8s GPU pod discovery failed: {exc}")

    return agents, warnings


# ── Container Services ────────────────────────────────────────────────────


def _discover_container_services(
    api_key: str,
    project_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Nebius container services and their images via REST API."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        data = _nebius_get(
            "https://serverless.api.nebius.cloud/v1/containers",
            api_key,
            params={"project_id": project_id},
        )

        services = data.get("containers", data.get("data", []))

        for svc in services:
            svc_id = svc.get("id", "unknown")
            svc_name = svc.get("name", svc_id)
            image = svc.get("image", "")

            if image:
                server = MCPServer(
                    name=f"nebius-container:{svc_name}",
                    command="docker",
                    args=["run", str(image)],
                    transport=TransportType.STDIO,
                )
            else:
                server = MCPServer(
                    name=f"nebius-container:{svc_name}",
                    transport=TransportType.UNKNOWN,
                )

            agent = Agent(
                name=f"nebius-container:{svc_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"nebius://{project_id}/containers/{svc_id}",
                source="nebius-container",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Nebius container services: {exc}")

    return agents, warnings
