"""RunPod cloud discovery — GPU pods and serverless endpoints.

RunPod is widely used for on-demand GPU workloads and fine-tuning.
Discovery uses the RunPod GraphQL API.

Authentication: ``RUNPOD_API_KEY`` environment variable or ``--runpod-api-key`` CLI flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_origin, build_package_purl

logger = logging.getLogger(__name__)

_GRAPHQL_URL = "https://api.runpod.io/graphql"
_API_TIMEOUT = 15

_PODS_QUERY = """
query {
  myself {
    pods {
      id
      name
      imageName
      podType
      gpuCount
      costPerHr
      runtime { gpus { id gpuUtilPercent memoryUtilPercent } }
      machine { podHostId gpuDisplayName location }
      desiredStatus
    }
  }
}
"""

_ENDPOINTS_QUERY = """
query {
  myself {
    serverlessDiscount { discountFactor }
    endpoints {
      id
      name
      gpuIds
      idleTimeout
      scalerType
      workersMax
      workersMin
      templateId
    }
  }
}
"""


def _graphql(query: str, api_key: str) -> dict:
    try:
        import requests
    except ImportError as exc:
        raise CloudDiscoveryError("requests is required for RunPod discovery. Install with: pip install requests") from exc

    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    resp = requests.post(_GRAPHQL_URL, json={"query": query}, headers=headers, timeout=_API_TIMEOUT)
    if resp.status_code == 401:
        raise CloudDiscoveryError("RunPod: invalid API key (HTTP 401)")
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise CloudDiscoveryError(f"RunPod GraphQL error: {data['errors']}")
    return data.get("data", {})


def discover(
    api_key: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover RunPod GPU pods and serverless endpoints.

    Args:
        api_key: RunPod API key. Falls back to ``RUNPOD_API_KEY`` env var.

    Returns:
        (agents, warnings) tuple.
    """
    try:
        import requests  # noqa: F401
    except ImportError:
        return [], ["RunPod discovery requires 'requests'. Install with: pip install requests"]

    resolved_key = api_key or os.environ.get("RUNPOD_API_KEY", "")
    if not resolved_key:
        return [], ["RUNPOD_API_KEY not set. Provide --runpod-api-key or set the RUNPOD_API_KEY env var."]

    agents: list[Agent] = []
    warnings: list[str] = []

    # ── GPU Pods ──────────────────────────────────────────────────────────────
    try:
        data = _graphql(_PODS_QUERY, resolved_key)
        pods = data.get("myself", {}).get("pods", []) or []

        for pod in pods:
            pod_id = pod.get("id", "unknown")
            pod_name = pod.get("name", pod_id)
            image = pod.get("imageName", "")
            gpu_count = pod.get("gpuCount", 0)
            status = pod.get("desiredStatus", "unknown")
            machine = pod.get("machine") or {}
            gpu_model = machine.get("gpuDisplayName", "GPU")
            location = machine.get("location", "unknown")

            packages = []
            container_sbom = None
            if image:
                img_name = image.split(":")[0].replace("/", "-")
                img_version = image.split(":")[-1] if ":" in image else "latest"
                packages.append(
                    Package(
                        name=img_name,
                        version=img_version,
                        ecosystem="container-image",
                        purl=build_package_purl(
                            ecosystem="container-image",
                            name=img_name,
                            version=img_version,
                        ),
                    )
                )
                try:
                    from agent_bom.cloud.container_sbom import scan_container_image

                    container_sbom = scan_container_image(image).to_dict()
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Container SBOM scan skipped for %s: %s", image, exc)

            server = MCPServer(
                name=f"runpod:{pod_name}",
                transport=TransportType.UNKNOWN,
                packages=packages,
                tools=[MCPTool(name=pod_name, description=f"RunPod {gpu_model}x{gpu_count} ({location})")],
            )

            agent = Agent(
                name=f"runpod:{pod_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"runpod://pod/{pod_id}",
                source="runpod-pod",
                version=status,
                mcp_servers=[server],
                metadata={
                    "gpu_type": gpu_model,
                    "gpu_count": gpu_count,
                    "location": location,
                    "image": image,
                    "container_sbom": container_sbom,
                    "cloud_origin": build_cloud_origin(
                        provider="runpod",
                        service="compute",
                        resource_type="gpu-pod",
                        resource_id=pod_id,
                        resource_name=pod_name,
                        raw_identity={"id": pod_id, "image": image, "location": location},
                    ),
                },
            )
            agents.append(agent)

    except CloudDiscoveryError as exc:
        warnings.append(str(exc))
    except Exception as exc:
        warnings.append(f"RunPod pods discovery error: {exc}")

    # ── Serverless Endpoints ──────────────────────────────────────────────────
    try:
        data = _graphql(_ENDPOINTS_QUERY, resolved_key)
        endpoints = data.get("myself", {}).get("endpoints", []) or []

        for ep in endpoints:
            ep_id = ep.get("id", "unknown")
            ep_name = ep.get("name", ep_id)
            gpu_ids = ep.get("gpuIds", "")

            server = MCPServer(
                name=f"runpod-serverless:{ep_name}",
                transport=TransportType.SSE,
                url=f"https://api.runpod.ai/v2/{ep_id}/run",
                tools=[MCPTool(name=ep_name, description=f"RunPod serverless endpoint ({gpu_ids})")],
            )

            agent = Agent(
                name=f"runpod-serverless:{ep_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"runpod://serverless/{ep_id}",
                source="runpod-serverless",
                version="serverless",
                mcp_servers=[server],
                metadata={
                    "gpu_ids": gpu_ids,
                    "endpoint_id": ep_id,
                    "cloud_origin": build_cloud_origin(
                        provider="runpod",
                        service="serverless",
                        resource_type="endpoint",
                        resource_id=ep_id,
                        resource_name=ep_name,
                        raw_identity={"id": ep_id, "gpu_ids": gpu_ids},
                    ),
                },
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"RunPod serverless discovery error: {exc}")

    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=("runpod:all",),
        permissions_used=("runpod:pods:read", "runpod:serverless:read"),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    logger.info("RunPod: discovered %d resource(s)", len(agents))
    return agents, warnings
