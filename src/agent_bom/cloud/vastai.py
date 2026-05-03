"""Vast.ai cloud discovery — rented GPU instances.

Vast.ai is a GPU marketplace used for burst fine-tuning and model serving.
Discovery uses the Vast.ai REST API to enumerate rented instances.

Authentication: ``VASTAI_API_KEY`` environment variable or ``--vastai-api-key`` CLI flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_origin, build_package_purl

logger = logging.getLogger(__name__)

_API_BASE = "https://console.vast.ai/api/v0"
_API_TIMEOUT = 15


def _vast_get(path: str, api_key: str) -> dict | list:
    try:
        import requests
    except ImportError as exc:
        raise CloudDiscoveryError("requests is required for Vast.ai discovery. Install with: pip install requests") from exc

    resp = requests.get(
        f"{_API_BASE}{path}",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=_API_TIMEOUT,
    )
    if resp.status_code == 401:
        raise CloudDiscoveryError("Vast.ai: invalid API key (HTTP 401)")
    resp.raise_for_status()
    return resp.json()


def discover(
    api_key: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover Vast.ai rented GPU instances.

    Args:
        api_key: Vast.ai API key. Falls back to ``VASTAI_API_KEY`` env var.

    Returns:
        (agents, warnings) tuple.
    """
    try:
        import requests  # noqa: F401
    except ImportError:
        return [], ["Vast.ai discovery requires 'requests'. Install with: pip install requests"]

    resolved_key = api_key or os.environ.get("VASTAI_API_KEY", "")
    if not resolved_key:
        return [], ["VASTAI_API_KEY not set. Provide --vastai-api-key or set the VASTAI_API_KEY env var."]

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        data = _vast_get("/instances/?owner=me", resolved_key)
        instances = data if isinstance(data, list) else data.get("instances", [])

        for inst in instances:
            inst_id = str(inst.get("id", "unknown"))
            status = inst.get("actual_status", inst.get("status", "unknown"))
            image = inst.get("image_uuid", inst.get("image_id", ""))
            gpu_name = inst.get("gpu_name", "GPU")
            gpu_count = inst.get("num_gpus", 1)
            hostname = inst.get("hostname", inst_id)
            location = inst.get("geolocation", inst.get("location", "unknown"))
            label = inst.get("label", hostname)

            packages = []
            if image:
                packages.append(
                    Package(
                        name=image.split(":")[0].replace("/", "-"),
                        version=image.split(":")[-1] if ":" in image else "latest",
                        ecosystem="container-image",
                        purl=build_package_purl(
                            ecosystem="container-image",
                            name=image.split(":")[0].replace("/", "-"),
                            version=image.split(":")[-1] if ":" in image else "latest",
                        ),
                    )
                )

            server = MCPServer(
                name=f"vastai:{label}",
                transport=TransportType.UNKNOWN,
                packages=packages,
                tools=[MCPTool(name=label, description=f"Vast.ai {gpu_name}x{gpu_count} ({location})")],
            )

            agent = Agent(
                name=f"vastai:{label}",
                agent_type=AgentType.CUSTOM,
                config_path=f"vastai://instance/{inst_id}",
                source="vastai",
                version=status,
                mcp_servers=[server],
                metadata={
                    "gpu_type": gpu_name,
                    "gpu_count": gpu_count,
                    "location": location,
                    "image": image,
                    "cloud_origin": build_cloud_origin(
                        provider="vastai",
                        service="compute",
                        resource_type="gpu-instance",
                        resource_id=inst_id,
                        resource_name=label,
                        raw_identity={"id": inst_id, "gpu": gpu_name, "location": location},
                    ),
                },
            )
            agents.append(agent)

    except CloudDiscoveryError as exc:
        warnings.append(str(exc))
    except Exception as exc:
        warnings.append(f"Vast.ai discovery error: {exc}")

    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=("vastai:all",),
        permissions_used=("vastai:instances:read",),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    logger.info("Vast.ai: discovered %d instance(s)", len(agents))
    return agents, warnings
