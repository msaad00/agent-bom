"""Crusoe Energy cloud discovery — sustainable GPU instances.

Crusoe Energy is a GPU cloud focused on AI workloads powered by stranded
natural gas.  Discovery uses the Crusoe Cloud REST API.

Authentication: ``CRUSOE_API_KEY`` environment variable or ``--crusoe-api-key`` CLI flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_origin, build_package_purl

logger = logging.getLogger(__name__)

_API_BASE = "https://api.crusoecloud.com/v1alpha5"
_API_TIMEOUT = 15


def _crusoe_get(path: str, api_key: str) -> dict | list:
    try:
        import requests
    except ImportError as exc:
        raise CloudDiscoveryError("requests is required for Crusoe discovery. Install with: pip install requests") from exc

    resp = requests.get(
        f"{_API_BASE}{path}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        timeout=_API_TIMEOUT,
    )
    if resp.status_code == 401:
        raise CloudDiscoveryError("Crusoe: invalid API key (HTTP 401)")
    resp.raise_for_status()
    return resp.json()


def discover(
    api_key: str | None = None,
    project_id: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover Crusoe Energy GPU instances.

    Args:
        api_key:    Crusoe API key. Falls back to ``CRUSOE_API_KEY`` env var.
        project_id: Crusoe project ID. Falls back to ``CRUSOE_PROJECT_ID`` env var.

    Returns:
        (agents, warnings) tuple.
    """
    try:
        import requests  # noqa: F401
    except ImportError:
        return [], ["Crusoe discovery requires 'requests'. Install with: pip install requests"]

    resolved_key = api_key or os.environ.get("CRUSOE_API_KEY", "")
    resolved_project = project_id or os.environ.get("CRUSOE_PROJECT_ID", "")

    if not resolved_key:
        return [], ["CRUSOE_API_KEY not set. Provide --crusoe-api-key or set the CRUSOE_API_KEY env var."]

    agents: list[Agent] = []
    warnings: list[str] = []

    path = "/compute/vms"
    if resolved_project:
        path = f"/projects/{resolved_project}/compute/vms"

    try:
        data = _crusoe_get(path, resolved_key)
        vms = data if isinstance(data, list) else data.get("items", data.get("vms", []))

        for vm in vms:
            vm_id = str(vm.get("id", "unknown"))
            vm_name = vm.get("name", vm_id)
            status = vm.get("state", vm.get("status", "unknown"))
            location = vm.get("location", vm.get("datacenter", "unknown"))

            # GPU info from product / vm_type
            vm_type = vm.get("type", vm.get("vm_type", ""))
            gpu_count_raw = vm.get("gpus", vm.get("gpu_count", 0))
            gpu_count = int(gpu_count_raw) if str(gpu_count_raw).isdigit() else 1
            # Crusoe uses "h100.80gb.sxm" style type names
            gpu_label = vm_type.split(".")[0].upper() if vm_type else "GPU"

            packages = [
                Package(
                    name=vm_type or "crusoe-gpu-vm",
                    version=status,
                    ecosystem="crusoe-cloud",
                    purl=build_package_purl(
                        ecosystem="crusoe-cloud",
                        name=vm_type or "crusoe-gpu-vm",
                        version=status,
                    ),
                )
            ]

            server = MCPServer(
                name=f"crusoe:{vm_name}",
                transport=TransportType.UNKNOWN,
                packages=packages,
                tools=[MCPTool(name=vm_name, description=f"Crusoe {gpu_label}x{gpu_count} ({location})")],
            )

            agent = Agent(
                name=f"crusoe:{vm_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"crusoe://vm/{vm_id}",
                source="crusoe",
                version=status,
                mcp_servers=[server],
                metadata={
                    "gpu_type": gpu_label,
                    "gpu_count": gpu_count,
                    "location": location,
                    "vm_type": vm_type,
                    "cloud_origin": build_cloud_origin(
                        provider="crusoe",
                        service="compute",
                        resource_type="gpu-vm",
                        resource_id=vm_id,
                        resource_name=vm_name,
                        raw_identity={"id": vm_id, "type": vm_type, "location": location},
                    ),
                },
            )
            agents.append(agent)

    except CloudDiscoveryError as exc:
        warnings.append(str(exc))
    except Exception as exc:
        warnings.append(f"Crusoe discovery error: {exc}")

    scope = (f"crusoe:project/{resolved_project}",) if resolved_project else ("crusoe:all",)
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=scope,
        permissions_used=("crusoe:vms:read",),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    logger.info("Crusoe: discovered %d VM(s)", len(agents))
    return agents, warnings
