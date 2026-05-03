"""Lambda Labs cloud discovery — GPU instances and fine-tuning jobs.

Lambda Labs is a GPU cloud used heavily for enterprise fine-tuning and
inference.  Discovery uses the Lambda Cloud REST API.

Authentication: ``LAMBDA_API_KEY`` environment variable or ``--lambda-api-key`` CLI flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_origin, build_package_purl

logger = logging.getLogger(__name__)

_API_BASE = "https://cloud.lambdalabs.com/api/v1"
_API_TIMEOUT = 15

# Lambda GPU instance type families → normalised capability label
_GPU_FAMILIES: dict[str, str] = {
    "gpu_1x_h100_pcie": "H100-PCIe",
    "gpu_1x_h100_sxm4": "H100-SXM4",
    "gpu_8x_h100_80gb_sxm4": "H100x8-SXM4",
    "gpu_1x_a100": "A100",
    "gpu_8x_a100": "A100x8",
    "gpu_1x_a10": "A10",
    "gpu_4x_a10": "A10x4",
    "gpu_1x_rtx6000": "RTX6000",
    "gpu_1x_v100": "V100",
}


def _lambda_get(path: str, api_key: str) -> dict | list:
    try:
        import requests
    except ImportError as exc:
        raise CloudDiscoveryError("requests is required for Lambda Labs discovery. Install with: pip install requests") from exc

    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.get(f"{_API_BASE}{path}", headers=headers, timeout=_API_TIMEOUT)
    if resp.status_code == 401:
        raise CloudDiscoveryError("Lambda Labs: invalid API key (HTTP 401)")
    resp.raise_for_status()
    return resp.json().get("data", resp.json())


def discover(
    api_key: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover Lambda Labs GPU instances.

    Args:
        api_key: Lambda Cloud API key. Falls back to ``LAMBDA_API_KEY`` env var.

    Returns:
        (agents, warnings) tuple.
    """
    try:
        import requests  # noqa: F401
    except ImportError:
        return [], ["Lambda Labs discovery requires 'requests'. Install with: pip install requests"]

    resolved_key = api_key or os.environ.get("LAMBDA_API_KEY", "")
    if not resolved_key:
        return [], ["LAMBDA_API_KEY not set. Provide --lambda-api-key or set the LAMBDA_API_KEY env var."]

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        instances = _lambda_get("/instances", resolved_key)
        if not isinstance(instances, list):
            instances = []

        for inst in instances:
            inst_id = inst.get("id", "unknown")
            inst_name = inst.get("name", inst_id)
            status = inst.get("status", "unknown")
            region = inst.get("region", {}).get("name", "unknown")
            itype = inst.get("instance_type", {}).get("name", "")
            gpu_label = _GPU_FAMILIES.get(itype, itype or "GPU")

            packages = [
                Package(
                    name=itype or "lambda-gpu-instance",
                    version=status,
                    ecosystem="lambda-cloud",
                    purl=build_package_purl(
                        ecosystem="lambda-cloud",
                        name=itype or "lambda-gpu-instance",
                        version=status,
                    ),
                )
            ]

            server = MCPServer(
                name=f"lambda:{inst_name}",
                transport=TransportType.UNKNOWN,
                packages=packages,
                tools=[MCPTool(name=inst_name, description=f"Lambda Labs {gpu_label} instance ({region})")],
            )

            agent = Agent(
                name=f"lambda:{inst_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"lambda://{region}/{inst_id}",
                source="lambda-cloud",
                version=status,
                mcp_servers=[server],
                metadata={
                    "gpu_type": gpu_label,
                    "region": region,
                    "status": status,
                    "cloud_origin": build_cloud_origin(
                        provider="lambda",
                        service="compute",
                        resource_type="gpu-instance",
                        resource_id=inst_id,
                        resource_name=inst_name,
                        raw_identity={"id": inst_id, "region": region, "type": itype},
                    ),
                },
            )
            agents.append(agent)

    except CloudDiscoveryError as exc:
        warnings.append(str(exc))
    except Exception as exc:
        warnings.append(f"Lambda Labs discovery error: {exc}")

    scope = tuple(f"lambda:region/{r}" for r in {a.metadata.get("region", "") for a in agents} if r)
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=scope or ("lambda:all",),
        permissions_used=("lambda-cloud:instances:read",),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    logger.info("Lambda Labs: discovered %d instance(s)", len(agents))
    return agents, warnings
