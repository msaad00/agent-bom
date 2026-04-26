"""Shared scan pipeline for the MCP server.

This module keeps the public ``agent_bom.mcp_server`` wrapper surface stable
while moving the discovery + scan pipeline out of the monolith.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE
from agent_bom.mcp_errors import (
    CODE_VALIDATION_INVALID_IMAGE_REF,
    CODE_VALIDATION_INVALID_PATH,
    mcp_error_json,
)
from agent_bom.security import sanitize_error  # noqa: F401 — kept for downstream importers

logger = logging.getLogger(__name__)


async def run_scan_pipeline(
    *,
    safe_path,
    config_path: Optional[str] = None,
    image: Optional[str] = None,
    sbom_path: Optional[str] = None,
    enrich: bool = False,
    transitive: bool = False,
):
    """Run discovery -> extraction -> scanning and return agents + findings."""
    from agent_bom.discovery import discover_all
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import scan_agents, scan_agents_with_enrichment

    warnings: list[str] = []
    scan_sources: list[str] = []

    if config_path:
        try:
            config_path = str(safe_path(config_path))
        except ValueError as exc:
            return mcp_error_json(CODE_VALIDATION_INVALID_PATH, exc, details={"argument": "config_path"})

    if sbom_path:
        try:
            sbom_path = str(safe_path(sbom_path))
        except ValueError as exc:
            return mcp_error_json(CODE_VALIDATION_INVALID_PATH, exc, details={"argument": "sbom_path"})

    if image:
        try:
            from agent_bom.security import validate_image_ref

            validate_image_ref(image)
        except Exception as exc:
            return mcp_error_json(CODE_VALIDATION_INVALID_IMAGE_REF, exc, details={"argument": "image"})

    agents = discover_all(project_dir=config_path)
    if agents:
        scan_sources.append("agent_discovery")

    if image:
        try:
            from agent_bom.image import scan_image as _scan_image
            from agent_bom.models import ServerSurface

            img_packages, _strategy = _scan_image(image)
            if img_packages:
                img_server = MCPServer(
                    name=f"image:{image}",
                    command="",
                    args=[],
                    env={},
                    transport=TransportType.UNKNOWN,
                    packages=img_packages,
                    surface=ServerSurface.CONTAINER_IMAGE,
                )
                agents.append(
                    Agent(
                        name=f"image:{image}",
                        agent_type=AgentType.CUSTOM,
                        config_path="",
                        mcp_servers=[img_server],
                    )
                )
                scan_sources.append("image")
        except Exception as exc:
            msg = f"Image scan failed for {image}: {sanitize_error(exc)}"
            logger.warning(msg)
            warnings.append(msg)

    if sbom_path:
        try:
            sbom_file = Path(sbom_path)
            if sbom_file.exists() and sbom_file.stat().st_size > _MAX_FILE_SIZE:
                msg = f"SBOM file too large ({sbom_file.stat().st_size} bytes, max {_MAX_FILE_SIZE})"
                warnings.append(msg)
            else:
                from agent_bom.models import ServerSurface
                from agent_bom.sbom import load_sbom

                sbom_packages, _warnings, _sbom_name = load_sbom(sbom_path)
                if sbom_packages:
                    sbom_server = MCPServer(
                        name=f"sbom:{Path(sbom_path).name}",
                        command="",
                        args=[],
                        env={},
                        transport=TransportType.UNKNOWN,
                        packages=sbom_packages,
                        surface=ServerSurface.SBOM,
                    )
                    agents.append(
                        Agent(
                            name=f"sbom:{Path(sbom_path).name}",
                            agent_type=AgentType.CUSTOM,
                            config_path=sbom_path,
                            mcp_servers=[sbom_server],
                        )
                    )
                    scan_sources.append("sbom")
        except Exception as exc:
            msg = f"SBOM load failed for {sbom_path}: {exc}"
            logger.warning(msg)
            warnings.append(msg)

    if not agents:
        return [], [], warnings, scan_sources

    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

    if enrich:
        blast_radii = await scan_agents_with_enrichment(agents)
    else:
        blast_radii = await scan_agents(agents)
    return agents, blast_radii, warnings, scan_sources
