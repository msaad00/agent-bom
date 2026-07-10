"""Shared scan pipeline for the MCP server.

This module keeps the public ``agent_bom.mcp_server`` wrapper surface stable
while moving the discovery + scan pipeline out of the monolith.
"""

from __future__ import annotations

import logging
import shlex
from pathlib import Path
from typing import Optional

from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE
from agent_bom.mcp_errors import (
    CODE_VALIDATION_INVALID_IMAGE_REF,
    CODE_VALIDATION_INVALID_PATH,
)
from agent_bom.security import sanitize_error  # noqa: F401 — kept for downstream importers


class McpScanValidationError(ValueError):
    """A scan input failed validation (e.g. a path outside the sandbox).

    Raised by :func:`run_scan_pipeline` instead of returning an error payload so
    the many call-sites that unpack a 4-tuple do not crash with "too many values
    to unpack (expected 4)" and tools surface a clean, structured error. It
    subclasses ``ValueError`` so existing ``except ValueError`` / ``except
    Exception`` handlers still catch it; ``code`` carries the machine-readable
    validation code.
    """

    def __init__(self, code: str, message: Exception | str, *, argument: str | None = None) -> None:
        self.code = code
        self.argument = argument
        text = message if isinstance(message, str) else sanitize_error(message)
        suffix = f" (argument: {argument})" if argument else ""
        super().__init__(f"{code}: {text}{suffix}")


logger = logging.getLogger(__name__)


def _package_spec_agent(package_spec: str):
    """Build a synthetic MCP inventory entry from a direct package command."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    tokens = shlex.split(package_spec)
    if not tokens:
        raise ValueError("package must not be empty")

    command = tokens[0]
    args = tokens[1:]
    if command not in {"npx", "npm", "pnpm", "yarn", "bunx", "uvx", "uv"}:
        command = "npx"
        args = tokens
    elif command in {"npm", "pnpm", "yarn"} and args and args[0] in {"dlx", "exec"}:
        command = "npx"
        args = args[1:]
    elif command == "bunx":
        command = "npx"

    server = MCPServer(
        name=f"package:{' '.join([command, *args]).strip()}",
        command=command,
        args=args,
        env={},
        transport=TransportType.STDIO,
        config_path="mcp-scan-package",
        discovery_sources=["mcp_scan_package"],
    )
    return Agent(
        name=f"package:{package_spec}",
        agent_type=AgentType.CUSTOM,
        config_path="mcp-scan-package",
        mcp_servers=[server],
    )


async def run_scan_pipeline(
    *,
    safe_path,
    config_path: Optional[str] = None,
    image: Optional[str] = None,
    sbom_path: Optional[str] = None,
    package: Optional[str] = None,
    enrich: bool = False,
    transitive: bool = False,
    offline: bool = False,
):
    """Run discovery -> extraction -> scanning and return agents + findings."""
    from agent_bom.discovery import discover_all
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import ScanOptions, scan_agents, scan_agents_with_enrichment

    warnings: list[str] = []
    scan_sources: list[str] = []

    if config_path:
        try:
            config_path = str(safe_path(config_path))
        except ValueError as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_PATH, exc, argument="config_path") from exc

    if sbom_path:
        try:
            sbom_path = str(safe_path(sbom_path))
        except ValueError as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_PATH, exc, argument="sbom_path") from exc

    if image:
        try:
            from agent_bom.security import validate_image_ref

            validate_image_ref(image)
        except Exception as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_IMAGE_REF, exc, argument="image") from exc

    agents = discover_all(project_dir=config_path)
    if agents:
        scan_sources.append("agent_discovery")

    if config_path:
        try:
            from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree
            from agent_bom.github_actions import scan_github_actions
            from agent_bom.python_agents import scan_python_agents
            from agent_bom.terraform import scan_terraform_dir

            scan_cloned_repo_tree(config_path, agents=agents, warnings=warnings)
            scan_sources.append("repo_tree")

            py_agents, py_warnings = scan_python_agents(config_path)
            agents.extend(py_agents)
            warnings.extend(py_warnings)
            if py_agents:
                scan_sources.append("python_agents")

            tf_agents, tf_warnings = scan_terraform_dir(config_path)
            agents.extend(tf_agents)
            warnings.extend(tf_warnings)
            if tf_agents:
                scan_sources.append("terraform")

            gha_agents, gha_warnings = scan_github_actions(config_path)
            agents.extend(gha_agents)
            warnings.extend(gha_warnings)
            if gha_agents:
                scan_sources.append("github_actions")
        except Exception as exc:
            msg = f"Repo static scan failed for {config_path}: {sanitize_error(exc)}"
            logger.warning(msg)
            warnings.append(msg)

    if package:
        try:
            agents.append(_package_spec_agent(package))
            scan_sources.append("mcp_package")
        except ValueError as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_PATH, exc, argument="package") from exc

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
            if offline:
                for pkg in server.packages:
                    if pkg.floating_reference and pkg.declared_version in {"latest", "*"}:
                        warnings.append(
                            f"{pkg.name} uses a floating package reference; pass {pkg.name}@version "
                            "or set offline=false for registry-backed resolution."
                        )

    if enrich and not offline:
        blast_radii = await scan_agents_with_enrichment(agents, options=ScanOptions(offline=offline))
    else:
        blast_radii = await scan_agents(agents, options=ScanOptions(offline=offline))
    return agents, blast_radii, warnings, scan_sources
