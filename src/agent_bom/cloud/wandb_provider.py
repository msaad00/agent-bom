"""Weights & Biases discovery — runs, artifacts, and model registry.

Requires ``wandb``.  Install with::

    pip install 'agent-bom[wandb]'

Authentication uses WANDB_API_KEY env var or --wandb-api-key flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_package_purl

logger = logging.getLogger(__name__)


def discover(
    api_key: str | None = None,
    entity: str | None = None,
    project: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI assets from Weights & Biases.

    Discovers recent runs (with Python package versions from metadata),
    model artifacts, and registered models.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``wandb`` is not installed.
    """
    try:
        import wandb  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError("wandb is required for W&B discovery. Install with: pip install 'agent-bom[wandb]'")

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_key = api_key or os.environ.get("WANDB_API_KEY", "")
    resolved_entity = entity or os.environ.get("WANDB_ENTITY", "")

    if not resolved_key:
        warnings.append("WANDB_API_KEY not set. Provide --wandb-api-key or set the WANDB_API_KEY env var.")
        return agents, warnings

    if not resolved_entity:
        warnings.append("WANDB_ENTITY not set. Provide --wandb-entity or set the WANDB_ENTITY env var.")
        return agents, warnings

    # ── Runs ──────────────────────────────────────────────────────────────
    try:
        run_agents, run_warns = _discover_runs(resolved_key, resolved_entity, project)
        agents.extend(run_agents)
        warnings.extend(run_warns)
    except Exception as exc:
        warnings.append(f"W&B run discovery error: {exc}")

    # ── Artifacts ─────────────────────────────────────────────────────────
    try:
        art_agents, art_warns = _discover_artifacts(resolved_key, resolved_entity, project)
        agents.extend(art_agents)
        warnings.extend(art_warns)
    except Exception as exc:
        warnings.append(f"W&B artifact discovery error: {exc}")

    return agents, warnings


def _discover_runs(
    api_key: str,
    entity: str,
    project: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover recent W&B runs and extract package metadata."""
    import wandb

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        api = wandb.Api(api_key=api_key)
        project_path = f"{entity}/{project}" if project else entity

        runs = api.runs(project_path, per_page=50) if project else []
        if not project:
            # Without a specific project, try listing projects first
            try:
                projects = api.projects(entity)
                for proj in list(projects):
                    proj_name = getattr(proj, "name", None)
                    if proj_name:
                        proj_runs = api.runs(f"{entity}/{proj_name}", per_page=50)
                        for run in list(proj_runs):
                            agent = _run_to_agent(run, entity, proj_name)
                            if agent:
                                agents.append(agent)
            except Exception as exc:
                warnings.append(f"Could not list W&B projects: {exc}")
            return agents, warnings

        for run in list(runs):
            agent = _run_to_agent(run, entity, project)
            if agent:
                agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list W&B runs: {exc}")

    return agents, warnings


def _run_to_agent(run, entity: str, project: str | None) -> Agent | None:
    """Convert a W&B run to an Agent with package metadata."""
    run_id = getattr(run, "id", "unknown")
    run_name = getattr(run, "name", run_id)
    config = getattr(run, "config", {}) or {}
    metadata = getattr(run, "metadata", {}) or {}

    packages = _extract_packages_from_metadata(config, metadata)

    server = MCPServer(
        name=f"wandb-run:{run_name}",
        transport=TransportType.UNKNOWN,
        packages=packages,
    )

    return Agent(
        name=f"wandb-run:{run_name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"wandb://{entity}/{project or '_'}/runs/{run_id}",
        source="wandb-run",
        version=run_id[:8],
        mcp_servers=[server],
    )


def _discover_artifacts(
    api_key: str,
    entity: str,
    project: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover W&B artifacts (models, datasets)."""
    import wandb

    agents: list[Agent] = []
    warnings: list[str] = []

    if not project:
        return agents, warnings

    try:
        api = wandb.Api(api_key=api_key)
        artifact_types = ["model", "dataset"]

        for art_type in artifact_types:
            try:
                artifacts = api.artifact_versions(
                    type_name=art_type,
                    name=f"{entity}/{project}",
                )
                for artifact in list(artifacts):
                    art_name = getattr(artifact, "name", "unknown")
                    art_version = getattr(artifact, "version", "latest")
                    art_metadata = getattr(artifact, "metadata", {}) or {}

                    packages = _extract_packages_from_metadata(art_metadata, {})

                    server = MCPServer(
                        name=f"wandb-{art_type}:{art_name}",
                        transport=TransportType.UNKNOWN,
                        packages=packages,
                    )

                    agent = Agent(
                        name=f"wandb-{art_type}:{art_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"wandb://{entity}/{project}/artifacts/{art_type}/{art_name}",
                        source=f"wandb-{art_type}",
                        version=str(art_version),
                        mcp_servers=[server],
                    )
                    agents.append(agent)
            except (ValueError, KeyError, AttributeError) as exc:
                # Artifact type may not exist in this project
                logger.debug("Could not list W&B artifacts of type %s: %s", art_type, exc)

    except Exception as exc:
        warnings.append(f"Could not list W&B artifacts: {exc}")

    return agents, warnings


def _extract_packages_from_metadata(
    config: dict,
    metadata: dict,
) -> list[Package]:
    """Extract Python packages from W&B run config/metadata.

    W&B runs often store requirements in config['_wandb']['requirements']
    or metadata['python']['packages'].
    """
    packages: list[Package] = []
    seen: set[str] = set()

    # Check config._wandb.requirements (pip freeze output)
    wandb_meta = config.get("_wandb", {})
    requirements = wandb_meta.get("requirements", [])
    if isinstance(requirements, list):
        for req in requirements:
            pkg = _parse_requirement(req)
            if pkg and pkg.name not in seen:
                packages.append(pkg)
                seen.add(pkg.name)

    # Check metadata.python.packages
    python_meta = metadata.get("python", {})
    meta_packages = python_meta.get("packages", [])
    if isinstance(meta_packages, list):
        for item in meta_packages:
            if isinstance(item, dict):
                name = item.get("name", "")
                version = item.get("version", "unknown")
                if name and name not in seen:
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="pypi",
                            purl=build_package_purl(ecosystem="pypi", name=name, version=version),
                        )
                    )
                    seen.add(name)

    # Check common config keys for framework hints
    if "_name_or_path" in config and "transformers" not in seen:
        packages.append(Package(name="transformers", version="unknown", ecosystem="pypi"))
        seen.add("transformers")

    return packages


def _parse_requirement(req: str) -> Package | None:
    """Parse a pip requirements line into a Package."""
    req = req.strip()
    if not req or req.startswith("#") or req.startswith("-"):
        return None

    # Handle ==, >=, <=, ~=
    for sep in ("==", ">=", "<=", "~=", "!="):
        if sep in req:
            name, version = req.split(sep, 1)
            # Strip extras: package[extra]==1.0 → package
            if "[" in name:
                name = name.split("[")[0]
            clean_name = name.strip()
            clean_version = version.strip()
            return Package(
                name=clean_name,
                version=clean_version,
                ecosystem="pypi",
                purl=build_package_purl(ecosystem="pypi", name=clean_name, version=clean_version),
            )

    # No version specifier
    name = req.split("[")[0].strip() if "[" in req else req.strip()
    if name:
        return Package(name=name, version="unknown", ecosystem="pypi")
    return None
