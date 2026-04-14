"""Databricks cloud discovery — clusters, libraries, and model serving endpoints.

Requires ``databricks-sdk``.  Install with::

    pip install 'agent-bom[databricks]'

Authentication — zero-credential model (no passwords stored or logged):

Uses the Databricks SDK credential chain in order:
1. ``~/.databrickscfg`` profile with OAuth M2M or browser auth (preferred)
2. ``DATABRICKS_HOST`` + ``DATABRICKS_TOKEN`` env vars (PAT — scoped read-only)
3. Workload identity in CI (Azure Managed Identity / GCP service account)

agent-bom never stores credentials. All access is read-only.

Required Databricks permissions (read-only):
    CAN VIEW on all clusters
    CAN VIEW on model serving endpoints
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional

from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_state, normalize_cloud_lifecycle_state

logger = logging.getLogger(__name__)


def discover(
    host: str | None = None,
    token: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from Databricks clusters and model serving endpoints.

    The Databricks cluster libraries API returns exact package names + versions,
    making this the most straightforward provider to implement.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``databricks-sdk`` is not installed.
    """
    try:
        from databricks.sdk import WorkspaceClient
        from databricks.sdk.errors import PermissionDenied  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError("databricks-sdk is required for Databricks discovery. Install with: pip install 'agent-bom[databricks]'")

    agents: list[Agent] = []
    warnings: list[str] = []

    ws_kwargs: dict[str, Any] = {}
    if host:
        ws_kwargs["host"] = host
    if token:
        ws_kwargs["token"] = token

    try:
        ws = WorkspaceClient(**ws_kwargs)
    except Exception as exc:
        warnings.append(f"Could not connect to Databricks: {exc}")
        return agents, warnings

    resolved_host = host or os.environ.get("DATABRICKS_HOST", "")

    # ── Clusters + Libraries ──────────────────────────────────────────────
    try:
        clusters = list(ws.clusters.list())
    except PermissionDenied:
        warnings.append("Access denied for Databricks clusters API. Check workspace permissions.")
        clusters = []
    except Exception as exc:
        warnings.append(f"Could not list Databricks clusters: {exc}")
        clusters = []

    for cluster in clusters:
        cluster_id = getattr(cluster, "cluster_id", "") or ""
        cluster_name = getattr(cluster, "cluster_name", "") or cluster_id
        state = getattr(cluster, "state", None)

        # Only scan running or terminated (recently used) clusters
        state_str = str(state).upper() if state else ""
        lifecycle_state = normalize_cloud_lifecycle_state(
            provider="databricks",
            service="clusters",
            resource_type="cluster",
            raw_state=state_str,
        )
        if lifecycle_state is None:
            continue

        packages = _get_cluster_packages(ws, cluster_id, warnings)
        if not packages:
            continue

        server = MCPServer(
            name=f"cluster-libs:{cluster_id}",
            command="spark",
            args=[cluster_id],
            transport=TransportType.UNKNOWN,
            packages=packages,
        )
        agent = Agent(
            name=f"databricks-cluster:{cluster_name}",
            agent_type=AgentType.CUSTOM,
            config_path=f"{resolved_host}/#/setting/clusters/{cluster_id}/configuration",
            source="databricks",
            mcp_servers=[server],
            metadata={
                "cloud_state": build_cloud_state(
                    provider="databricks",
                    service="clusters",
                    resource_type="cluster",
                    lifecycle_state=lifecycle_state,
                    raw_state=state_str,
                    state_source="cluster.state",
                )
            },
        )
        agents.append(agent)

    # ── Model Serving Endpoints ───────────────────────────────────────────
    try:
        endpoints = list(ws.serving_endpoints.list())
        for ep in endpoints:
            ep_name = getattr(ep, "name", "unknown")
            ep_state = getattr(ep, "state", None)
            # ep_state.ready is an EndpointStateReady enum — use .value to get
            # the raw string ("READY" / "NOT_READY") rather than the repr.
            ready_enum = getattr(ep_state, "ready", None) if ep_state else None
            state_str = getattr(ready_enum, "value", str(ready_enum or "")).upper()
            lifecycle_state = normalize_cloud_lifecycle_state(
                provider="databricks",
                service="model-serving",
                resource_type="serving-endpoint",
                raw_state=state_str,
            )
            if lifecycle_state is None:
                continue

            server = MCPServer(
                name=f"serving:{ep_name}",
                command="model-serving",
                transport=TransportType.STREAMABLE_HTTP,
            )
            agent = Agent(
                name=f"databricks-serving:{ep_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"{resolved_host}/ml/endpoints/{ep_name}",
                source="databricks",
                mcp_servers=[server],
                metadata={
                    "cloud_state": build_cloud_state(
                        provider="databricks",
                        service="model-serving",
                        resource_type="serving-endpoint",
                        lifecycle_state=lifecycle_state,
                        raw_state=state_str,
                        state_source="state.ready",
                    )
                },
            )
            agents.append(agent)

    except PermissionDenied:
        warnings.append("Access denied for Databricks model serving API.")
    except Exception as exc:
        warnings.append(f"Could not list Databricks serving endpoints: {exc}")

    return agents, warnings


def _get_cluster_packages(
    ws: Any,
    cluster_id: str,
    warnings: list[str],
) -> list[Package]:
    """Extract installed packages from a Databricks cluster's library status."""
    packages: list[Package] = []
    seen: set[str] = set()

    try:
        statuses = ws.libraries.cluster_status(cluster_id=cluster_id)
        for ls in getattr(statuses, "library_statuses", []) or []:
            lib = getattr(ls, "library", None)
            if not lib:
                continue

            # PyPI library
            pypi = getattr(lib, "pypi", None)
            if pypi:
                pkg_str = getattr(pypi, "package", "") or ""
                pkg = _parse_pypi_spec(pkg_str)
                if pkg and pkg.name.lower() not in seen:
                    seen.add(pkg.name.lower())
                    packages.append(pkg)

            # Maven library
            maven = getattr(lib, "maven", None)
            if maven:
                coords = getattr(maven, "coordinates", "") or ""
                pkg = _parse_maven_coords(coords)
                if pkg and f"{pkg.name}:{pkg.version}" not in seen:
                    seen.add(f"{pkg.name}:{pkg.version}")
                    packages.append(pkg)

            # JAR library (just the filename)
            jar = getattr(lib, "jar", None)
            if jar:
                jar_path = str(jar)
                pkg = _parse_jar_path(jar_path)
                if pkg and pkg.name.lower() not in seen:
                    seen.add(pkg.name.lower())
                    packages.append(pkg)

    except Exception as exc:
        warnings.append(f"Could not get library status for cluster {cluster_id}: {exc}")

    return packages


def _parse_pypi_spec(spec: str) -> Optional[Package]:
    """Parse a PyPI package spec like 'langchain==0.1.0' or 'openai>=1.0'."""
    if not spec:
        return None
    # Handle ==, >=, <=, ~=, != and bare name
    match = re.match(r"^([a-zA-Z0-9._-]+)\s*(?:[=!<>~]=*\s*(.+))?$", spec.strip())
    if not match:
        return None
    name = match.group(1)
    version = match.group(2) or "unknown"
    # Clean version — take first version if comma-separated
    version = version.split(",")[0].strip()
    return Package(name=name, version=version, ecosystem="pypi")


def _parse_maven_coords(coords: str) -> Optional[Package]:
    """Parse Maven coordinates like 'org.apache.spark:spark-sql_2.12:3.5.0'."""
    if not coords:
        return None
    parts = coords.split(":")
    if len(parts) >= 3:
        group_artifact = f"{parts[0]}:{parts[1]}"
        version = parts[2]
        return Package(name=group_artifact, version=version, ecosystem="maven")
    if len(parts) == 2:
        return Package(name=parts[0], version=parts[1], ecosystem="maven")
    return None


def _parse_jar_path(path: str) -> Optional[Package]:
    """Try to extract name and version from a JAR filename."""
    if not path:
        return None
    # Extract filename from path
    filename = path.rsplit("/", 1)[-1].replace(".jar", "")
    # Try pattern: name-version
    match = re.match(r"^(.+?)-(\d+\..+)$", filename)
    if match:
        return Package(name=match.group(1), version=match.group(2), ecosystem="maven")
    return Package(name=filename, version="unknown", ecosystem="maven")
