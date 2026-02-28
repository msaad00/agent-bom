"""GCP cloud discovery — Vertex AI, Cloud Functions, GKE, and Cloud Run.

Requires one or more GCP SDKs.  Install with::

    pip install 'agent-bom[gcp]'

Authentication uses Application Default Credentials (``gcloud auth application-default login``
or ``GOOGLE_APPLICATION_CREDENTIALS`` env var).
"""

from __future__ import annotations

import logging
import os

from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    project_id: str | None = None,
    region: str = "us-central1",
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from Google Cloud Vertex AI, Cloud Functions, GKE, and Cloud Run.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if no GCP SDK packages are installed.
    """
    # Check that at least one GCP SDK is available
    _has_any = False
    for mod in (
        "google.cloud.aiplatform",
        "google.cloud.functions_v2",
        "google.cloud.container_v1",
        "google.cloud.run_v2",
    ):
        try:
            __import__(mod)
            _has_any = True
            break
        except ImportError:
            continue

    if not _has_any:
        raise CloudDiscoveryError("At least one GCP SDK is required for GCP discovery. Install with: pip install 'agent-bom[gcp]'")

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    if not resolved_project:
        warnings.append("GOOGLE_CLOUD_PROJECT not set. Provide --gcp-project or set the GOOGLE_CLOUD_PROJECT env var.")
        return agents, warnings

    # -- Vertex AI Endpoints ---------------------------------------------------
    try:
        vertex_agents, vertex_warns = _discover_vertex_ai(resolved_project, region)
        agents.extend(vertex_agents)
        warnings.extend(vertex_warns)
    except Exception as exc:
        warnings.append(f"Vertex AI discovery error: {exc}")

    # -- Cloud Functions -------------------------------------------------------
    try:
        cf_agents, cf_warns = _discover_cloud_functions(resolved_project, region)
        agents.extend(cf_agents)
        warnings.extend(cf_warns)
    except Exception as exc:
        warnings.append(f"Cloud Functions discovery error: {exc}")

    # -- GKE Clusters ----------------------------------------------------------
    try:
        gke_agents, gke_warns = _discover_gke_clusters(resolved_project, region)
        agents.extend(gke_agents)
        warnings.extend(gke_warns)
    except Exception as exc:
        warnings.append(f"GKE discovery error: {exc}")

    # -- Cloud Run services ----------------------------------------------------
    try:
        run_agents, run_warns = _discover_cloud_run(resolved_project, region)
        agents.extend(run_agents)
        warnings.extend(run_warns)
    except Exception as exc:
        warnings.append(f"Cloud Run discovery error: {exc}")

    return agents, warnings


# ---------------------------------------------------------------------------
# Vertex AI
# ---------------------------------------------------------------------------


def _discover_vertex_ai(
    project_id: str,
    region: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Vertex AI endpoints and their deployed models.

    Uses ``google.cloud.aiplatform`` to enumerate endpoints and extract
    deployed model metadata (model name, version, machine type).
    """
    try:
        import google.cloud.aiplatform as aiplatform
    except ImportError:
        return [], ["google-cloud-aiplatform not installed. Skipping Vertex AI discovery."]

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        aiplatform.init(project=project_id, location=region)
        endpoints = aiplatform.Endpoint.list()

        for endpoint in endpoints:
            ep_name = endpoint.display_name or "unknown"
            ep_resource = endpoint.resource_name

            # Enumerate deployed models on this endpoint
            servers: list[MCPServer] = []
            deployed_models = getattr(endpoint.gca_resource, "deployed_models", []) or []
            for deployed in deployed_models:
                model_id = getattr(deployed, "model", "") or ""
                model_display = getattr(deployed, "display_name", "") or model_id
                model_version = getattr(deployed, "model_version_id", None)

                # Extract machine type from dedicated/automatic resources
                machine_type = "unknown"
                dedicated = getattr(deployed, "dedicated_resources", None)
                if dedicated:
                    machine_spec = getattr(dedicated, "machine_spec", None)
                    if machine_spec:
                        machine_type = getattr(machine_spec, "machine_type", "unknown") or "unknown"
                else:
                    auto = getattr(deployed, "automatic_resources", None)
                    if auto:
                        machine_type = "automatic-scaling"

                server_name = f"vertex-model:{model_display}"
                if model_version:
                    server_name += f"@{model_version}"

                server = MCPServer(
                    name=server_name,
                    command="",
                    transport=TransportType.STREAMABLE_HTTP,
                    url=f"https://{region}-aiplatform.googleapis.com/v1/{ep_resource}",
                )
                servers.append(server)

                logger.debug(
                    "Vertex AI model: %s (version=%s, machine=%s) on endpoint %s",
                    model_display,
                    model_version,
                    machine_type,
                    ep_name,
                )

            agent = Agent(
                name=f"vertex-ai:{ep_name}",
                agent_type=AgentType.CUSTOM,
                config_path=ep_resource,
                source="gcp-vertex-ai",
                mcp_servers=servers,
                metadata={
                    "gcp_project": project_id,
                    "region": region,
                    "resource_name": ep_resource,
                },
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Vertex AI endpoints: {exc}")

    return agents, warnings


# ---------------------------------------------------------------------------
# Cloud Functions
# ---------------------------------------------------------------------------


def _discover_cloud_functions(
    project_id: str,
    region: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Cloud Functions (2nd gen) and extract runtime/build info.

    Uses ``google.cloud.functions_v2.FunctionServiceClient`` to list
    functions, extract runtime (python312, nodejs20, etc.), and pull
    build config for dependency metadata.
    """
    try:
        from google.cloud.functions_v2 import FunctionServiceClient
    except ImportError:
        return [], ["google-cloud-functions not installed. Skipping Cloud Functions discovery."]

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        client = FunctionServiceClient()
        parent = f"projects/{project_id}/locations/{region}"
        functions = client.list_functions(parent=parent)

        for function in functions:
            fn_name = function.name.split("/")[-1] if function.name else "unknown"
            fn_resource = function.name or f"projects/{project_id}/locations/{region}/functions/{fn_name}"

            # Extract runtime and entry point from build config
            runtime = "unknown"
            entry_point = ""
            source_uri = ""
            build_config = getattr(function, "build_config", None)
            if build_config:
                runtime = getattr(build_config, "runtime", "unknown") or "unknown"
                entry_point = getattr(build_config, "entry_point", "") or ""
                # Source info for dependency tracing
                source = getattr(build_config, "source", None)
                if source:
                    storage_source = getattr(source, "storage_source", None)
                    repo_source = getattr(source, "repo_source", None)
                    if storage_source:
                        bucket = getattr(storage_source, "bucket", "")
                        obj = getattr(storage_source, "object_", "")
                        source_uri = f"gs://{bucket}/{obj}" if bucket else ""
                    elif repo_source:
                        source_uri = getattr(repo_source, "url", "") or ""

            # Service config for URL and resource limits
            service_url = ""
            service_config = getattr(function, "service_config", None)
            if service_config:
                service_url = getattr(service_config, "uri", "") or ""

            server = MCPServer(
                name=f"cloud-function:{fn_name}",
                command="",
                transport=TransportType.STREAMABLE_HTTP,
                url=service_url or f"https://{region}-{project_id}.cloudfunctions.net/{fn_name}",
            )

            agent = Agent(
                name=f"cloud-function:{fn_name}",
                agent_type=AgentType.CUSTOM,
                config_path=fn_resource,
                source="gcp-cloud-functions",
                mcp_servers=[server],
                metadata={
                    "gcp_project": project_id,
                    "region": region,
                    "runtime": runtime,
                    "entry_point": entry_point,
                    "source_uri": source_uri,
                },
            )
            agents.append(agent)

            logger.debug(
                "Cloud Function: %s (runtime=%s, entry_point=%s, source=%s)",
                fn_name,
                runtime,
                entry_point,
                source_uri,
            )

    except Exception as exc:
        warnings.append(f"Could not list Cloud Functions: {exc}")

    return agents, warnings


# ---------------------------------------------------------------------------
# GKE Clusters
# ---------------------------------------------------------------------------


def _discover_gke_clusters(
    project_id: str,
    region: str,
) -> tuple[list[Agent], list[str]]:
    """Discover GKE clusters, node pools, and container workloads.

    Uses ``google.cloud.container_v1.ClusterManagerClient`` to list
    clusters, extract node pool machine types, and attempt to gather
    container images from workload metadata where available.
    """
    try:
        from google.cloud.container_v1 import ClusterManagerClient
    except ImportError:
        return [], ["google-cloud-container not installed. Skipping GKE discovery."]

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        client = ClusterManagerClient()
        # The parent format for listing clusters: projects/*/locations/*
        # Using "-" for location lists clusters in all zones/regions under the project
        parent = f"projects/{project_id}/locations/{region}"
        response = client.list_clusters(parent=parent)
        clusters = getattr(response, "clusters", []) or []

        for cluster in clusters:
            cluster_name = getattr(cluster, "name", "unknown") or "unknown"
            cluster_location = getattr(cluster, "location", region) or region
            cluster_self_link = getattr(cluster, "self_link", "") or ""
            cluster_version = getattr(cluster, "current_master_version", "") or ""

            # Collect node pool info (machine types, image types)
            node_pool_info: list[dict[str, str]] = []
            node_pools = getattr(cluster, "node_pools", []) or []
            for pool in node_pools:
                pool_name = getattr(pool, "name", "unknown") or "unknown"
                config = getattr(pool, "config", None)
                machine_type = "unknown"
                image_type = "unknown"
                if config:
                    machine_type = getattr(config, "machine_type", "unknown") or "unknown"
                    image_type = getattr(config, "image_type", "unknown") or "unknown"
                node_pool_info.append(
                    {
                        "name": pool_name,
                        "machine_type": machine_type,
                        "image_type": image_type,
                    }
                )

            # Build MCP server entries for the cluster endpoint
            endpoint = getattr(cluster, "endpoint", "") or ""
            server_url = f"https://{endpoint}" if endpoint else cluster_self_link

            server = MCPServer(
                name=f"gke-cluster:{cluster_name}",
                command="",
                transport=TransportType.STREAMABLE_HTTP,
                url=server_url,
            )

            agent = Agent(
                name=f"gke:{cluster_name}",
                agent_type=AgentType.CUSTOM,
                config_path=cluster_self_link or f"projects/{project_id}/locations/{cluster_location}/clusters/{cluster_name}",
                source="gcp-gke",
                mcp_servers=[server],
                metadata={
                    "gcp_project": project_id,
                    "region": cluster_location,
                    "cluster_version": cluster_version,
                    "node_pools": node_pool_info,
                },
            )
            agents.append(agent)

            logger.debug(
                "GKE cluster: %s (version=%s, location=%s, node_pools=%d)",
                cluster_name,
                cluster_version,
                cluster_location,
                len(node_pool_info),
            )

    except Exception as exc:
        warnings.append(f"Could not list GKE clusters: {exc}")

    return agents, warnings


# ---------------------------------------------------------------------------
# Cloud Run
# ---------------------------------------------------------------------------


def _discover_cloud_run(
    project_id: str,
    region: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Cloud Run services and extract container images."""
    try:
        from google.cloud.run_v2 import ServicesClient
    except ImportError:
        return [], ["google-cloud-run not installed. Skipping Cloud Run discovery."]

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        client = ServicesClient()
        parent = f"projects/{project_id}/locations/{region}"
        services = client.list_services(parent=parent)

        for service in services:
            svc_name = service.name.split("/")[-1] if service.name else "unknown"
            template = service.template
            if not template or not template.containers:
                continue

            for container in template.containers:
                image = container.image or ""
                if image:
                    server = MCPServer(
                        name=f"cloud-run:{svc_name}",
                        command="docker",
                        args=["run", image],
                        transport=TransportType.STDIO,
                    )
                    agent = Agent(
                        name=f"cloud-run:{svc_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=service.name or f"gcp://{svc_name}",
                        source="gcp-cloud-run",
                        mcp_servers=[server],
                        metadata={
                            "gcp_project": project_id,
                            "region": region,
                            "image": image,
                        },
                    )
                    agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Cloud Run services: {exc}")

    return agents, warnings
