"""Azure cloud discovery — AI Foundry, Container Apps, OpenAI, Functions, ACI, ML.

Requires ``azure-identity`` and related SDKs.  Install with::

    pip install 'agent-bom[azure]'

Authentication uses ``DefaultAzureCredential`` (env vars, managed identity,
Azure CLI login, VS Code credentials).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    subscription_id: str | None = None,
    resource_group: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from Azure services.

    Scans Container Apps, AI Foundry, OpenAI deployments, Azure Functions,
    Container Instances, and ML endpoints.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``azure-identity`` is not installed.
    """
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F811
    except ImportError:
        raise CloudDiscoveryError("azure-identity is required for Azure discovery. Install with: pip install 'agent-bom[azure]'")

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not resolved_sub:
        warnings.append("AZURE_SUBSCRIPTION_ID not set. Provide --azure-subscription or set the AZURE_SUBSCRIPTION_ID env var.")
        return agents, warnings

    try:
        credential = DefaultAzureCredential()
    except Exception as exc:
        warnings.append(f"Azure authentication failed: {exc}")
        return agents, warnings

    # ── Container Apps ────────────────────────────────────────────────────
    try:
        container_agents, ca_warns = _discover_container_apps(credential, resolved_sub, resource_group)
        agents.extend(container_agents)
        warnings.extend(ca_warns)
    except Exception as exc:
        warnings.append(f"Azure Container Apps discovery error: {exc}")

    # ── AI Foundry agents ─────────────────────────────────────────────────
    try:
        ai_agents, ai_warns = _discover_ai_foundry(credential, resolved_sub, resource_group)
        agents.extend(ai_agents)
        warnings.extend(ai_warns)
    except Exception as exc:
        warnings.append(f"Azure AI Foundry discovery error: {exc}")

    # ── Azure OpenAI deployments ──────────────────────────────────────────
    try:
        oai_agents, oai_warns = _discover_openai_deployments(credential, resolved_sub)
        agents.extend(oai_agents)
        warnings.extend(oai_warns)
    except Exception as exc:
        warnings.append(f"Azure OpenAI discovery error: {exc}")

    # ── Azure Functions ───────────────────────────────────────────────────
    try:
        fn_agents, fn_warns = _discover_azure_functions(credential, resolved_sub)
        agents.extend(fn_agents)
        warnings.extend(fn_warns)
    except Exception as exc:
        warnings.append(f"Azure Functions discovery error: {exc}")

    # ── Container Instances (ACI) ─────────────────────────────────────────
    try:
        aci_agents, aci_warns = _discover_container_instances(credential, resolved_sub)
        agents.extend(aci_agents)
        warnings.extend(aci_warns)
    except Exception as exc:
        warnings.append(f"Azure Container Instances discovery error: {exc}")

    # ── ML endpoints ──────────────────────────────────────────────────────
    try:
        ml_agents, ml_warns = _discover_ml_endpoints(credential, resolved_sub)
        agents.extend(ml_agents)
        warnings.extend(ml_warns)
    except Exception as exc:
        warnings.append(f"Azure ML endpoints discovery error: {exc}")

    return agents, warnings


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def _discover_container_apps(
    credential: Any,
    subscription_id: str,
    resource_group: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure Container Apps and extract their container images."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.mgmt.appcontainers import ContainerAppsAPIClient
    except ImportError:
        warnings.append("azure-mgmt-appcontainers not installed. Skipping Container Apps discovery.")
        return agents, warnings

    try:
        client = ContainerAppsAPIClient(credential, subscription_id)

        if resource_group:
            apps = list(client.container_apps.list_by_resource_group(resource_group))
        else:
            apps = list(client.container_apps.list_by_subscription())

        for app in apps:
            app_name = app.name or "unknown"
            template = getattr(app, "template", None)
            if not template:
                continue

            containers = getattr(template, "containers", []) or []
            for container in containers:
                image = getattr(container, "image", "")
                if image:
                    server = MCPServer(
                        name=f"container:{container.name or image}",
                        command="docker",
                        args=["run", image],
                        transport=TransportType.STDIO,
                    )
                    agent = Agent(
                        name=f"azure-container-app:{app_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=app.id or f"azure://{app_name}",
                        source="azure-container-apps",
                        mcp_servers=[server],
                    )
                    agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Container Apps: {exc}")

    return agents, warnings


def _discover_ai_foundry(
    credential: Any,
    subscription_id: str,
    resource_group: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure AI Foundry (Azure AI Studio) agents."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.ai.projects import AIProjectClient  # noqa: F401 — availability check
    except ImportError:
        warnings.append("azure-ai-projects not installed. Skipping AI Foundry agent discovery. Install with: pip install azure-ai-projects")
        return agents, warnings

    # AI Foundry requires a project endpoint — discover via resource graph
    try:
        from azure.mgmt.resource import ResourceManagementClient

        rm_client = ResourceManagementClient(credential, subscription_id)

        # Find AI project resources
        filter_str = "resourceType eq 'Microsoft.MachineLearningServices/workspaces'"
        if resource_group:
            resources = list(rm_client.resources.list_by_resource_group(resource_group, filter=filter_str))
        else:
            resources = list(rm_client.resources.list(filter=filter_str))

        for resource in resources:
            ws_name = resource.name or "unknown"
            agent = Agent(
                name=f"azure-ai-foundry:{ws_name}",
                agent_type=AgentType.CUSTOM,
                config_path=resource.id or f"azure://{ws_name}",
                source="azure-ai-foundry",
                mcp_servers=[],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not discover AI Foundry workspaces: {exc}")

    return agents, warnings


def _discover_openai_deployments(
    credential: Any,
    subscription_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure OpenAI deployments across all Cognitive Services accounts."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    except ImportError:
        warnings.append(
            "azure-mgmt-cognitiveservices not installed. Skipping Azure OpenAI discovery. "
            "Install with: pip install azure-mgmt-cognitiveservices"
        )
        return agents, warnings

    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)

        # List all Cognitive Services accounts and filter for OpenAI kind
        for account in client.accounts.list():
            if getattr(account, "kind", "") != "OpenAI":
                continue

            account_name = account.name or "unknown"
            # Extract resource group from the account's ID
            # Format: /subscriptions/.../resourceGroups/<rg>/providers/...
            account_id = account.id or ""
            rg_parts = account_id.split("/resourceGroups/")
            if len(rg_parts) < 2:
                continue
            rg_name = rg_parts[1].split("/")[0]

            # List deployments for this OpenAI account
            try:
                for deployment in client.deployments.list(rg_name, account_name):
                    deploy_name = deployment.name or "unknown"
                    properties = getattr(deployment, "properties", None)
                    model = getattr(properties, "model", None)
                    model_name = getattr(model, "name", "unknown") if model else "unknown"
                    model_version = getattr(model, "version", "") if model else ""
                    sku = getattr(deployment, "sku", None)
                    sku_name = getattr(sku, "name", "") if sku else ""

                    label = f"{model_name}@{model_version}" if model_version else model_name
                    server = MCPServer(
                        name=f"openai-deployment:{deploy_name}",
                        command=f"azure://openai/{account_name}/{deploy_name}",
                        transport=TransportType.SSE,
                        url=f"https://{account_name}.openai.azure.com/openai/deployments/{deploy_name}",
                    )
                    agent = Agent(
                        name=f"azure-openai:{account_name}/{deploy_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=deployment.id or f"azure://openai/{account_name}/{deploy_name}",
                        source="azure-openai",
                        mcp_servers=[server],
                        metadata={"model": label, "sku": sku_name},
                    )
                    agents.append(agent)
            except Exception as exc:
                warnings.append(f"Could not list deployments for OpenAI account {account_name}: {exc}")

    except Exception as exc:
        warnings.append(f"Could not list Cognitive Services accounts: {exc}")

    return agents, warnings


def _discover_azure_functions(
    credential: Any,
    subscription_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure Function Apps and extract runtime/package metadata."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.mgmt.web import WebSiteManagementClient
    except ImportError:
        warnings.append("azure-mgmt-web not installed. Skipping Azure Functions discovery. Install with: pip install azure-mgmt-web")
        return agents, warnings

    try:
        client = WebSiteManagementClient(credential, subscription_id)

        for app in client.web_apps.list():
            kind = getattr(app, "kind", "") or ""
            # Function apps have kind containing "functionapp"
            if "functionapp" not in kind.lower():
                continue

            app_name = app.name or "unknown"
            app_id = app.id or f"azure://functions/{app_name}"
            location = getattr(app, "location", "")

            # Extract resource group from app ID
            rg_name = ""
            if app.id:
                rg_parts = app.id.split("/resourceGroups/")
                if len(rg_parts) >= 2:
                    rg_name = rg_parts[1].split("/")[0]

            # Get runtime stack from site config
            runtime_stack = ""
            packages: list[Package] = []
            if rg_name:
                try:
                    config = client.web_apps.get_configuration(rg_name, app_name)
                    linux_fx = getattr(config, "linux_fx_version", "") or ""
                    net_version = getattr(config, "net_framework_version", "") or ""
                    node_version = getattr(config, "node_version", "") or ""
                    python_version = getattr(config, "python_version", "") or ""
                    java_version = getattr(config, "java_version", "") or ""

                    if linux_fx:
                        runtime_stack = linux_fx  # e.g. "PYTHON|3.11", "NODE|20"
                    elif python_version:
                        runtime_stack = f"python:{python_version}"
                    elif node_version:
                        runtime_stack = f"node:{node_version}"
                    elif net_version:
                        runtime_stack = f"dotnet:{net_version}"
                    elif java_version:
                        runtime_stack = f"java:{java_version}"

                    # Create a package entry for the runtime itself
                    if runtime_stack:
                        parts = runtime_stack.replace("|", ":").split(":")
                        rt_name = parts[0].lower() if parts else "unknown"
                        rt_ver = parts[1] if len(parts) > 1 else "0.0"
                        packages.append(
                            Package(
                                name=rt_name,
                                version=rt_ver,
                                ecosystem="azure-runtime",
                            )
                        )
                except Exception:
                    pass  # Site config read is best-effort

            server = MCPServer(
                name=f"function-app:{app_name}",
                command=f"azure://functions/{app_name}",
                transport=TransportType.SSE,
                url=f"https://{app_name}.azurewebsites.net",
                packages=packages,
            )
            agent = Agent(
                name=f"azure-function:{app_name}",
                agent_type=AgentType.CUSTOM,
                config_path=app_id,
                source="azure-functions",
                mcp_servers=[server],
                metadata={"runtime": runtime_stack, "location": location},
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Azure Functions: {exc}")

    return agents, warnings


def _discover_container_instances(
    credential: Any,
    subscription_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure Container Instances and extract container image references."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    except ImportError:
        warnings.append(
            "azure-mgmt-containerinstance not installed. Skipping ACI discovery. Install with: pip install azure-mgmt-containerinstance"
        )
        return agents, warnings

    try:
        client = ContainerInstanceManagementClient(credential, subscription_id)

        for group in client.container_groups.list():
            group_name = group.name or "unknown"
            group_id = group.id or f"azure://aci/{group_name}"
            containers = getattr(group, "containers", []) or []

            for container in containers:
                image = getattr(container, "image", "")
                container_name = getattr(container, "name", "") or image
                if not image:
                    continue

                server = MCPServer(
                    name=f"aci-container:{container_name}",
                    command="docker",
                    args=["run", image],
                    transport=TransportType.STDIO,
                )
                agent = Agent(
                    name=f"azure-aci:{group_name}/{container_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=group_id,
                    source="azure-container-instances",
                    mcp_servers=[server],
                    metadata={"image": image},
                )
                agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Container Instances: {exc}")

    return agents, warnings


def _discover_ml_endpoints(
    credential: Any,
    subscription_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure ML online endpoints and their model deployments."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.mgmt.machinelearningservices import MachineLearningServicesMgmtClient
    except ImportError:
        warnings.append(
            "azure-mgmt-machinelearningservices not installed. Skipping ML endpoint discovery. "
            "Install with: pip install azure-mgmt-machinelearningservices"
        )
        return agents, warnings

    try:
        client = MachineLearningServicesMgmtClient(credential, subscription_id)

        # List all ML workspaces, then enumerate online endpoints in each
        for ws in client.workspaces.list_by_subscription():
            ws_name = ws.name or "unknown"
            ws_id = ws.id or ""

            # Extract resource group from workspace ID
            rg_parts = ws_id.split("/resourceGroups/")
            if len(rg_parts) < 2:
                continue
            rg_name = rg_parts[1].split("/")[0]

            try:
                for endpoint in client.online_endpoints.list(rg_name, ws_name):
                    ep_name = endpoint.name or "unknown"
                    ep_id = endpoint.id or f"azure://ml/{ws_name}/{ep_name}"
                    properties = getattr(endpoint, "properties", None)
                    scoring_uri = getattr(properties, "scoring_uri", "") if properties else ""

                    # List deployments under this endpoint
                    deploy_meta: list[dict[str, str]] = []
                    try:
                        for deployment in client.online_deployments.list(rg_name, ws_name, ep_name):
                            d_name = deployment.name or "unknown"
                            d_props = getattr(deployment, "properties", None)
                            model_id = getattr(d_props, "model", "") if d_props else ""
                            instance_type = getattr(d_props, "instance_type", "") if d_props else ""
                            deploy_meta.append(
                                {
                                    "deployment": d_name,
                                    "model": model_id,
                                    "instance_type": instance_type,
                                }
                            )
                    except Exception:
                        pass  # Deployment listing is best-effort

                    server = MCPServer(
                        name=f"ml-endpoint:{ep_name}",
                        command=f"azure://ml/{ws_name}/{ep_name}",
                        transport=TransportType.SSE,
                        url=scoring_uri or None,
                    )
                    agent = Agent(
                        name=f"azure-ml:{ws_name}/{ep_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=ep_id,
                        source="azure-ml",
                        mcp_servers=[server],
                        metadata={
                            "workspace": ws_name,
                            "deployments": deploy_meta,
                        },
                    )
                    agents.append(agent)

            except Exception as exc:
                warnings.append(f"Could not list ML endpoints in workspace {ws_name}: {exc}")

    except Exception as exc:
        warnings.append(f"Could not list ML workspaces: {exc}")

    return agents, warnings
