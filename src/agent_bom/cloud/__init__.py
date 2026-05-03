"""Cloud provider auto-discovery for AI agents and MCP servers.

Discovers agents from AWS, Azure, GCP, CoreWeave, Databricks, Snowflake,
Nebius, Hugging Face Hub, W&B, MLflow, OpenAI, Ollama (local), Lambda Labs,
RunPod, Vast.ai, and Crusoe Energy APIs.
Each provider is an optional dependency — install with e.g. ``pip install 'agent-bom[aws]'``.
"""

from __future__ import annotations

import importlib
from typing import Any

from agent_bom.extensions import ExtensionCapabilities, entrypoint_extensions_enabled, iter_entry_point_registrations
from agent_bom.models import Agent

from .base import CloudDiscoveryError, CloudProviderRegistration
from .normalization import sanitize_discovery_warnings

_ENTRY_POINT_GROUP = "agent_bom.cloud_providers"

# Backward-compatible module lookup surface. Keep this mutable for tests,
# integrations, and stats checks that read the old registry directly.
_PROVIDERS: dict[str, str] = {
    "aws": "agent_bom.cloud.aws",
    "azure": "agent_bom.cloud.azure",
    "gcp": "agent_bom.cloud.gcp",
    "coreweave": "agent_bom.cloud.coreweave",
    "databricks": "agent_bom.cloud.databricks",
    "snowflake": "agent_bom.cloud.snowflake",
    "nebius": "agent_bom.cloud.nebius",
    "huggingface": "agent_bom.cloud.huggingface",
    "wandb": "agent_bom.cloud.wandb_provider",
    "mlflow": "agent_bom.cloud.mlflow_provider",
    "openai": "agent_bom.cloud.openai_provider",
    "ollama": "agent_bom.cloud.ollama",
    "lambda": "agent_bom.cloud.lambda_labs",
    "runpod": "agent_bom.cloud.runpod",
    "vastai": "agent_bom.cloud.vastai",
    "crusoe": "agent_bom.cloud.crusoe",
}

_BUILTIN_PROVIDERS: dict[str, str] = dict(_PROVIDERS)
_PROVIDER_REGISTRY: dict[str, CloudProviderRegistration] = {}
_PROVIDER_REGISTRY_WARNINGS: list[str] = []
_PROVIDER_REGISTRY_LOADED = False

_PROVIDER_PERMISSIONS_USED: dict[str, tuple[str, ...]] = {
    "aws": (
        "sts:GetCallerIdentity",
        "bedrock:GetAgent",
        "bedrock:ListAgentActionGroups",
        "bedrock:ListAgents",
        "ec2:DescribeInstances",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecs:ListClusters",
        "ecs:ListServices",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "lambda:GetFunctionConfiguration",
        "lambda:GetLayerVersion",
        "lambda:ListFunctions",
        "sagemaker:DescribeEndpoint",
        "sagemaker:DescribeEndpointConfig",
        "sagemaker:ListEndpoints",
        "states:DescribeStateMachine",
        "states:ListStateMachines",
    ),
    "azure": (
        "Microsoft.CognitiveServices/accounts/read",
        "Microsoft.ContainerService/managedClusters/read",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Web/sites/read",
    ),
    "gcp": (
        "aiplatform.endpoints.list",
        "aiplatform.models.list",
        "container.clusters.list",
        "run.services.list",
        "storage.buckets.list",
    ),
    "coreweave": ("coreweave:read",),
    "databricks": (
        "databricks:clusters:read",
        "databricks:model-serving:read",
        "databricks:workspace:read",
    ),
    "huggingface": ("huggingface:models:read", "huggingface:spaces:read"),
    "mlflow": ("mlflow:experiments:read", "mlflow:models:read", "mlflow:runs:read"),
    "nebius": ("nebius:read",),
    "ollama": (),
    "openai": ("openai:assistants:read", "openai:models:read", "openai:responses:read"),
    "snowflake": ("snowflake:show:read", "snowflake:account_usage:read"),
    "wandb": ("wandb:artifacts:read", "wandb:runs:read"),
    "lambda": ("lambda-cloud:instances:read",),
    "runpod": ("runpod:pods:read", "runpod:serverless:read"),
    "vastai": ("vastai:instances:read",),
    "crusoe": ("crusoe:vms:read",),
}


def _provider_capabilities(name: str) -> ExtensionCapabilities:
    scan_modes: tuple[str, ...]
    if name == "ollama":
        scan_modes = ("runtime_probe",)
    elif name in {"aws", "azure", "gcp", "snowflake"}:
        scan_modes = ("direct_cloud_pull", "operator_pushed_inventory", "skill_invoked_pull")
    else:
        scan_modes = ("direct_cloud_pull",)
    return ExtensionCapabilities(
        scan_modes=scan_modes,
        required_scopes=(f"{name}:read",),
        permissions_used=_PROVIDER_PERMISSIONS_USED.get(name, (f"{name}:read",)),
        outbound_destinations=(name,),
        data_boundary="agentless_read_only",
        network_access=name != "ollama",
    )


def _registration_for_provider(name: str, module: str, *, source: str = "builtin") -> CloudProviderRegistration:
    return CloudProviderRegistration(
        name=name,
        module=module,
        capabilities=_provider_capabilities(name),
        source=source,
    )


def builtin_provider_registrations() -> list[CloudProviderRegistration]:
    """Return built-in cloud provider registrations."""

    return [_registration_for_provider(name, module) for name, module in _BUILTIN_PROVIDERS.items()]


def _coerce_provider_registration(value: Any, entry_point_name: str) -> CloudProviderRegistration:
    if isinstance(value, CloudProviderRegistration):
        return value
    name = str(getattr(value, "name", entry_point_name)).strip()
    module = str(getattr(value, "module", "")).strip()
    if not name or not module:
        raise ValueError("cloud provider registration must declare name and module")
    capabilities = getattr(value, "capabilities", ExtensionCapabilities())
    if not isinstance(capabilities, ExtensionCapabilities):
        capabilities = ExtensionCapabilities()
    return CloudProviderRegistration(
        name=name,
        module=module,
        capabilities=capabilities,
        source=str(getattr(value, "source", "entry_point")),
        discover_attr=str(getattr(value, "discover_attr", "discover")),
    )


def register_provider(registration: CloudProviderRegistration) -> None:
    """Register a cloud provider for discovery lookup."""

    _PROVIDER_REGISTRY[registration.name] = registration
    _PROVIDERS[registration.name] = registration.module


def _ensure_provider_registry_loaded() -> None:
    global _PROVIDER_REGISTRY_LOADED
    if _PROVIDER_REGISTRY_LOADED:
        return
    for registration in builtin_provider_registrations():
        register_provider(registration)
    for registration in iter_entry_point_registrations(
        group=_ENTRY_POINT_GROUP,
        coerce=_coerce_provider_registration,
        warnings=_PROVIDER_REGISTRY_WARNINGS,
    ):
        register_provider(registration)
    _PROVIDER_REGISTRY_LOADED = True


def list_registered_providers() -> list[CloudProviderRegistration]:
    """Return registered cloud providers with capability declarations."""

    _ensure_provider_registry_loaded()
    registrations = dict(_PROVIDER_REGISTRY)
    for name, module in _PROVIDERS.items():
        registrations.setdefault(name, _registration_for_provider(name, module, source="legacy"))
    return [registrations[name] for name in sorted(registrations)]


def provider_registry_warnings() -> list[str]:
    """Return sanitized non-fatal registry loading warnings."""

    _ensure_provider_registry_loaded()
    return list(_PROVIDER_REGISTRY_WARNINGS)


def _capabilities_payload(capabilities: ExtensionCapabilities) -> dict[str, Any]:
    return {
        "scan_modes": list(capabilities.scan_modes),
        "required_scopes": list(capabilities.required_scopes),
        "permissions_used": list(capabilities.permissions_used),
        "outbound_destinations": list(capabilities.outbound_destinations),
        # Alias for operator-facing API consumers. Keep the extension field name
        # above for SDK compatibility, but expose this wording in the contract.
        "network_destinations": list(capabilities.outbound_destinations),
        "data_boundary": capabilities.data_boundary,
        "writes": capabilities.writes,
        "network_access": capabilities.network_access,
        "guarantees": list(capabilities.guarantees),
    }


def _trust_contract_payload(capabilities: ExtensionCapabilities) -> dict[str, Any]:
    guarantees = set(capabilities.guarantees)
    scan_modes = set(capabilities.scan_modes)
    return {
        "read_only": not capabilities.writes and "read_only" in guarantees,
        "agentless": "agentless_read_only" in capabilities.data_boundary,
        "entrypoints_opt_in": True,
        "redaction_status": "central_sanitizer_applied",
        "scope_control": "operator_supplied_scopes",
        "data_residency": "operator_environment",
        "supports_scope_zero": bool({"operator_pushed_inventory", "skill_invoked_pull"} & scan_modes),
    }


def provider_contracts() -> dict[str, Any]:
    """Return provider capability contracts without importing provider SDK modules."""

    providers: list[dict[str, Any]] = []
    for registration in list_registered_providers():
        capabilities = registration.capabilities
        providers.append(
            {
                "name": registration.name,
                "module": registration.module,
                "source": registration.source,
                "discover_attr": registration.discover_attr,
                "capabilities": _capabilities_payload(capabilities),
                "trust_contract": _trust_contract_payload(capabilities),
            }
        )
    return {
        "contract_version": "1",
        "entrypoints_enabled": entrypoint_extensions_enabled(),
        "provider_count": len(providers),
        "providers": providers,
        "warnings": provider_registry_warnings(),
    }


def _reset_provider_registry_for_tests() -> None:
    _PROVIDER_REGISTRY.clear()
    _PROVIDER_REGISTRY_WARNINGS.clear()
    _PROVIDERS.clear()
    global _PROVIDER_REGISTRY_LOADED
    _PROVIDER_REGISTRY_LOADED = False


def discover_from_provider(
    provider: str,
    **kwargs: Any,
) -> tuple[list[Agent], list[str]]:
    """Lazily import and call the named provider's ``discover()`` function.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warning messages.

    Raises:
        ValueError: if *provider* is not a known provider name.
        CloudDiscoveryError: if the provider SDK is not installed or API fails.
    """
    _ensure_provider_registry_loaded()
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown cloud provider '{provider}'. Available: {', '.join(sorted(_PROVIDERS))}")
    registration = _PROVIDER_REGISTRY.get(provider)
    mod = importlib.import_module(_PROVIDERS[provider])
    discover_attr = registration.discover_attr if registration else "discover"
    agents, warnings = getattr(mod, discover_attr)(**kwargs)
    return agents, sanitize_discovery_warnings(warnings)


def discover_governance(
    provider: str = "snowflake",
    **kwargs: Any,
) -> Any:
    """Run governance discovery for the given provider.

    Currently only Snowflake is supported.

    Returns:
        GovernanceReport with findings and raw data.
    """
    _ensure_provider_registry_loaded()
    if provider != "snowflake":
        raise ValueError(f"Governance discovery not supported for '{provider}'.")
    mod = importlib.import_module(_PROVIDERS["snowflake"])
    return mod.discover_governance(**kwargs)


def discover_activity(
    provider: str = "snowflake",
    **kwargs: Any,
) -> Any:
    """Run activity timeline discovery for the given provider.

    Currently only Snowflake is supported.

    Returns:
        ActivityTimeline with query history and observability events.
    """
    _ensure_provider_registry_loaded()
    if provider != "snowflake":
        raise ValueError(f"Activity discovery not supported for '{provider}'.")
    mod = importlib.import_module(_PROVIDERS["snowflake"])
    return mod.discover_activity(**kwargs)


__all__ = [
    "CloudDiscoveryError",
    "discover_from_provider",
    "discover_governance",
    "discover_activity",
    "list_registered_providers",
    "provider_registry_warnings",
    "provider_contracts",
    "register_provider",
    "builtin_provider_registrations",
]
