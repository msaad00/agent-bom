"""Cloud provider auto-discovery for AI agents and MCP servers.

Discovers agents from AWS, Azure, GCP, CoreWeave, Databricks, Snowflake,
Nebius, Hugging Face Hub, W&B, MLflow, OpenAI, and Ollama (local) APIs.
Each provider is an optional dependency — install with e.g. ``pip install 'agent-bom[aws]'``.
"""

from __future__ import annotations

import importlib
from typing import Any

from agent_bom.extensions import ExtensionCapabilities, iter_entry_point_registrations
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
}

_BUILTIN_PROVIDERS: dict[str, str] = dict(_PROVIDERS)
_PROVIDER_REGISTRY: dict[str, CloudProviderRegistration] = {}
_PROVIDER_REGISTRY_WARNINGS: list[str] = []
_PROVIDER_REGISTRY_LOADED = False


def _provider_capabilities(name: str) -> ExtensionCapabilities:
    return ExtensionCapabilities(
        scan_modes=("inventory",),
        required_scopes=(f"{name}:read",),
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
    "register_provider",
    "builtin_provider_registrations",
]
