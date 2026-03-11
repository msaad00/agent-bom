"""Cloud provider auto-discovery for AI agents and MCP servers.

Providers are split into two tiers:

**Core providers** (actively developed, 80 %+ test coverage target, CIS benchmarks):
  AWS, Azure, GCP, Snowflake, Databricks, Hugging Face Hub

**Extended providers** (maintained, not actively expanded until core tier is solid):
  CoreWeave, Nebius, W&B, MLflow, OpenAI, Ollama

Each provider is an optional dependency — install with e.g. ``pip install 'agent-bom[aws]'``.
"""

from __future__ import annotations

import importlib
from typing import Any

from agent_bom.models import Agent

from .base import CloudDiscoveryError

# Core providers: actively developed, CIS benchmark coverage, 80%+ test coverage target.
CORE_PROVIDERS: dict[str, str] = {
    "aws": "agent_bom.cloud.aws",
    "azure": "agent_bom.cloud.azure",
    "gcp": "agent_bom.cloud.gcp",
    "snowflake": "agent_bom.cloud.snowflake",
    "databricks": "agent_bom.cloud.databricks",
    "huggingface": "agent_bom.cloud.huggingface",
}

# Extended providers: maintained but not actively expanded until core tier is solid.
EXTENDED_PROVIDERS: dict[str, str] = {
    "coreweave": "agent_bom.cloud.coreweave",
    "nebius": "agent_bom.cloud.nebius",
    "wandb": "agent_bom.cloud.wandb_provider",
    "mlflow": "agent_bom.cloud.mlflow_provider",
    "openai": "agent_bom.cloud.openai_provider",
    "ollama": "agent_bom.cloud.ollama",
}

_PROVIDERS: dict[str, str] = {**CORE_PROVIDERS, **EXTENDED_PROVIDERS}


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
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown cloud provider '{provider}'. Available: {', '.join(sorted(_PROVIDERS))}")
    mod = importlib.import_module(_PROVIDERS[provider])
    return mod.discover(**kwargs)


def discover_governance(
    provider: str = "snowflake",
    **kwargs: Any,
) -> Any:
    """Run governance discovery for the given provider.

    Currently only Snowflake is supported.

    Returns:
        GovernanceReport with findings and raw data.
    """
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
    if provider != "snowflake":
        raise ValueError(f"Activity discovery not supported for '{provider}'.")
    mod = importlib.import_module(_PROVIDERS["snowflake"])
    return mod.discover_activity(**kwargs)


__all__ = [
    "CloudDiscoveryError",
    "CORE_PROVIDERS",
    "EXTENDED_PROVIDERS",
    "discover_from_provider",
    "discover_governance",
    "discover_activity",
]
