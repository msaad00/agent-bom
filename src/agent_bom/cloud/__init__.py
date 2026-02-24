"""Cloud provider auto-discovery for AI agents and MCP servers.

Discovers agents from AWS, Azure, GCP, Databricks, Snowflake, Nebius,
Hugging Face Hub, W&B, MLflow, OpenAI, and Ollama (local) APIs.
Each provider is an optional dependency — install with e.g. ``pip install 'agent-bom[aws]'``.
"""

from __future__ import annotations

import importlib
from typing import Any

from agent_bom.models import Agent

from .base import CloudDiscoveryError

_PROVIDERS: dict[str, str] = {
    "aws": "agent_bom.cloud.aws",
    "azure": "agent_bom.cloud.azure",
    "gcp": "agent_bom.cloud.gcp",
    "databricks": "agent_bom.cloud.databricks",
    "snowflake": "agent_bom.cloud.snowflake",
    "nebius": "agent_bom.cloud.nebius",
    "huggingface": "agent_bom.cloud.huggingface",
    "wandb": "agent_bom.cloud.wandb_provider",
    "mlflow": "agent_bom.cloud.mlflow_provider",
    "openai": "agent_bom.cloud.openai_provider",
    "ollama": "agent_bom.cloud.ollama",
}


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
        raise ValueError(
            f"Unknown cloud provider '{provider}'. "
            f"Available: {', '.join(sorted(_PROVIDERS))}"
        )
    mod = importlib.import_module(_PROVIDERS[provider])
    return mod.discover(**kwargs)


__all__ = ["CloudDiscoveryError", "discover_from_provider"]
