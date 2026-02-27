"""Hugging Face Hub discovery — models, spaces, and inference endpoints.

Requires ``huggingface-hub``.  Install with::

    pip install 'agent-bom[huggingface]'

Authentication uses HF_TOKEN env var or --hf-token flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    token: str | None = None,
    username: str | None = None,
    organization: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI assets from Hugging Face Hub.

    Discovers models (with framework/library metadata), Spaces (Gradio/Streamlit
    apps), and inference endpoints.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``huggingface-hub`` is not installed.
    """
    try:
        import huggingface_hub  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "huggingface-hub is required for Hugging Face discovery. Install with: pip install 'agent-bom[huggingface]'"
        )

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_token = token or os.environ.get("HF_TOKEN", "")

    author = organization or username
    if not author and not resolved_token:
        warnings.append(
            "HF_TOKEN not set and no --hf-username/--hf-organization provided. Provide credentials to discover your models and spaces."
        )
        return agents, warnings

    # ── Models ────────────────────────────────────────────────────────────
    try:
        model_agents, model_warns = _discover_models(resolved_token, author)
        agents.extend(model_agents)
        warnings.extend(model_warns)
    except Exception as exc:
        warnings.append(f"HF model discovery error: {exc}")

    # ── Spaces ────────────────────────────────────────────────────────────
    try:
        space_agents, space_warns = _discover_spaces(resolved_token, author)
        agents.extend(space_agents)
        warnings.extend(space_warns)
    except Exception as exc:
        warnings.append(f"HF Spaces discovery error: {exc}")

    # ── Inference Endpoints ───────────────────────────────────────────────
    if resolved_token:
        try:
            ep_agents, ep_warns = _discover_inference_endpoints(resolved_token)
            agents.extend(ep_agents)
            warnings.extend(ep_warns)
        except Exception as exc:
            warnings.append(f"HF inference endpoint discovery error: {exc}")

    return agents, warnings


def _discover_models(
    token: str,
    author: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover models from Hugging Face Hub."""
    from huggingface_hub import HfApi

    agents: list[Agent] = []
    warnings: list[str] = []

    api = HfApi(token=token or None)

    try:
        models = list(api.list_models(author=author, limit=200))
    except Exception as exc:
        warnings.append(f"Could not list HF models: {exc}")
        return agents, warnings

    for model in models:
        model_id = getattr(model, "id", "unknown") or getattr(model, "modelId", "unknown")
        library = getattr(model, "library_name", None) or ""
        pipeline_tag = getattr(model, "pipeline_tag", None) or ""
        tags = getattr(model, "tags", []) or []

        # Extract framework packages from library metadata
        packages = _extract_framework_packages(library, tags)

        server = MCPServer(
            name=f"hf-model:{model_id}",
            transport=TransportType.UNKNOWN,
            packages=packages,
        )

        # Add tools based on pipeline tag
        if pipeline_tag:
            server.tools.append(
                MCPTool(
                    name=pipeline_tag,
                    description=f"HF pipeline: {pipeline_tag}",
                )
            )

        # Parse model card metadata (YAML frontmatter)
        card_meta = _parse_model_card(model)

        agent = Agent(
            name=f"hf-model:{model_id}",
            agent_type=AgentType.CUSTOM,
            config_path=f"huggingface://models/{model_id}",
            source="huggingface-model",
            version=library or pipeline_tag or None,
            mcp_servers=[server],
            metadata=card_meta,
        )
        agents.append(agent)

    return agents, warnings


def _discover_spaces(
    token: str,
    author: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover Spaces (Gradio/Streamlit apps) from Hugging Face Hub."""
    from huggingface_hub import HfApi

    agents: list[Agent] = []
    warnings: list[str] = []

    api = HfApi(token=token or None)

    try:
        spaces = list(api.list_spaces(author=author, limit=100))
    except Exception as exc:
        warnings.append(f"Could not list HF Spaces: {exc}")
        return agents, warnings

    for space in spaces:
        space_id = getattr(space, "id", "unknown")
        sdk = getattr(space, "sdk", None) or ""

        packages: list[Package] = []
        if sdk.lower() == "gradio":
            packages.append(Package(name="gradio", version="unknown", ecosystem="pypi"))
        elif sdk.lower() == "streamlit":
            packages.append(Package(name="streamlit", version="unknown", ecosystem="pypi"))
        elif sdk.lower() == "docker":
            pass  # Docker spaces — image scanning needed

        server = MCPServer(
            name=f"hf-space:{space_id}",
            transport=TransportType.UNKNOWN,
            packages=packages,
        )

        agent = Agent(
            name=f"hf-space:{space_id}",
            agent_type=AgentType.CUSTOM,
            config_path=f"huggingface://spaces/{space_id}",
            source="huggingface-space",
            version=sdk or None,
            mcp_servers=[server],
        )
        agents.append(agent)

    return agents, warnings


def _discover_inference_endpoints(
    token: str,
) -> tuple[list[Agent], list[str]]:
    """Discover deployed inference endpoints."""
    from huggingface_hub import HfApi

    agents: list[Agent] = []
    warnings: list[str] = []

    api = HfApi(token=token)

    try:
        endpoints = list(api.list_inference_endpoints())
    except Exception as exc:
        warnings.append(f"Could not list HF inference endpoints: {exc}")
        return agents, warnings

    for ep in endpoints:
        ep_name = getattr(ep, "name", "unknown")
        model_id = getattr(ep, "model_id", None) or getattr(ep, "repository", None) or ""
        status = getattr(ep, "status", "unknown")
        framework = getattr(ep, "framework", None) or ""

        packages = _extract_framework_packages(framework, [])

        server = MCPServer(
            name=f"hf-endpoint:{ep_name}",
            transport=TransportType.UNKNOWN,
            packages=packages,
        )

        agent = Agent(
            name=f"hf-endpoint:{ep_name}",
            agent_type=AgentType.CUSTOM,
            config_path=f"huggingface://endpoints/{ep_name}",
            source="huggingface-endpoint",
            version=str(status),
            mcp_servers=[server],
        )
        agents.append(agent)

    return agents, warnings


def _parse_model_card(model_info: object) -> dict:
    """Extract structured metadata from a HuggingFace model card.

    Pulls license, datasets, language, tags, pipeline_tag, and evaluation
    metrics from the model info object returned by ``HfApi.list_models()``.
    """
    meta: dict = {}

    # card_data is a ModelCardData object (or None) with YAML frontmatter fields
    card = getattr(model_info, "card_data", None)
    if card is not None:
        # License (SPDX identifier)
        license_val = getattr(card, "license", None)
        if license_val:
            meta["license"] = license_val

        # Training datasets
        datasets = getattr(card, "datasets", None)
        if datasets:
            meta["datasets"] = list(datasets) if not isinstance(datasets, list) else datasets

        # Languages
        language = getattr(card, "language", None)
        if language:
            meta["language"] = list(language) if not isinstance(language, list) else language

        # Evaluation metrics from model-index
        model_index = getattr(card, "model_index", None)
        if model_index:
            metrics = []
            for entry in model_index:
                for result in getattr(entry, "results", []) or []:
                    for m in getattr(result, "metrics", []) or []:
                        name = getattr(m, "name", None) or getattr(m, "type", None)
                        value = getattr(m, "value", None)
                        if name and value is not None:
                            metrics.append({"name": str(name), "value": value})
            if metrics:
                meta["eval_metrics"] = metrics

    # Fields available directly on the model info object
    pipeline_tag = getattr(model_info, "pipeline_tag", None)
    if pipeline_tag:
        meta["pipeline_tag"] = pipeline_tag

    tags = getattr(model_info, "tags", None)
    if tags:
        meta["tags"] = list(tags) if not isinstance(tags, list) else tags

    # Downloads and likes (popularity signals for risk assessment)
    downloads = getattr(model_info, "downloads", None)
    if downloads is not None:
        meta["downloads"] = downloads

    likes = getattr(model_info, "likes", None)
    if likes is not None:
        meta["likes"] = likes

    return meta


def _extract_framework_packages(
    library: str,
    tags: list[str],
) -> list[Package]:
    """Extract Python packages from HF model library/tag metadata."""
    library_packages: dict[str, str] = {
        "transformers": "transformers",
        "pytorch": "torch",
        "tensorflow": "tensorflow",
        "jax": "jax",
        "flax": "flax",
        "diffusers": "diffusers",
        "sentence-transformers": "sentence-transformers",
        "peft": "peft",
        "trl": "trl",
        "gguf": "llama-cpp-python",
        "onnx": "onnxruntime",
        "safetensors": "safetensors",
        "timm": "timm",
        "spacy": "spacy",
        "flair": "flair",
        "adapter-transformers": "adapter-transformers",
    }

    packages: list[Package] = []
    seen: set[str] = set()

    # From library_name field
    lib_lower = library.lower().strip()
    if lib_lower in library_packages and library_packages[lib_lower] not in seen:
        pkg_name = library_packages[lib_lower]
        packages.append(Package(name=pkg_name, version="unknown", ecosystem="pypi"))
        seen.add(pkg_name)

    # From tags
    for tag in tags:
        tag_lower = tag.lower().strip()
        if tag_lower in library_packages and library_packages[tag_lower] not in seen:
            pkg_name = library_packages[tag_lower]
            packages.append(Package(name=pkg_name, version="unknown", ecosystem="pypi"))
            seen.add(pkg_name)

    return packages
