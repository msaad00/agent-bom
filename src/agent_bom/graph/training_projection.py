"""Model, dataset and serving evidence projected from their own report sections."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def project_model_provenance(graph: UnifiedGraph, model_provenance: list[dict[str, Any]]) -> None:
    for model_dict in model_provenance:
        model_name = model_dict.get("model_name", model_dict.get("name", "unknown"))
        model_id = _model_node_id(model_name)
        graph.add_node(
            UnifiedNode(
                id=model_id,
                entity_type=EntityType.MODEL,
                label=model_name,
                attributes={
                    "framework": model_dict.get("framework", ""),
                    "source": model_dict.get("source", ""),
                    "hash": model_dict.get("hash", ""),
                    "verified": model_dict.get("verified", False),
                },
                data_sources=["model-provenance"],
            )
        )


def project_serving_configs(graph: UnifiedGraph, serving_configs: list[dict[str, Any]]) -> None:
    for serving_dict in serving_configs:
        container_image = serving_dict.get("container_image", "")
        if not container_image:
            continue
        container_id = f"container:{container_image}"
        graph.add_node(
            UnifiedNode(
                id=container_id,
                entity_type=EntityType.CONTAINER,
                label=serving_dict.get("name") or container_image,
                attributes={
                    "container_image": container_image,
                    "framework": serving_dict.get("framework", ""),
                    "source_file": serving_dict.get("source_file", ""),
                    "model_uri": serving_dict.get("model_uri", ""),
                    "endpoint_url": serving_dict.get("endpoint_url", ""),
                    "security_flags": serving_dict.get("security_flags", []),
                },
                dimensions=NodeDimensions(surface="container"),
                data_sources=["training-pipeline"],
            )
        )
        model_id = _resolve_model_id(graph, serving_dict.get("model_uri", ""))
        if model_id:
            graph.add_edge(
                UnifiedEdge(
                    source=container_id,
                    target=model_id,
                    relationship=RelationshipType.SERVES_MODEL,
                )
            )


def project_dataset_cards(graph: UnifiedGraph, dataset_cards: dict[str, Any] | None) -> None:
    if isinstance(dataset_cards, dict):
        for dataset_dict in dataset_cards.get("datasets", []):
            dataset_name = dataset_dict.get("name") or dataset_dict.get("source_file") or "unknown-dataset"
            graph.add_node(
                UnifiedNode(
                    id=f"dataset:{dataset_name}",
                    entity_type=EntityType.DATASET,
                    label=dataset_name,
                    attributes={
                        "description": dataset_dict.get("description", ""),
                        "license": dataset_dict.get("license", ""),
                        "source_url": dataset_dict.get("source_url", ""),
                        "version": dataset_dict.get("version", ""),
                        "features": dataset_dict.get("features", []),
                        "splits": dataset_dict.get("splits", {}),
                        "size_bytes": dataset_dict.get("size_bytes", 0),
                        "source_file": dataset_dict.get("source_file", ""),
                        "languages": dataset_dict.get("languages", []),
                        "task_categories": dataset_dict.get("task_categories", []),
                        "security_flags": dataset_dict.get("security_flags", []),
                    },
                    compliance_tags=_flatten_compliance_tags(dataset_dict.get("compliance_tags")),
                    data_sources=["dataset-cards"],
                )
            )


def _flatten_compliance_tags(raw: Any) -> list[str]:
    """Normalize arbitrary compliance-tag payloads into a simple list."""
    if not raw:
        return []
    if isinstance(raw, list):
        return sorted({str(tag) for tag in raw if tag})
    if isinstance(raw, dict):
        tags: set[str] = set()
        for value in raw.values():
            if isinstance(value, list):
                tags.update(str(tag) for tag in value if tag)
            elif value:
                tags.add(str(value))
        return sorted(tags)
    return [str(raw)]


_MODEL_PROVIDER_PREFIXES = frozenset(
    {
        "openai",
        "azure",
        "azure_openai",
        "anthropic",
        "google",
        "gemini",
        "vertex",
        "vertex_ai",
        "vertexai",
        "bedrock",
        "aws",
        "cohere",
        "mistral",
        "mistralai",
        "meta",
        "llama",
        "huggingface",
        "hf",
        "ollama",
        "together",
        "groq",
        "fireworks",
        "replicate",
        "xai",
        "deepseek",
        "perplexity",
        "watsonx",
        "databricks",
    }
)


def _normalize_model_ref(ref: str) -> str:
    """Fold a model reference to a canonical fingerprint.

    Lower-cases and strips leading provider-prefix segments
    (``openai:gpt-4o``, ``openai/gpt-4o``, ``azure/openai/gpt-4o``) so refs
    naming the same model from different producers collapse to one identity.
    """
    label = str(ref or "").strip().lower()
    if not label:
        return ""
    parts = [p for p in label.replace("://", "/").replace(":", "/").split("/") if p]
    if not parts:
        return label
    while len(parts) > 1 and parts[0] in _MODEL_PROVIDER_PREFIXES:
        parts.pop(0)
    return "/".join(parts)


def _model_node_id(ref: str) -> str:
    """Canonical graph node id for a model, shared by every model producer.

    Model provenance, framework ``model_refs``, ``unique_models`` and
    serving-config URI resolution all route through here so a given model
    yields exactly ONE node regardless of which source discovered it — the
    node the ``serves_model`` edges point at also carries the provenance
    hash/verified attributes.
    """
    return f"model:{_normalize_model_ref(ref)}"


def _resolve_model_id(graph: UnifiedGraph, model_uri: str) -> str:
    """Best-effort link from a serving config model URI to a known model node."""
    if not model_uri:
        return ""
    candidates = [part for part in model_uri.replace("://", "/").replace(":", "/").split("/") if part]
    for candidate in reversed(candidates):
        model_id = _model_node_id(candidate)
        if graph.has_node(model_id):
            return model_id
    return ""
