"""Unambiguous resource aliases used to join findings with discovered cloud assets."""

from collections import defaultdict
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _resource_tail(value: Any) -> str:
    """Return the provider-resource name at the end of an ARN/path-like ID."""
    normalized = _clean_graph_part(value).rstrip("/")
    if not normalized:
        return ""
    return normalized.rsplit("/", 1)[-1].rsplit(":", 1)[-1].casefold()


_CloudResourceAliasIndex = dict[tuple[str, str], set[str]]


def _build_cloud_resource_alias_index(graph: UnifiedGraph) -> _CloudResourceAliasIndex:
    """Index provider-native, typed, and name aliases in one graph pass."""
    index: _CloudResourceAliasIndex = defaultdict(set)
    for node in graph.nodes_by_type(EntityType.CLOUD_RESOURCE):
        provider = _clean_graph_part(node.attributes.get("cloud_provider") or node.dimensions.cloud_provider).casefold()
        if not provider:
            continue
        identifiers = {
            _clean_graph_part(node.attributes.get("resource_id")).rstrip("/").casefold(),
            _clean_graph_part(node.attributes.get("resource_name")).rstrip("/").casefold(),
        }
        identifiers.discard("")
        kinds = {
            _clean_graph_part(node.attributes.get("resource_type")).casefold(),
            _clean_graph_part(node.attributes.get("resource_kind")).casefold(),
            _clean_graph_part(node.attributes.get("cloud_service")).casefold(),
        }
        kinds.update(part.casefold() for part in node.id.split(":"))
        kinds.discard("")
        for identifier in identifiers:
            index[(provider, f"exact:{identifier}")].add(node.id)
            tail = _resource_tail(identifier)
            if not tail:
                continue
            index[(provider, f"name:{tail}")].add(node.id)
            for kind in kinds:
                index[(provider, f"typed:{kind}:{tail}")].add(node.id)
    return dict(index)


def _resolve_cloud_resource_node_id(
    graph: UnifiedGraph,
    provider: str,
    resource_id: Any,
    *,
    alias_index: _CloudResourceAliasIndex | None = None,
) -> str | None:
    """Resolve a finding resource reference to one existing inventory node.

    CIS providers commonly report ``bucket/name`` or a provider-native ARN,
    while inventory uses a typed graph ID.  Match exact provider-native IDs
    first, then a typed ``kind/name`` alias, and finally a unique provider/name
    alias. Ambiguity deliberately returns ``None`` so unrelated same-named
    resources are never collapsed.
    """
    raw = _clean_graph_part(resource_id).rstrip("/")
    provider_key = _clean_graph_part(provider).casefold()
    if not raw or not provider_key:
        return None

    raw_key = raw.casefold()
    raw_tail = _resource_tail(raw)
    path_parts = [part.casefold() for part in raw.split("/") if part]
    type_hint = path_parts[-2] if len(path_parts) >= 2 and not raw_key.startswith("arn:") else ""

    index = alias_index if alias_index is not None else _build_cloud_resource_alias_index(graph)
    candidate_sets = [index.get((provider_key, f"exact:{raw_key}"), set())]
    if type_hint:
        candidate_sets.append(index.get((provider_key, f"typed:{type_hint}:{raw_tail}"), set()))
    candidate_sets.append(index.get((provider_key, f"name:{raw_tail}"), set()))

    for candidates in candidate_sets:
        unique = sorted(candidates)
        if len(unique) == 1:
            return unique[0]
        if len(unique) > 1:
            return None
    return None
