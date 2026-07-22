"""Stamp GitHub (or other) repo trust-card metadata onto the graph.

When a ``--repo`` / ``repo_url`` scan attaches ``repo_trust`` on the report, this
overlay makes that metadata traversable next to the repo-structure tree:

- Ensures an ``APPLICATION`` node for the repository (even when no findings
  derived an app yet) so humans and agents have a correlation root.
- Copies trust fields onto that APPLICATION and, when present, the repo-root
  ``DIRECTORY`` node (``directory:.``).

Best-effort and additive. No-op when ``repo_trust`` is absent. Never invents
stars/contributors — only mirrors what the trust fetch already recorded.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, GraphSemanticLayer

_OVERLAY_SOURCE = "repo-trust-overlay"
_ROOT_DIR_ID = "directory:."


def _trust_payload(report_json: dict[str, Any]) -> dict[str, Any] | None:
    raw = report_json.get("repo_trust")
    if isinstance(raw, dict) and raw:
        return raw
    inventory = report_json.get("project_inventory")
    if isinstance(inventory, dict):
        nested = inventory.get("repo_trust")
        if isinstance(nested, dict) and nested:
            return nested
    return None


def _app_id(trust: dict[str, Any]) -> str:
    full = str(trust.get("full_name") or "").strip()
    if full:
        return f"application:repo:{full}"
    url = str(trust.get("repo_url") or "").strip()
    if url:
        return f"application:repo:{url}"
    return "application:repo:scanned"


def _label(trust: dict[str, Any]) -> str:
    full = str(trust.get("full_name") or "").strip()
    if full:
        return full
    name = str(trust.get("name") or "").strip()
    if name:
        return name
    return str(trust.get("repo_url") or "scanned repository")


def _trust_attrs(trust: dict[str, Any]) -> dict[str, Any]:
    """Subset of trust fields safe to put on graph node attributes."""
    keys = (
        "status",
        "provider",
        "host",
        "repo_url",
        "full_name",
        "owner",
        "name",
        "description",
        "language",
        "license",
        "default_branch",
        "stars",
        "forks",
        "watchers",
        "open_issues",
        "contributors",
        "pushed_at",
        "created_at",
        "updated_at",
        "visibility",
        "archived",
        "is_fork",
        "homepage",
    )
    out: dict[str, Any] = {"source": _OVERLAY_SOURCE, "is_repo_trust": True}
    for key in keys:
        if key in trust and trust[key] is not None:
            out[key] = trust[key]
    topics = trust.get("topics")
    if isinstance(topics, list) and topics:
        out["topics"] = [str(t) for t in topics if isinstance(t, str)][:20]
    return out


def apply_repo_trust_overlay(
    graph: UnifiedGraph,
    report_json: dict[str, Any],
    now: datetime,
) -> dict[str, int]:
    """Attach repo trust metadata to APPLICATION (+ optional root DIRECTORY)."""
    counts = {"applications": 0, "directory_stamps": 0}
    trust = _trust_payload(report_json)
    if not trust:
        return counts

    attrs = _trust_attrs(trust)
    app_id = _app_id(trust)
    now_iso = now.isoformat()

    existing = graph.nodes.get(app_id)
    if existing is None:
        graph.add_node(
            UnifiedNode(
                id=app_id,
                entity_type=EntityType.APPLICATION,
                label=_label(trust),
                attributes=attrs,
                data_sources=[_OVERLAY_SOURCE],
                dimensions=NodeDimensions(surface=GraphSemanticLayer.APP.value),
                first_seen=now_iso,
                last_seen=now_iso,
            )
        )
        counts["applications"] = 1
    else:
        merged = dict(existing.attributes or {})
        merged.update(attrs)
        existing.attributes = merged
        sources = list(existing.data_sources or [])
        if _OVERLAY_SOURCE not in sources:
            sources.append(_OVERLAY_SOURCE)
            existing.data_sources = sources
        existing.last_seen = now_iso

    root = graph.nodes.get(_ROOT_DIR_ID)
    if root is not None and root.entity_type == EntityType.DIRECTORY:
        merged = dict(root.attributes or {})
        for key, value in attrs.items():
            if key == "source":
                continue
            merged[key] = value
        merged["repo_trust_source"] = _OVERLAY_SOURCE
        root.attributes = merged
        counts["directory_stamps"] = 1

    return counts
