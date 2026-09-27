"""Bounded per-agent composition exports from persisted scan evidence."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from agent_bom.evidence.agent_bom import (
    AREAS,
    MAX_AGENT_BOM_BYTES,
    AgentBomComponent,
    AgentBomContent,
    AgentBomCoverage,
    AgentBomDocument,
    AgentBomReceipt,
    AgentBomRelationship,
    AgentBomSubject,
    Relationship,
    _key,
    content_digest,
)
from agent_bom.security import sanitize_text

MAX_SCAN_INPUT_BYTES = 32 * 1024 * 1024
MAX_SCAN_AGENTS = 10000


class AgentSelectionError(ValueError):
    """Selection is missing, ambiguous, or has conflicting identity fields."""


def _text(value: Any, limit: int = 200) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Expected a non-empty string")
    return sanitize_text(value, max_len=limit)


def _identity(row: dict[str, Any]) -> str:
    values = [row[key] for key in ("canonical_id", "stable_id") if row.get(key) is not None]
    if not values or any(not isinstance(value, str) or not value.strip() or len(value) > 512 for value in values):
        raise AgentSelectionError("Identity evidence is unavailable")
    if len(set(values)) != 1:
        raise AgentSelectionError("Identity fields disagree")
    return values[0]


def _rows(value: Any, limit: int = 10000) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > limit or any(not isinstance(row, dict) for row in value):
        raise ValueError("Invalid or oversized scan inventory")
    return value


def read_scan_json(raw: bytes) -> dict[str, Any]:
    """Parse a bounded scan document without executing discovery or provider calls."""
    if len(raw) > MAX_SCAN_INPUT_BYTES:
        raise ValueError("Scan input exceeds 32 MiB")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError("Non-finite JSON number")

    try:
        result = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid scan JSON") from exc
    if not isinstance(result, dict):
        raise ValueError("Expected a scan object")
    return result


def build_scan_agent_bom(result: dict[str, Any], *, agent_id: str | None, tenant_id: str, scan_id: str | None = None) -> AgentBomDocument:
    """Select exact recorded identity; never rediscover or reconstruct it from names.

    This exports composition and a source-scan receipt. Findings, evaluated
    grants, runtime activity, and compliance remain separate evidence.
    """
    agents = _rows(result.get("agents"), MAX_SCAN_AGENTS)
    if agent_id is None:
        if len(agents) != 1:
            raise AgentSelectionError("Expected exactly one agent")
        selected = agents
    else:
        selected = [row for row in agents if agent_id in (row.get("canonical_id"), row.get("stable_id"))]
    if len(selected) != 1:
        raise AgentSelectionError("Expected exactly one exact agent ID")
    agent = selected[0]
    subject_id = _identity(agent)
    source_scan = scan_id if scan_id is not None else result.get("scan_id")
    if not isinstance(source_scan, str) or not source_scan.strip() or len(source_scan) > 400:
        raise ValueError("Source scan ID is required")
    captured = result.get("generated_at") or result.get("scan_timestamp")
    if not isinstance(captured, str):
        raise ValueError("Source scan timestamp is required")
    observed_at = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    if observed_at.utcoffset() is None:
        raise ValueError("Source scan timestamp must include a timezone")
    receipt = AgentBomReceipt(
        evidence_id=f"scan:{source_scan}",
        source="agent-bom-scan",
        method="scan",
        observed_at=observed_at,
        assurance="producer_asserted",
    )
    receipts = (receipt.evidence_id,)
    components: dict[str, AgentBomComponent] = {}
    edges: dict[tuple[str, str, str], AgentBomRelationship] = {}
    examined = 0

    def add(row: AgentBomComponent, parent: str, relation: Relationship) -> None:
        nonlocal examined
        examined += 1
        if examined > 10000:
            raise ValueError("Selected composition exceeds the export budget")
        if row.component_id in components and components[row.component_id] != row:
            raise ValueError("Conflicting component identity")
        components[row.component_id] = row
        edge = AgentBomRelationship(source=parent, target=row.component_id, relationship=relation, basis="declared", evidence_ids=receipts)
        edges[(parent, row.component_id, relation)] = edge

    for server in _rows(agent.get("mcp_servers", [])):
        parent = subject_id
        # Non-MCP scan wrappers are not MCP servers. Their package membership
        # is retained directly under the selected subject without invented tools.
        if server.get("surface") == "mcp-server":
            parent = _key("mcp_server", _identity(server))
            add(
                AgentBomComponent(component_id=parent, kind="mcp_server", name=_text(server.get("name")), evidence_ids=receipts),
                subject_id,
                "configured_with",
            )
            for index, tool in enumerate(_rows(server.get("tools", []))):
                tool_id = _key("tool", parent, str(index))
                add(
                    AgentBomComponent(component_id=tool_id, kind="tool", name=_text(tool.get("name")), evidence_ids=receipts),
                    parent,
                    "provides_tool",
                )
        for package in _rows(server.get("packages", [])):
            name, ecosystem = (_text(package.get(key)) for key in ("name", "ecosystem"))
            version = _text(package["version"]) if package.get("version") else None
            add(
                AgentBomComponent(
                    component_id=_key("package", ecosystem, name, version or ""),
                    kind="package",
                    name=name,
                    version=version,
                    ecosystem=ecosystem,
                    evidence_ids=receipts,
                ),
                parent,
                "contains_package",
            )

    content = AgentBomContent(
        tenant_id=tenant_id,
        subject=AgentBomSubject(
            agent_id=subject_id,
            name=_text(agent.get("name")),
            agent_type=_text(agent.get("agent_type") or agent.get("type")),
            version=_text(agent["version"]) if agent.get("version") else None,
            source_id=_text(agent["source_id"], 512) if agent.get("source_id") else None,
            identity_status="observed",
        ),
        components=tuple(components[key] for key in sorted(components)),
        relationships=tuple(edges[key] for key in sorted(edges)),
        evidence=(receipt,),
        coverage=tuple(
            AgentBomCoverage(
                area=area,
                status="partial" if area == "composition" else "not_assessed",
                reason="selected_scan_inventory_only" if area == "composition" else "assessment_not_included_in_composition_export",
                evidence_ids=receipts if area == "composition" else (),
            )
            for area in AREAS
        ),
    )
    # Re-exporting the same source is deterministic; this is the source time,
    # not a claim that collection happened again when the download was requested.
    document = AgentBomDocument(generated_at=observed_at, snapshot_id=content_digest(content), content=content)
    if len(document.model_dump_json().encode()) > MAX_AGENT_BOM_BYTES:
        raise ValueError("Per-agent BOM exceeds 8 MiB")
    return document
