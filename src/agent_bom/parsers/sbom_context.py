"""Bounded, source-scoped import of cloud evidence attached to software BOMs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface
from agent_bom.sbom import parse_sbom_document
from agent_bom.security import sanitize_sensitive_payload

_PREFIX = "agent-bom:cloud-inventory:"
CLOUD_INVENTORY_PROPERTY = _PREFIX + "v1"
_MAX_BYTES = 10 * 1024 * 1024


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("SBOM JSON contains duplicate object keys")
        result[key] = value
    return result


def _json(text: str | bytes) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError("SBOM evidence must contain valid JSON with unique keys") from exc


def _invalid_constant(value: str) -> None:
    raise ValueError("Non-finite JSON numbers are not supported")


def _annotation_context(annotation: dict[str, Any]) -> dict[str, Any]:
    statement = annotation.get("statement", annotation.get("comment", ""))
    if not isinstance(statement, str) or not statement.lstrip().startswith("{"):
        return {}
    try:
        parsed = _json(statement)
    except ValueError:
        if _PREFIX in statement:
            raise
        return {}
    return parsed if isinstance(parsed, dict) else {}


def read_cloud_context(document: dict[str, Any]) -> dict[str, Any] | list[dict[str, Any]] | None:
    """Read exactly one v1 document-level extension; reject ambiguous evidence."""
    candidates: list[Any] = []
    if document.get("bomFormat") == "CycloneDX":
        metadata = document.get("metadata", {})
        if not isinstance(metadata, dict) or not isinstance(metadata.get("properties", []), list):
            raise ValueError("Invalid CycloneDX metadata properties")
        for prop in metadata.get("properties", []):
            if isinstance(prop, dict) and str(prop.get("name", "")).startswith(_PREFIX):
                if prop["name"] != CLOUD_INVENTORY_PROPERTY or not isinstance(prop.get("value"), str):
                    raise ValueError("Unsupported cloud-inventory extension")
                candidates.append(_json(prop["value"]))
    else:
        graph = document.get("@graph")
        roots = (
            [n.get("spdxId") for n in graph if isinstance(n, dict) and n.get("type") == "SpdxDocument"] if isinstance(graph, list) else []
        )
        annotations = graph if isinstance(graph, list) else document.get("annotations", [])
        if not isinstance(annotations, list):
            raise ValueError("Invalid SPDX annotations")
        for annotation in annotations:
            if not isinstance(annotation, dict):
                continue
            for key, evidence in _annotation_context(annotation).items():
                if key.startswith(_PREFIX):
                    if key != CLOUD_INVENTORY_PROPERTY:
                        raise ValueError("Unsupported cloud-inventory extension")
                    if isinstance(graph, list) and (
                        len(roots) != 1
                        or annotation.get("subject") != roots[0]
                        or annotation.get("type") != "Annotation"
                        or annotation.get("contentType") != "application/json"
                    ):
                        raise ValueError("Cloud-inventory annotation must identify the SPDX document")
                    candidates.append(evidence)
    if not candidates:
        return None
    if len(candidates) != 1:
        raise ValueError("Ambiguous cloud-inventory extensions")
    return _validate_cloud_evidence(candidates[0])


def _validate_cloud_evidence(evidence: Any) -> dict[str, Any] | list[dict[str, Any]] | None:
    if (
        not isinstance(evidence, dict)
        or type(evidence.get("schema_version")) is not int
        or evidence["schema_version"] != 1
        or evidence.get("source") != "cloud_inventory"
        or evidence.get("coverage") != "not_assessed"
    ):
        raise ValueError("Invalid cloud-inventory v1 evidence envelope")
    inventory = evidence.get("inventory")
    if not isinstance(inventory, dict | list) or (isinstance(inventory, list) and any(not isinstance(row, dict) for row in inventory)):
        raise ValueError("Cloud inventory must be an object or a list of objects")
    sanitized = sanitize_sensitive_payload(inventory)
    return sanitized if isinstance(sanitized, dict | list) else None


def load_sbom_agent(path: str, name: str | None = None) -> tuple[Agent, str]:
    """Read packages and cloud evidence from the same bounded file snapshot."""
    with Path(path).open("rb") as stream:
        raw = stream.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        raise ValueError("SBOM exceeds the 10 MiB import limit")
    document = _json(raw)
    if not isinstance(document, dict):
        raise ValueError("SBOM must be a JSON object")
    packages, fmt, detected = parse_sbom_document(document, source_name="uploaded SBOM")
    inventory = read_cloud_context(document)
    provenance = {"source": "sbom", "document_sha256": hashlib.sha256(raw).hexdigest(), "format": fmt, "coverage": "not_assessed"}
    if inventory is not None:
        for row in inventory if isinstance(inventory, list) else [inventory]:
            row["import_provenance"] = dict(provenance)
    resource_name = name or detected or Path(path).stem
    agent = Agent(
        name=f"sbom:{resource_name}",
        agent_type=AgentType.CUSTOM,
        config_path=path,
        source="sbom",
        mcp_servers=[MCPServer(name=resource_name, command="sbom", args=[path], packages=packages, surface=ServerSurface.SBOM)],
        metadata={"sbom_import": {**provenance, "cloud_inventory": inventory}},
    )
    return agent, fmt


def combine_cloud_inventories(existing: Any, incoming: Any) -> Any:
    """Retain both observations without joining by names or overwriting scopes."""
    if existing is None:
        return incoming
    if incoming is None:
        return existing
    return [*(existing if isinstance(existing, list) else [existing]), *(incoming if isinstance(incoming, list) else [incoming])]


def imported_cloud_inventory(agents: list[Agent]) -> Any:
    inventory = None
    for agent in agents:
        evidence = agent.metadata.get("sbom_import") if agent.source == "sbom" else None
        if isinstance(evidence, dict):
            inventory = combine_cloud_inventories(inventory, evidence.get("cloud_inventory"))
    return inventory
