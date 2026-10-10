"""Graph HTTP request/response contracts and OpenAPI evidence schemas."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from agent_bom.graph.hop_evidence import hop_evidence_schema
from agent_bom.graph.scope import GraphScopeKind

GraphIdentifier = Annotated[str, StringConstraints(pattern=r"^[^\x00]*$")]


class GraphScopeDescriptor(BaseModel):
    kind: GraphScopeKind
    id: str | None
    observed: bool
    basis: Literal["persisted_graph_snapshot", "persisted_node_attributes", "persisted_graph_traversal"]


class GraphCompletenessResponse(BaseModel):
    status: Literal["complete", "sampled", "truncated"]
    complete: bool
    sampled: bool
    truncated: bool
    returned: int
    total: int | None = None
    reason: str | None = None


class IncidentEdgePageCompleteness(GraphCompletenessResponse):
    scope: Literal["incident_edge_page"] = "incident_edge_page"
    missing_endpoint_count: int = 0


class IncidentEdgePageResponse(BaseModel):
    """Recorded relationship page, not a permission or collection-coverage verdict."""

    evidence_scope: Literal["current_estate", "historical_scan"] | None = None

    snapshot_generation: str | None
    scan_id: str
    node_id: str
    found: bool
    direction: Literal["in", "out", "both"]
    limit: int
    node: dict[str, Any] | None
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    next_cursor: str | None
    completeness: IncidentEdgePageCompleteness


class ScopedGraphCompleteness(BaseModel):
    source: GraphCompletenessResponse
    result: GraphCompletenessResponse
    edges: GraphCompletenessResponse


class ScopedGraphResponse(BaseModel):
    scan_id: str
    tenant_id: str
    created_at: str
    scope: GraphScopeDescriptor
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    stats: dict[str, Any]
    completeness: ScopedGraphCompleteness


_TECHNIQUE_MAPPING_OPENAPI_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "A typed MITRE ATT&CK / ATLAS technique mapped to one hop of the attack path, "
        "derived from the path's observed graph evidence (edge relationship + node type). "
        "These are potential/mapped techniques for the kill-chain sequence, NOT a claim of "
        "detected attacker activity. Technique and tactic IDs resolve against the bundled catalog."
    ),
    "required": ["hop_index", "technique_id", "catalog", "tactics", "provenance", "confidence"],
    "properties": {
        "hop_index": {"type": "integer", "minimum": 0, "description": "0-based position in the kill-chain edge sequence."},
        "technique_id": {"type": "string", "description": "ATT&CK (e.g. T1078) or ATLAS (e.g. AML.T0053) technique ID."},
        "technique_name": {"type": "string"},
        "catalog": {"type": "string", "enum": ["attack", "atlas"]},
        "tactics": {"type": "array", "items": {"type": "string"}, "description": "Catalog-resolved tactic phase names / IDs."},
        "provenance": {"type": "string", "description": "The observed edge evidence that produced the mapping."},
        "confidence": {"anyOf": [{"type": "number", "minimum": 0.0, "maximum": 1.0}, {"type": "null"}]},
        "evidence_basis": {"type": ["string", "null"], "enum": ["observed", "runtime_observed", "inferred", "modeled", None]},
    },
    "additionalProperties": False,
}

_ATTACK_PATH_ITEM_OPENAPI_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "exposure_path": None,  # filled after _EXPOSURE_PATH_OPENAPI_SCHEMA is defined
        "reachability": {
            "type": "string",
            "enum": ["confirmed", "likely", "unlikely", "unknown"],
            "description": "Evidence strength for whether the path is executable; structural topology alone is unknown.",
        },
        "reachability_basis": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Machine-readable evidence that produced the reachability verdict.",
        },
        "hop_evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "relationship_provenance": {"type": "string", "enum": ["recorded", "unavailable"]},
                    "correlation_identity_status": {"type": "string", "enum": ["current", "recomputation_required", "unavailable"]},
                    "authority": hop_evidence_schema()["properties"]["authority"],
                },
                "additionalProperties": True,
            },
        },
        "technique_mappings": {"type": "array", "items": _TECHNIQUE_MAPPING_OPENAPI_SCHEMA},
        "mitre_technique_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Deduped technique IDs mapped across the path's hops (convenience projection).",
        },
    },
    "additionalProperties": True,
}

_EXPOSURE_PATH_OPENAPI_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Investigation-first exposure path shared by graph views and report exports.",
    "required": ["id", "label", "summary", "riskScore", "severity", "source", "target", "hops", "relationships"],
    "properties": {
        "id": {"type": "string"},
        "rank": {"type": "integer", "minimum": 1},
        "label": {"type": "string"},
        "summary": {"type": "string"},
        "riskScore": {"type": "number"},
        "severity": {"type": "string"},
        "source": {"type": "object", "additionalProperties": True},
        "target": {"type": "object", "additionalProperties": True},
        "hops": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "hopEvidence": {"type": "array", "items": hop_evidence_schema()},
        "relationships": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "nodeIds": {"type": "array", "items": {"type": "string"}},
        "edgeIds": {"type": "array", "items": {"type": "string"}},
        "findings": {"type": "array", "items": {"type": "string"}},
        "affectedAgents": {"type": "array", "items": {"type": "string"}},
        "affectedServers": {"type": "array", "items": {"type": "string"}},
        "reachableTools": {"type": "array", "items": {"type": "string"}},
        "exposedCredentials": {"type": "array", "items": {"type": "string"}},
        "dependencyContext": {"type": "object", "additionalProperties": True},
        "evidence": {"type": "object", "additionalProperties": True},
        "provenance": {"type": "object", "additionalProperties": True},
        "reachability": {"type": "string", "enum": ["confirmed", "likely", "unlikely", "unknown"]},
        "reachabilityBasis": {"type": "array", "items": {"type": "string"}},
    },
}

_ATTACK_PATH_ITEM_OPENAPI_SCHEMA["properties"]["exposure_path"] = _EXPOSURE_PATH_OPENAPI_SCHEMA

_FIX_FIRST_VIEW_OPENAPI_RESPONSE: dict[str, Any] = {
    "description": "Fix-first graph view with ranked cards and embedded ExposurePath payloads.",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "created_at": {"type": "string"},
                    "attack_campaigns": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "priority_score": {"type": ["number", "null"]},
                                "priority_method": {
                                    "type": ["string", "null"],
                                    "description": "Versioned structural ranking method; not an exploitability assessment.",
                                },
                                "exploitability": {"type": ["number", "null"]},
                                "expected_risk_reduction": {"type": ["number", "null"]},
                                "exploitability_evidence": {"type": "object", "additionalProperties": True},
                                "expected_risk_reduction_evidence": {"type": "object", "additionalProperties": True},
                            },
                            "additionalProperties": True,
                        },
                    },
                    "cards": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "semantic_key": {"type": "string"},
                                "occurrence_count": {"type": "integer", "minimum": 1},
                                "occurrence_path_ids": {"type": "array", "items": {"type": "string"}},
                                "rank": {"type": "integer", "minimum": 1},
                                "title": {"type": "string"},
                                "attack_path": _ATTACK_PATH_ITEM_OPENAPI_SCHEMA,
                                "exposure_path": _EXPOSURE_PATH_OPENAPI_SCHEMA,
                                "rank_meta": {
                                    "type": "object",
                                    "properties": {
                                        "reachability": {
                                            "type": "string",
                                            "enum": ["confirmed", "likely", "unknown", "unlikely"],
                                        },
                                        "raw_severity": {"type": "string"},
                                    },
                                    "additionalProperties": True,
                                },
                                "affected": {
                                    "type": "object",
                                    "properties": {
                                        "findings": {"type": "array", "items": {"type": "string"}},
                                        "finding_labels": {"type": "array", "items": {"type": "string"}},
                                    },
                                    "additionalProperties": True,
                                },
                            },
                            "additionalProperties": True,
                        },
                    },
                    "summary": {"type": "object", "additionalProperties": True},
                    "focus": {"type": "object", "additionalProperties": True},
                },
            }
        }
    },
}

_ATTACK_PATHS_OPENAPI_RESPONSE: dict[str, Any] = {
    "description": "Ranked attack-path queue with embedded ExposurePath payloads.",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "created_at": {"type": "string"},
                    "nodes": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "edges": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "attack_paths": {
                        "type": "array",
                        "items": _ATTACK_PATH_ITEM_OPENAPI_SCHEMA,
                    },
                    "stats": {
                        "type": "object",
                        "properties": {
                            "analysis_status": {
                                "type": "object",
                                "additionalProperties": {
                                    "type": "object",
                                    "required": ["status", "reason_codes", "limits", "observed"],
                                    "properties": {
                                        "status": {
                                            "type": "string",
                                            "enum": ["complete", "limited", "skipped", "failed", "not_recorded"],
                                        },
                                        "reason_codes": {"type": "array", "items": {"type": "string"}},
                                        "limits": {
                                            "type": "object",
                                            "additionalProperties": {"type": "integer", "minimum": 0},
                                        },
                                        "observed": {
                                            "type": "object",
                                            "additionalProperties": {"type": "integer", "minimum": 0},
                                        },
                                    },
                                },
                            }
                        },
                        "additionalProperties": True,
                    },
                    "pagination": {"type": "object", "additionalProperties": True},
                    "count_metadata": {"type": "object", "additionalProperties": True},
                },
            }
        }
    },
}


class PresetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = ""
    filters: dict


class GraphDeployDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    candidate: str | dict[str, Any] = Field(..., description="Package, image, service, or structured candidate descriptor")
    tenant_id: str | None = Field(default=None, description="Accepted for SDK compatibility; request tenant scope is authoritative")
    scan_id: str | None = Field(default=None, description="Scan snapshot ID; latest if omitted")
    limit: int = Field(5, ge=1, le=25, description="Maximum matched exposure paths")
    warn_risk: float = Field(40.0, ge=0, le=100, alias="warnRisk", description="Risk threshold for warning")
    block_risk: float = Field(80.0, ge=0, le=100, alias="blockRisk", description="Risk threshold for blocking")
    context: dict[str, Any] = Field(default_factory=dict, description="Optional caller context for future policy extensions")
