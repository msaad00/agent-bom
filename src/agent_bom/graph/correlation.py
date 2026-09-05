"""Deterministic correlation of immutable graph snapshots.

Correlation is deliberately conservative: it merges observations only when
their typed canonical identity is exact, and it never creates relationships
that were absent from every input snapshot. Mutable container tags are scoped
to their source snapshot unless an OCI digest is present.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from packageurl import PackageURL

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.severity import SEVERITY_RANK
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import _now_iso

_EMPTY_VALUES: tuple[Any, ...] = (None, "", [], {})
_OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-fA-F]{64}")
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_FAILURE_CODE_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}")
_CORRELATION_ATTR = "correlation"
_REPOSITORY_ENTITY_TYPES = frozenset(
    {
        EntityType.SOURCE_FILE.value,
        EntityType.CODE_MODULE.value,
        EntityType.CONFIG_FILE.value,
        EntityType.EXTERNAL_IMPORT.value,
        EntityType.CI_JOB.value,
        EntityType.DIRECTORY.value,
    }
)
_CLOUD_RESOURCE_ENTITY_TYPES = frozenset(
    {
        EntityType.ACCOUNT.value,
        EntityType.API_GATEWAY.value,
        EntityType.CLOUD_RESOURCE.value,
        EntityType.CLUSTER.value,
        EntityType.DATASET.value,
        EntityType.DATA_STORE.value,
        EntityType.ORG.value,
        EntityType.PROVIDER.value,
        EntityType.RESOURCE.value,
    }
)
_PROVIDER_IDENTITY_ENTITY_TYPES = frozenset(
    {
        EntityType.FEDERATED_IDENTITY.value,
        EntityType.GROUP.value,
        EntityType.MANAGED_IDENTITY.value,
        EntityType.ROLE.value,
        EntityType.SERVICE_ACCOUNT.value,
        EntityType.SERVICE_PRINCIPAL.value,
        EntityType.USER.value,
    }
)
_RUNTIME_ENTITY_TYPES = frozenset(
    {
        EntityType.AGENT.value,
        EntityType.SERVER.value,
        EntityType.TOOL.value,
        EntityType.TOOL_CALL.value,
    }
)


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _timestamp_instant(value: str) -> datetime:
    """Parse one evidence timestamp into a comparable UTC instant."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("correlation timestamps must be valid ISO-8601 values") from exc
    if parsed.tzinfo is None:
        raise ValueError("correlation timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _timestamp_sort_key(value: str) -> tuple[datetime, str]:
    return _timestamp_instant(value), value


def _oldest_timestamp(values: Sequence[str]) -> str:
    return min(values, key=_timestamp_sort_key)


def _newest_timestamp(values: Sequence[str]) -> str:
    return max(values, key=_timestamp_sort_key)


def correlation_manifest_digest(value: Mapping[str, Any]) -> str:
    """Return the canonical digest used for durable correlation receipts."""

    return _digest(value)


def _correlation_output_count(output: Mapping[str, Any], field: str) -> int:
    value = output.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"completed correlation manifest {field} must be a non-negative integer")
    return value


def correlation_graph_digest(graph: UnifiedGraph) -> str:
    """Hash persisted graph content consumed by correlation runtime facts.

    Load-time pagination metadata and derived UI statistics are intentionally
    excluded. Edge defaults are normalized exactly as persistence does, making
    the digest stable before save and after a complete backend round trip.
    """

    digest = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), default=str)

    def write(value: Any) -> None:
        # One node/edge is bounded; encode it in one chunk to avoid the method
        # call overhead of feeding every punctuation token separately.
        digest.update(encoder.encode(value).encode("utf-8"))

    # This is the exact canonical JSON emitted by _digest above.  Stream each
    # item so hashing does not duplicate the full graph as dictionaries plus one
    # giant encoded bytes object at peak RSS.
    digest.update(b'{"edges":[')
    for index, edge in enumerate(sorted(graph.edges, key=lambda item: str(item.canonical_id))):
        if index:
            digest.update(b",")
        payload = edge.to_dict()
        payload["valid_from"] = edge.valid_from or edge.first_seen or graph.created_at
        payload["source_scan_id"] = edge.source_scan_id or graph.scan_id
        write(payload)
    digest.update(b'],"nodes":[')
    for index, node in enumerate(sorted(graph.nodes.values(), key=lambda item: str(item.id))):
        if index:
            digest.update(b",")
        write(node.to_dict())
    digest.update(b'],"scan_id":')
    write(graph.scan_id)
    digest.update(b',"tenant_id":')
    write(graph.tenant_id)
    digest.update(b"}")
    return "sha256:" + digest.hexdigest()


def validate_correlation_output_manifest(
    graph: UnifiedGraph,
    *,
    result_manifest: Mapping[str, Any],
    manifest_sha256: str,
) -> None:
    """Require a completion receipt to bind the exact persisted graph output."""

    if correlation_manifest_digest(result_manifest) != manifest_sha256:
        raise ValueError("completed correlation manifest hash does not match result_manifest")
    output = result_manifest.get("output")
    if not isinstance(output, Mapping):
        raise ValueError("completed correlation manifest requires output metadata")
    if str(output.get("scan_id") or "") != graph.scan_id:
        raise ValueError("completed correlation manifest output must equal graph scan_id")
    node_count = _correlation_output_count(output, "node_count")
    edge_count = _correlation_output_count(output, "edge_count")
    if node_count == 0 or not graph.nodes:
        raise ValueError("completed correlation manifest requires a nonempty graph output")
    if node_count != len(graph.nodes) or edge_count != len(graph.edges):
        raise ValueError("completed correlation manifest counts do not match graph output")
    expected_digest = str(output.get("graph_digest_sha256") or "")
    if not expected_digest.startswith("sha256:") or len(expected_digest) != 71:
        raise ValueError("completed correlation manifest requires a graph digest")
    if expected_digest != correlation_graph_digest(graph):
        raise ValueError("completed correlation manifest graph digest does not match output")


def _non_empty(value: Any) -> bool:
    return value not in _EMPTY_VALUES


def _entity_value(node: UnifiedNode) -> str:
    return node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)


def _relationship_value(edge: UnifiedEdge) -> str:
    return edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)


def _oci_digest(node: UnifiedNode) -> str:
    for key in ("image_digest", "digest", "repo_digest", "container_image", "image", "image_ref"):
        value = node.attributes.get(key)
        if not isinstance(value, str):
            continue
        match = _OCI_DIGEST_RE.search(value)
        if match:
            return match.group(0).lower()
    return ""


def _snapshot_scoped_identity(node: UnifiedNode, *, scan_id: str) -> tuple[str, str, str]:
    entity_type = _entity_value(node)
    return entity_type, f"snapshot:{scan_id}:{node.canonical_id}", "snapshot_scoped_missing_exact_identity"


def _exact_attribute_identity(
    node: UnifiedNode,
    *,
    keys: Sequence[str],
    basis: str,
) -> tuple[str, str, str] | None:
    value = next((str(node.attributes.get(key) or "").strip() for key in keys if str(node.attributes.get(key) or "").strip()), "")
    if not value:
        return None
    scope = {
        key: str(node.attributes.get(key) or "").strip()
        for key in ("cloud_provider", "cloud_account_id", "tenant_id", "subscription_id", "project_id")
        if str(node.attributes.get(key) or "").strip()
    }
    return _entity_value(node), _digest({"scope": scope, "value": value}), basis


def correlation_identity(node: UnifiedNode, *, scan_id: str) -> tuple[str, str, str]:
    """Return ``(entity_type, identity, basis)`` for a source observation.

    A container is a runtime occurrence. Image digests identify reusable artifacts
    and never authorize joins between permission-bearing deployments. Unknown
    occurrence identity remains snapshot-scoped.
    """

    entity_type = _entity_value(node)
    if entity_type == EntityType.CONTAINER.value:
        attrs = node.attributes
        scope = {
            key: str(attrs.get(key) or "").strip()
            for key in (
                "cloud_provider",
                "cloud_account_id",
                "account_id",
                "tenant_id",
                "subscription_id",
                "project_id",
                "cluster_id",
                "cluster_arn",
                "runtime_host_id",
                "environment",
            )
            if str(attrs.get(key) or "").strip()
        }
        for key in ("cloud_provider", "environment"):
            dimension = str(getattr(node.dimensions, key, "") or "").strip()
            if dimension:
                scope[f"dimension_{key}"] = dimension
                scope.setdefault(key, dimension)
        located = bool(scope.get("cluster_id") or scope.get("cluster_arn") or scope.get("runtime_host_id")) or bool(
            scope.get("cloud_provider")
            and any(scope.get(key) for key in ("cloud_account_id", "account_id", "subscription_id", "project_id"))
        )
        uid_key = "runtime_uid" if attrs.get("runtime_uid") else "container_id"
        uid = str(attrs.get(uid_key) or "").strip()
        if (
            not uid
            and attrs.get("kubernetes_uid")
            and attrs.get("container_name")
            and (scope.get("cluster_id") or scope.get("cluster_arn"))
        ):
            uid_key = "kubernetes_container"
            uid = f"{attrs['kubernetes_uid']}:{attrs['container_name']}"
        if uid and located:
            return entity_type, _digest({"scope": scope, "uid_kind": uid_key, "runtime_uid": uid}), "runtime_occurrence"
        scoped_type, scoped_id, _basis = _snapshot_scoped_identity(node, scan_id=scan_id)
        return scoped_type, scoped_id, "snapshot_scoped_runtime_occurrence"

    if entity_type == EntityType.PACKAGE.value:
        purl = node.attributes.get("purl")
        if isinstance(purl, str) and purl.strip():
            try:
                canonical_purl = PackageURL.from_string(purl.strip()).to_string()
            except ValueError:
                return _snapshot_scoped_identity(node, scan_id=scan_id)
            return entity_type, canonical_purl, "purl"
        return _snapshot_scoped_identity(node, scan_id=scan_id)

    if entity_type in _REPOSITORY_ENTITY_TYPES:
        commit = next(
            (
                str(node.attributes[key]).strip().lower()
                for key in ("repository_commit", "commit_sha", "git_commit")
                if node.attributes.get(key)
            ),
            "",
        )
        path = next(
            (
                str(node.attributes[key]).strip().replace("\\", "/")
                for key in ("repository_path", "path", "source_file", "config_path")
                if node.attributes.get(key)
            ),
            "",
        )
        if commit and path:
            return entity_type, _digest({"commit": commit, "path": path}), "repository_commit_path"
        return _snapshot_scoped_identity(node, scan_id=scan_id)

    if entity_type in _CLOUD_RESOURCE_ENTITY_TYPES:
        exact = _exact_attribute_identity(
            node,
            keys=(
                "arn",
                "resource_arn",
                "kubernetes_uid",
                "uid",
                "resource_id",
                "provider_id",
                "object_fqn",
                "self_link",
                "canonical_id",
                "stable_id",
            ),
            basis="cloud_resource_id",
        )
        return exact or _snapshot_scoped_identity(node, scan_id=scan_id)

    if entity_type in _PROVIDER_IDENTITY_ENTITY_TYPES:
        exact = _exact_attribute_identity(
            node,
            keys=(
                "provider_identity_id",
                "principal_id",
                "directory_principal_id",
                "object_id",
                "subject_id",
                "arn",
                "client_id",
                "canonical_id",
                "stable_id",
            ),
            basis="provider_identity_id",
        )
        return exact or _snapshot_scoped_identity(node, scan_id=scan_id)

    if entity_type in _RUNTIME_ENTITY_TYPES:
        exact = _exact_attribute_identity(
            node,
            keys=("runtime_id", "stable_id", "canonical_id"),
            basis="runtime_stable_id",
        )
        return exact or _snapshot_scoped_identity(node, scan_id=scan_id)

    exact = _exact_attribute_identity(
        node,
        keys=("canonical_id", "stable_id"),
        basis="canonical_id",
    )
    return exact or _snapshot_scoped_identity(node, scan_id=scan_id)


@dataclass(frozen=True, slots=True)
class CorrelationSnapshot:
    """One immutable graph snapshot selected for a correlation run."""

    scan_id: str
    tenant_id: str
    created_at: str
    graph: UnifiedGraph
    digest: str

    @classmethod
    def from_graph(cls, graph: UnifiedGraph) -> "CorrelationSnapshot":
        return cls(
            scan_id=graph.scan_id,
            tenant_id=graph.tenant_id,
            created_at=graph.created_at,
            graph=graph,
            digest=_digest(graph.to_dict()),
        )


@dataclass(frozen=True, slots=True)
class CorrelationMergeResult:
    graph: UnifiedGraph
    manifest: dict[str, Any]
    manifest_sha256: str


class CorrelationRunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


_CORRELATION_TRANSITIONS = {
    CorrelationRunStatus.PENDING: {CorrelationRunStatus.RUNNING, CorrelationRunStatus.FAILED},
    CorrelationRunStatus.RUNNING: {CorrelationRunStatus.COMPLETE, CorrelationRunStatus.FAILED},
    CorrelationRunStatus.COMPLETE: set(),
    CorrelationRunStatus.FAILED: set(),
}


@dataclass(frozen=True, slots=True)
class GraphCorrelationRun:
    """Immutable request plus monotonic execution state for one correlation."""

    correlation_id: str
    tenant_id: str
    idempotency_key: str
    name: str
    status: CorrelationRunStatus
    max_age_hours: int
    allow_stale: bool
    input_manifest: list[dict[str, Any]]
    result_manifest: dict[str, Any] = field(default_factory=dict)
    manifest_sha256: str = ""
    output_scan_id: str = ""
    failure_code: str = ""
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    execution_owner: str = ""
    execution_lease_expires_at: str = ""

    def __post_init__(self) -> None:
        if not self.correlation_id.strip():
            raise ValueError("correlation_id is required")
        if not self.tenant_id.strip():
            raise ValueError("tenant_id is required")
        if not self.idempotency_key.strip():
            raise ValueError("idempotency_key is required")
        if not 1 <= int(self.max_age_hours) <= 8760:
            raise ValueError("max_age_hours must be between 1 and 8760")
        if not 2 <= len(self.input_manifest) <= 32:
            raise ValueError("input_manifest must contain between 2 and 32 snapshots")
        scan_ids = [str(item.get("scan_id") or "").strip() for item in self.input_manifest]
        if any(not scan_id for scan_id in scan_ids) or len(set(scan_ids)) != len(scan_ids):
            raise ValueError("input_manifest snapshot IDs must be non-empty and unique")
        if self.failure_code and _FAILURE_CODE_RE.fullmatch(self.failure_code) is None:
            raise ValueError("failure_code must be a sanitized machine-readable code")

    def request_fingerprint(self) -> str:
        """Hash immutable request fields for tenant-scoped idempotent replay."""

        return _digest(
            {
                "tenant_id": self.tenant_id,
                "name": self.name,
                "max_age_hours": self.max_age_hours,
                "allow_stale": self.allow_stale,
                # Freshness and age are observations captured at admission and
                # therefore change across retries. Idempotency binds only to
                # immutable source receipts plus the caller's policy.
                "source_receipts": sorted(
                    (
                        {
                            "scan_id": str(item.get("scan_id") or ""),
                            "created_at": str(item.get("created_at") or ""),
                            "digest": str(item.get("digest") or ""),
                        }
                        for item in self.input_manifest
                    ),
                    key=lambda item: (item["scan_id"], item["created_at"], item["digest"]),
                ),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "idempotency_key": self.idempotency_key,
            "name": self.name,
            "status": self.status.value,
            "max_age_hours": self.max_age_hours,
            "allow_stale": self.allow_stale,
            "input_manifest": deepcopy(self.input_manifest),
            "result_manifest": deepcopy(self.result_manifest),
            "manifest_sha256": self.manifest_sha256,
            "output_scan_id": self.output_scan_id,
            "failure_code": self.failure_code,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "GraphCorrelationRun":
        status = value.get("status", CorrelationRunStatus.PENDING)
        return cls(
            correlation_id=str(value.get("correlation_id") or ""),
            tenant_id=str(value.get("tenant_id") or ""),
            idempotency_key=str(value.get("idempotency_key") or ""),
            name=str(value.get("name") or ""),
            status=status if isinstance(status, CorrelationRunStatus) else CorrelationRunStatus(str(status)),
            max_age_hours=int(value.get("max_age_hours") or 0),
            allow_stale=bool(value.get("allow_stale", False)),
            input_manifest=[dict(item) for item in value.get("input_manifest") or [] if isinstance(item, Mapping)],
            result_manifest=dict(value.get("result_manifest") or {}),
            manifest_sha256=str(value.get("manifest_sha256") or ""),
            output_scan_id=str(value.get("output_scan_id") or ""),
            failure_code=str(value.get("failure_code") or ""),
            created_at=str(value.get("created_at") or ""),
            started_at=str(value.get("started_at") or ""),
            completed_at=str(value.get("completed_at") or ""),
            execution_owner=str(value.get("execution_owner") or ""),
            execution_lease_expires_at=str(value.get("execution_lease_expires_at") or ""),
        )


def validate_correlation_update(
    existing: GraphCorrelationRun,
    *,
    status: CorrelationRunStatus,
    manifest_sha256: str = "",
    result_manifest: Mapping[str, Any] | None = None,
    output_scan_id: str = "",
    failure_code: str = "",
) -> tuple[str, dict[str, Any], str, str]:
    """Validate one monotonic state transition and return resolved values."""

    if status not in _CORRELATION_TRANSITIONS[existing.status]:
        raise ValueError("correlation run is terminal or the status transition is invalid")
    resolved_manifest = manifest_sha256 or existing.manifest_sha256
    resolved_result_manifest = dict(result_manifest or existing.result_manifest)
    resolved_output = output_scan_id or existing.output_scan_id
    if failure_code and _FAILURE_CODE_RE.fullmatch(failure_code) is None:
        raise ValueError("failure_code must be a sanitized machine-readable code")
    if status is CorrelationRunStatus.COMPLETE:
        if resolved_output != existing.correlation_id:
            raise ValueError("completed correlation output snapshot must equal correlation_id")
        if _SHA256_RE.fullmatch(resolved_manifest) is None:
            raise ValueError("completed correlation requires a sha256 evidence manifest")
        if not resolved_result_manifest or _digest(resolved_result_manifest) != resolved_manifest:
            raise ValueError("completed correlation manifest hash does not match result_manifest")
        if failure_code:
            raise ValueError("completed correlation cannot contain a failure code")
    if status is CorrelationRunStatus.FAILED:
        if not failure_code:
            raise ValueError("failed correlation requires a sanitized failure code")
        if resolved_output:
            raise ValueError("failed correlation cannot expose an output snapshot")
    return resolved_manifest, resolved_result_manifest, resolved_output, failure_code


@dataclass(frozen=True, slots=True)
class _NodeObservation:
    snapshot: CorrelationSnapshot
    node: UnifiedNode
    identity_basis: str


@dataclass(frozen=True, slots=True)
class _EdgeObservation:
    snapshot: CorrelationSnapshot
    edge: UnifiedEdge


def _project_mapping(observations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Project newest non-empty top-level values from oldest→newest inputs."""

    projected: dict[str, Any] = {}
    for values in observations:
        for key, value in values.items():
            if key == _CORRELATION_ATTR or not _non_empty(value):
                continue
            projected[str(key)] = deepcopy(value)
    return projected


def _conflict_fields(observations: Iterable[Mapping[str, Any]]) -> list[str]:
    values_by_key: dict[str, set[str]] = {}
    for values in observations:
        for key, value in values.items():
            if key in {_CORRELATION_ATTR, "canonical_id", "stable_id", "source_ids"} or not _non_empty(value):
                continue
            values_by_key.setdefault(str(key), set()).add(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))
    return sorted(key for key, values in values_by_key.items() if len(values) > 1)


def _node_observation_receipt(observation: _NodeObservation) -> dict[str, Any]:
    node = observation.node
    return {
        "scan_id": observation.snapshot.scan_id,
        "snapshot_created_at": observation.snapshot.created_at,
        "source_node_id": node.id,
        "data_sources": sorted(set(node.data_sources)),
        "risk_score": float(node.risk_score),
        "severity": node.severity,
        "attribute_digest": _digest(node.attributes),
    }


def _merge_node(observations: Sequence[_NodeObservation]) -> UnifiedNode:
    ordered = sorted(
        observations,
        key=lambda item: (_timestamp_instant(item.snapshot.created_at), item.snapshot.scan_id, item.node.id),
    )
    newest = ordered[-1].node
    attributes = _project_mapping(item.node.attributes for item in ordered)
    source_scan_ids = sorted({item.snapshot.scan_id for item in ordered})
    identity_basis = sorted({item.identity_basis for item in ordered})
    attributes[_CORRELATION_ATTR] = {
        "identity_version": "runtime-occurrence.v2",
        "identity_basis": identity_basis[0] if len(identity_basis) == 1 else identity_basis,
        "observation_count": len(ordered),
        "source_scan_ids": source_scan_ids,
        "conflict_fields": _conflict_fields(item.node.attributes for item in ordered),
        "observations": [_node_observation_receipt(item) for item in ordered],
    }

    severity_source = max(
        ordered,
        key=lambda item: (
            SEVERITY_RANK.get((item.node.severity or "").lower(), 0),
            item.node.risk_score,
            _timestamp_instant(item.snapshot.created_at),
        ),
    ).node
    dimensions = NodeDimensions()
    for item in ordered:
        dimensions = dimensions.merge(item.node.dimensions)

    first_seen_values = [item.node.first_seen for item in ordered if item.node.first_seen]
    last_seen_values = [item.node.last_seen for item in ordered if item.node.last_seen]
    return UnifiedNode(
        id=newest.id,
        entity_type=newest.entity_type,
        label=newest.label,
        category_uid=newest.category_uid,
        class_uid=newest.class_uid,
        type_uid=newest.type_uid,
        status=newest.status,
        risk_score=max(float(item.node.risk_score) for item in ordered),
        severity=severity_source.severity,
        severity_id=severity_source.severity_id,
        first_seen=_oldest_timestamp(first_seen_values) if first_seen_values else "",
        last_seen=_newest_timestamp(last_seen_values) if last_seen_values else "",
        attributes=attributes,
        compliance_tags=sorted({tag for item in ordered for tag in item.node.compliance_tags}),
        data_sources=sorted({source for item in ordered for source in item.node.data_sources}),
        dimensions=dimensions,
    )


def _edge_receipt(observation: _EdgeObservation) -> dict[str, Any]:
    edge = observation.edge
    return {
        "scan_id": observation.snapshot.scan_id,
        "snapshot_created_at": observation.snapshot.created_at,
        "source_edge_id": edge.id,
        "confidence": float(edge.confidence),
        "traversable": bool(edge.traversable),
        "direction": edge.direction,
        "evidence_digest": _digest(edge.evidence),
    }


def _merge_edge(
    observations: Sequence[_EdgeObservation],
    *,
    source_id: str,
    target_id: str,
    correlation_id: str,
) -> UnifiedEdge:
    ordered = sorted(
        observations,
        key=lambda item: (_timestamp_instant(item.snapshot.created_at), item.snapshot.scan_id, item.edge.id),
    )
    newest = ordered[-1].edge
    first_seen_values = [item.edge.first_seen for item in ordered if item.edge.first_seen]
    last_seen_values = [item.edge.last_seen for item in ordered if item.edge.last_seen]
    source_scan_ids = sorted({item.snapshot.scan_id for item in ordered})
    provenance = _project_mapping(item.edge.provenance for item in ordered)
    conflict_fields: list[str] = []
    if len({item.edge.direction for item in ordered}) > 1:
        conflict_fields.append("direction")
    if len({bool(item.edge.traversable) for item in ordered}) > 1:
        conflict_fields.append("traversable")
    provenance[_CORRELATION_ATTR] = {
        "identity_version": (
            "runtime-occurrence.v2"
            if all(
                not item.edge.provenance.get(_CORRELATION_ATTR)
                or isinstance(item.edge.provenance.get(_CORRELATION_ATTR), dict)
                and item.edge.provenance[_CORRELATION_ATTR].get("identity_version") == "runtime-occurrence.v2"
                for item in ordered
            )
            else "legacy"
        ),
        "observation_count": len(ordered),
        "source_scan_ids": source_scan_ids,
        "conflict_fields": conflict_fields,
        "observations": [_edge_receipt(item) for item in ordered],
    }
    return UnifiedEdge(
        source=source_id,
        target=target_id,
        relationship=newest.relationship,
        # Conservative merge: conflicting directionality cannot expand an
        # attacker's traversal. Every observation must support bidirectionality.
        direction="bidirectional" if all(item.edge.direction == "bidirectional" for item in ordered) else "directed",
        weight=max(float(item.edge.weight) for item in ordered),
        traversable=all(bool(item.edge.traversable) for item in ordered),
        first_seen=_oldest_timestamp(first_seen_values) if first_seen_values else "",
        last_seen=_newest_timestamp(last_seen_values) if last_seen_values else "",
        valid_from=_oldest_timestamp([item.edge.valid_from for item in ordered if item.edge.valid_from])
        if any(item.edge.valid_from for item in ordered)
        else "",
        valid_to=newest.valid_to,
        source_scan_id=correlation_id,
        source_run_id=correlation_id,
        evidence=_project_mapping(item.edge.evidence for item in ordered),
        confidence=max(float(item.edge.confidence) for item in ordered),
        provenance=provenance,
        activity_id=newest.activity_id,
    )


def merge_graph_snapshots(
    *,
    correlation_id: str,
    tenant_id: str,
    snapshots: Sequence[CorrelationSnapshot],
    created_at: str = "",
) -> CorrelationMergeResult:
    """Merge selected immutable snapshots without inventing cross-source edges."""

    if len(snapshots) < 2:
        raise ValueError("Correlation requires at least 2 graph snapshots")
    if len(snapshots) > 32:
        raise ValueError("Correlation accepts at most 32 graph snapshots")
    if len({snapshot.scan_id for snapshot in snapshots}) != len(snapshots):
        raise ValueError("Correlation snapshot IDs must be unique")
    if any(snapshot.tenant_id != tenant_id or snapshot.graph.tenant_id != tenant_id for snapshot in snapshots):
        raise ValueError("Correlation inputs must belong to the same tenant")
    if any(not snapshot.graph.nodes for snapshot in snapshots):
        raise ValueError("Correlation inputs must be non-empty graph snapshots")

    ordered_snapshots = sorted(snapshots, key=lambda item: (_timestamp_instant(item.created_at), item.scan_id))
    node_groups: dict[tuple[str, str], list[_NodeObservation]] = {}
    source_to_key: dict[tuple[str, str], tuple[str, str]] = {}
    for snapshot in ordered_snapshots:
        for node in sorted(snapshot.graph.nodes.values(), key=lambda item: item.id):
            entity_type, identity, basis = correlation_identity(node, scan_id=snapshot.scan_id)
            key = (entity_type, identity)
            source_to_key[(snapshot.scan_id, node.id)] = key
            node_groups.setdefault(key, []).append(_NodeObservation(snapshot=snapshot, node=node, identity_basis=basis))

    output = UnifiedGraph(scan_id=correlation_id, tenant_id=tenant_id, created_at=created_at or _now_iso())
    output_id_by_key: dict[tuple[str, str], str] = {}
    merged_nodes = [(key, _merge_node(node_groups[key])) for key in sorted(node_groups)]
    candidate_id_counts: dict[str, int] = {}
    for _key, node in merged_nodes:
        candidate_id_counts[node.id] = candidate_id_counts.get(node.id, 0) + 1
    for key, node in merged_nodes:
        if candidate_id_counts[node.id] > 1:
            # Snapshot-scoped identities can legitimately retain the same local
            # graph ID. Give every colliding observation group a deterministic
            # correlated ID so UnifiedGraph.add_node cannot conflate them.
            node.id = f"correlated:{key[0]}:{_digest(key).removeprefix('sha256:')}"
        output.add_node(node)
        output_id_by_key[key] = node.id

    edge_groups: dict[tuple[tuple[str, str], tuple[str, str], str], list[_EdgeObservation]] = {}
    for snapshot in ordered_snapshots:
        for edge in sorted(snapshot.graph.edges, key=lambda item: (item.source, item.target, _relationship_value(item))):
            source_key = source_to_key.get((snapshot.scan_id, edge.source))
            target_key = source_to_key.get((snapshot.scan_id, edge.target))
            if source_key is None or target_key is None:
                continue
            edge_key = (source_key, target_key, _relationship_value(edge))
            edge_groups.setdefault(edge_key, []).append(_EdgeObservation(snapshot=snapshot, edge=edge))

    for (source_key, target_key, _relationship), observations in sorted(edge_groups.items(), key=lambda item: str(item[0])):
        output.add_edge(
            _merge_edge(
                observations,
                source_id=output_id_by_key[source_key],
                target_id=output_id_by_key[target_key],
                correlation_id=correlation_id,
            )
        )

    manifest = {
        "schema_version": "agent-bom.graph-correlation.v1",
        "identity_version": "runtime-occurrence.v2",
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "created_at": output.created_at,
        "input_snapshots": [
            {
                "scan_id": snapshot.scan_id,
                "created_at": snapshot.created_at,
                "digest": snapshot.digest,
                "node_count": len(snapshot.graph.nodes),
                "edge_count": len(snapshot.graph.edges),
                "data_sources": sorted({source for node in snapshot.graph.nodes.values() for source in node.data_sources}),
            }
            for snapshot in ordered_snapshots
        ],
        "output": {
            "scan_id": correlation_id,
            "node_count": len(output.nodes),
            "edge_count": len(output.edges),
            "node_conflict_count": sum(
                bool(node.attributes.get(_CORRELATION_ATTR, {}).get("conflict_fields")) for node in output.nodes.values()
            ),
            "edge_conflict_count": sum(bool(edge.provenance.get(_CORRELATION_ATTR, {}).get("conflict_fields")) for edge in output.edges),
        },
    }
    return CorrelationMergeResult(graph=output, manifest=manifest, manifest_sha256=_digest(manifest))


__all__ = [
    "CorrelationMergeResult",
    "CorrelationRunStatus",
    "CorrelationSnapshot",
    "GraphCorrelationRun",
    "correlation_graph_digest",
    "correlation_identity",
    "correlation_manifest_digest",
    "merge_graph_snapshots",
    "validate_correlation_output_manifest",
    "validate_correlation_update",
]
