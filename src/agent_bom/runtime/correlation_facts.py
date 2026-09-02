"""Signed, expiring correlation facts consumed by the runtime gateway."""

from __future__ import annotations

import hmac
import json
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping

from agent_bom.runtime.graph_reachability import AgentReachability, ReachabilityMap

_SCHEMA = "agent-bom.runtime-facts/v2"
_ALGORITHM = "HMAC-SHA256"
_MAX_TTL_SECONDS = 86400
_MAX_CLOCK_SKEW_SECONDS = 300
_DEPTH_LIMIT = 6
_VISITED_NODE_LIMIT = 5000
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_KEY_ID_BYTES = 512
RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS = frozenset(
    {
        "correlation_manifest_invalid",
        "correlation_manifest_mismatch",
        "correlation_output_changed",
        "correlation_output_empty",
        "correlation_output_mismatch",
        "correlation_output_replaced",
        "correlation_output_unavailable",
        "correlation_inputs_stale",
        "invalid_analysis_bounds",
        "invalid_input_freshness",
        "invalid_signature",
        "runtime_facts_empty",
        "tenant_mismatch",
        "unsupported_schema",
    }
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _validated_key_id(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or len(value.encode("utf-8")) > _MAX_KEY_ID_BYTES:
        raise RuntimeFactsBundleError("invalid_key_id")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RuntimeFactsBundleError("invalid_key_id")
    return value


def _signature_input(payload: Mapping[str, Any], *, key_id: str) -> bytes:
    return _canonical({"algorithm": _ALGORITHM, "key_id": key_id, "payload": payload})


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise RuntimeFactsBundleError("invalid_timestamp")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeFactsBundleError("invalid_timestamp") from exc
    return _utc(parsed)


def _validate_key(signing_key: bytes) -> None:
    if len(signing_key) < 32:
        raise RuntimeFactsBundleError("invalid_signing_key")


class RuntimeFactsBundleError(ValueError):
    """Sanitized bundle validation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class VerifiedRuntimeFacts:
    correlation_id: str
    tenant_id: str
    manifest_sha256: str
    issued_at: datetime
    expires_at: datetime
    key_id: str
    evidence_freshness: str
    analysis_complete: bool
    analysis_bounds: dict[str, Any]
    reachability: ReachabilityMap


def _facts(reachability: ReachabilityMap) -> list[dict[str, Any]]:
    return [
        {
            "agent_id": item.agent_id,
            "node_ids": sorted(item.node_ids),
            "node_labels": sorted(item.node_labels),
            "rule_id": item.rule_id,
            "severity": item.severity,
            "detail": item.detail,
        }
        for _key, item in sorted(reachability.by_agent.items())
    ]


def _validated_analysis_bounds(value: Mapping[str, Any] | None) -> dict[str, Any]:
    raw = value or {
        "status": "complete",
        "complete": True,
        "depth_limit": _DEPTH_LIMIT,
        "visited_node_limit": _VISITED_NODE_LIMIT,
        "limit_reasons": [],
    }
    status = str(raw.get("status") or "")
    complete = raw.get("complete")
    reasons = raw.get("limit_reasons")
    try:
        depth_limit = int(str(raw.get("depth_limit") or ""))
        visited_node_limit = int(str(raw.get("visited_node_limit") or ""))
    except (TypeError, ValueError) as exc:
        raise RuntimeFactsBundleError("invalid_analysis_bounds") from exc
    if (
        status not in {"complete", "limited"}
        or not isinstance(complete, bool)
        or complete != (status == "complete")
        or not isinstance(reasons, list)
        or any(not isinstance(reason, str) or not reason for reason in reasons)
        or depth_limit < 1
        or visited_node_limit < 1
        or (complete and reasons)
        or (not complete and not reasons)
    ):
        raise RuntimeFactsBundleError("invalid_analysis_bounds")
    normalized: dict[str, Any] = {
        "status": status,
        "complete": complete,
        "depth_limit": depth_limit,
        "visited_node_limit": visited_node_limit,
        "limit_reasons": sorted(set(reasons)),
    }
    if "max_visited_nodes_per_agent" in raw:
        try:
            maximum = int(str(raw["max_visited_nodes_per_agent"]))
        except (TypeError, ValueError) as exc:
            raise RuntimeFactsBundleError("invalid_analysis_bounds") from exc
        if maximum < 0 or maximum > visited_node_limit:
            raise RuntimeFactsBundleError("invalid_analysis_bounds")
        normalized["max_visited_nodes_per_agent"] = maximum
    return normalized


def _validated_input_freshness(
    value: Mapping[str, Any],
    *,
    at: datetime,
) -> tuple[dict[str, Any], str, datetime]:
    """Validate signed source receipts and derive freshness at ``at``."""

    raw_max_age = value.get("max_age_hours")
    allow_stale = value.get("allow_stale")
    raw_snapshots = value.get("snapshots")
    if (
        not isinstance(raw_max_age, int)
        or isinstance(raw_max_age, bool)
        or not 1 <= raw_max_age <= 8760
        or not isinstance(allow_stale, bool)
        or not isinstance(raw_snapshots, list)
        or not 2 <= len(raw_snapshots) <= 32
    ):
        raise RuntimeFactsBundleError("invalid_input_freshness")

    moment = _utc(at)
    snapshots: list[dict[str, str]] = []
    scan_ids: set[str] = set()
    fresh_until: datetime | None = None
    for raw_snapshot in raw_snapshots:
        if not isinstance(raw_snapshot, Mapping):
            raise RuntimeFactsBundleError("invalid_input_freshness")
        scan_id = str(raw_snapshot.get("scan_id") or "").strip()
        try:
            created_at = _parse_timestamp(raw_snapshot.get("created_at"))
        except RuntimeFactsBundleError as exc:
            raise RuntimeFactsBundleError("invalid_input_freshness") from exc
        if not scan_id or scan_id in scan_ids or created_at - moment > timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS):
            raise RuntimeFactsBundleError("invalid_input_freshness")
        scan_ids.add(scan_id)
        snapshots.append({"scan_id": scan_id, "created_at": created_at.isoformat()})
        snapshot_fresh_until = created_at + timedelta(hours=raw_max_age)
        fresh_until = min(fresh_until, snapshot_fresh_until) if fresh_until is not None else snapshot_fresh_until

    assert fresh_until is not None  # length is validated above
    stale = moment > fresh_until
    if stale and not allow_stale:
        raise RuntimeFactsBundleError("correlation_inputs_stale")
    normalized: dict[str, Any] = {
        "max_age_hours": raw_max_age,
        "allow_stale": allow_stale,
        "snapshots": snapshots,
    }
    return normalized, "stale_allowed" if stale else "fresh", fresh_until


def _immutable_input_receipts(value: object) -> list[dict[str, Any]] | None:
    """Project source-bound fields while allowing execution-time freshness."""

    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        return None
    return [
        {str(key): item[key] for key in sorted(item) if key not in {"age_hours", "freshness"}}
        for item in value
        if isinstance(item, Mapping)
    ]


def create_runtime_facts_bundle(
    *,
    correlation_id: str,
    tenant_id: str,
    manifest_sha256: str,
    reachability: ReachabilityMap,
    signing_key: bytes,
    ttl_seconds: int,
    now: datetime | None = None,
    key_id: str = "",
    evidence_freshness: str = "fresh",
    analysis_bounds: Mapping[str, Any] | None = None,
    input_freshness: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create an HMAC-authenticated runtime-facts envelope."""

    _validate_key(signing_key)
    key_id = _validated_key_id(key_id)
    if not correlation_id or not tenant_id:
        raise RuntimeFactsBundleError("invalid_identity")
    if _SHA256_RE.fullmatch(manifest_sha256) is None:
        raise RuntimeFactsBundleError("invalid_manifest_hash")
    if not 1 <= ttl_seconds <= _MAX_TTL_SECONDS:
        raise RuntimeFactsBundleError("invalid_ttl")
    if evidence_freshness not in {"fresh", "stale_allowed"}:
        raise RuntimeFactsBundleError("invalid_evidence_freshness")
    bounds = _validated_analysis_bounds(analysis_bounds)
    issued = _utc(now or datetime.now(timezone.utc))
    normalized_input_freshness: dict[str, Any] | None = None
    fresh_until: datetime | None = None
    if input_freshness is not None:
        normalized_input_freshness, derived_freshness, fresh_until = _validated_input_freshness(
            input_freshness,
            at=issued,
        )
        if evidence_freshness != derived_freshness:
            raise RuntimeFactsBundleError("invalid_input_freshness")
    expires_at = issued + timedelta(seconds=ttl_seconds)
    if fresh_until is not None and evidence_freshness == "fresh":
        expires_at = min(expires_at, fresh_until)
        if expires_at <= issued:
            raise RuntimeFactsBundleError("correlation_inputs_stale")
    payload = {
        "schema_version": _SCHEMA,
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "manifest_sha256": manifest_sha256,
        "evidence_freshness": evidence_freshness,
        "analysis_bounds": bounds,
        "issued_at": issued.isoformat(),
        "expires_at": expires_at.isoformat(),
        "facts": _facts(reachability),
    }
    if normalized_input_freshness is not None:
        payload["input_freshness"] = normalized_input_freshness
    signature = hmac.digest(signing_key, _signature_input(payload, key_id=key_id), "sha256").hex()
    return {
        "payload": payload,
        "signature": {
            "algorithm": _ALGORITHM,
            "key_id": key_id,
            "value": signature,
        },
    }


def _reachability_from_correlation_graph(graph: Any) -> tuple[ReachabilityMap, dict[str, Any]]:
    from agent_bom.graph.types import EntityType

    target_types = {EntityType.TOOL, EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF}
    by_agent: dict[str, AgentReachability] = {}
    limit_reasons: set[str] = set()
    max_visited = 0

    def directed_evidence_edge(edge: Any) -> bool:
        correlation = edge.provenance.get("correlation") if isinstance(edge.provenance, dict) else None
        source_ids = correlation.get("source_scan_ids") if isinstance(correlation, dict) else None
        has_provenance = bool(source_ids or edge.source_scan_id or graph.scan_id)
        return bool(edge.traversable and edge.direction == "directed" and has_provenance)

    for agent in sorted(graph.nodes.values(), key=lambda node: node.id):
        if agent.entity_type is not EntityType.AGENT:
            continue
        runtime_id = next(
            (
                str(agent.attributes.get(key) or "").strip()
                for key in ("runtime_id", "stable_id", "canonical_id")
                if str(agent.attributes.get(key) or "").strip()
            ),
            "",
        )
        if not runtime_id:
            continue
        node_ids: set[str] = set()
        node_labels: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(agent.id, 0)])
        visited = {agent.id}
        while queue:
            source, depth = queue.popleft()
            if depth >= _DEPTH_LIMIT:
                if any(
                    directed_evidence_edge(edge) and edge.target not in visited and edge.target in graph.nodes
                    for edge in graph.adjacency.get(source, [])
                ):
                    limit_reasons.add("depth_cap_reached")
                continue
            for edge in graph.adjacency.get(source, []):
                if not directed_evidence_edge(edge) or edge.target in visited:
                    continue
                if len(visited) >= _VISITED_NODE_LIMIT:
                    limit_reasons.add("visited_node_cap_reached")
                    continue
                visited.add(edge.target)
                target = graph.nodes.get(edge.target)
                if target is None:
                    continue
                if target.entity_type in target_types:
                    node_ids.add(target.id)
                    node_labels.add(target.label or target.id)
                queue.append((target.id, depth + 1))
        max_visited = max(max_visited, len(visited))
        if node_ids or node_labels:
            by_agent[runtime_id.lower()] = AgentReachability(
                agent_id=runtime_id,
                node_ids=frozenset(node_ids),
                node_labels=frozenset(node_labels),
                detail="Derived from directed, traversable correlation graph relationships.",
            )
    complete = not limit_reasons
    return ReachabilityMap(by_agent=by_agent), {
        "status": "complete" if complete else "limited",
        "complete": complete,
        "depth_limit": _DEPTH_LIMIT,
        "visited_node_limit": _VISITED_NODE_LIMIT,
        "max_visited_nodes_per_agent": max_visited,
        "limit_reasons": sorted(limit_reasons),
    }


def create_runtime_facts_bundle_from_correlation(
    run: Any,
    graph: Any,
    *,
    snapshot_metadata: Mapping[str, Any] | None,
    signing_key: bytes,
    ttl_seconds: int,
    now: datetime | None = None,
    key_id: str = "",
) -> dict[str, Any]:
    """Produce runtime facts only from a completed, tenant-bound correlation."""

    from agent_bom.graph.correlation import CorrelationRunStatus

    if run.status is not CorrelationRunStatus.COMPLETE:
        raise RuntimeFactsBundleError("correlation_not_complete")
    if not isinstance(snapshot_metadata, Mapping):
        raise RuntimeFactsBundleError("correlation_output_unavailable")
    if run.output_scan_id != run.correlation_id or graph.scan_id != run.correlation_id:
        raise RuntimeFactsBundleError("correlation_output_mismatch")
    if graph.tenant_id != run.tenant_id:
        raise RuntimeFactsBundleError("tenant_mismatch")
    if (
        str(snapshot_metadata.get("scan_id") or "") != run.correlation_id
        or str(snapshot_metadata.get("snapshot_kind") or "") != "correlation"
        or str(snapshot_metadata.get("correlation_id") or "") != run.correlation_id
    ):
        raise RuntimeFactsBundleError("correlation_output_replaced")
    if str(snapshot_metadata.get("evidence_manifest_sha256") or "") != run.manifest_sha256:
        raise RuntimeFactsBundleError("correlation_manifest_mismatch")
    if not graph.nodes or int(snapshot_metadata.get("node_count") or 0) < 1:
        raise RuntimeFactsBundleError("correlation_output_empty")
    from agent_bom.graph.correlation import correlation_graph_digest, correlation_manifest_digest

    if not hmac.compare_digest(correlation_manifest_digest(run.result_manifest), run.manifest_sha256):
        raise RuntimeFactsBundleError("correlation_manifest_mismatch")
    output = run.result_manifest.get("output") if isinstance(run.result_manifest, Mapping) else None
    expected_digest = str(output.get("graph_digest_sha256") or "") if isinstance(output, Mapping) else ""
    if not expected_digest.startswith("sha256:") or len(expected_digest) != 71:
        raise RuntimeFactsBundleError("correlation_manifest_invalid")

    if not hmac.compare_digest(correlation_graph_digest(graph), expected_digest):
        raise RuntimeFactsBundleError("correlation_output_changed")
    reachability, analysis_bounds = _reachability_from_correlation_graph(graph)
    if not reachability:
        raise RuntimeFactsBundleError("runtime_facts_empty")
    freshness_policy = run.result_manifest.get("freshness_policy")
    input_snapshots = run.result_manifest.get("input_snapshots")
    if not isinstance(freshness_policy, Mapping) or not isinstance(input_snapshots, list):
        raise RuntimeFactsBundleError("correlation_manifest_invalid")
    if (
        freshness_policy.get("max_age_hours") != run.max_age_hours
        or freshness_policy.get("allow_stale") is not run.allow_stale
        or _immutable_input_receipts(input_snapshots) != _immutable_input_receipts(run.input_manifest)
    ):
        raise RuntimeFactsBundleError("correlation_manifest_mismatch")
    input_freshness = {
        "max_age_hours": freshness_policy.get("max_age_hours"),
        "allow_stale": freshness_policy.get("allow_stale"),
        "snapshots": [
            {
                "scan_id": item.get("scan_id"),
                "created_at": item.get("created_at"),
            }
            for item in input_snapshots
            if isinstance(item, Mapping)
        ],
    }
    issued = _utc(now or datetime.now(timezone.utc))
    _normalized_input_freshness, evidence_freshness, _fresh_until = _validated_input_freshness(
        input_freshness,
        at=issued,
    )
    return create_runtime_facts_bundle(
        correlation_id=run.correlation_id,
        tenant_id=run.tenant_id,
        manifest_sha256=run.manifest_sha256,
        reachability=reachability,
        signing_key=signing_key,
        ttl_seconds=ttl_seconds,
        now=issued,
        key_id=key_id,
        evidence_freshness=evidence_freshness,
        analysis_bounds=analysis_bounds,
        input_freshness=input_freshness,
    )


def verify_runtime_facts_bundle(
    bundle: Mapping[str, Any],
    *,
    signing_key: bytes,
    tenant_id: str,
    now: datetime | None = None,
) -> VerifiedRuntimeFacts:
    """Verify structure, signature, tenant binding, and expiry."""

    _validate_key(signing_key)
    payload = bundle.get("payload")
    signature = bundle.get("signature")
    if not isinstance(payload, Mapping) or not isinstance(signature, Mapping):
        raise RuntimeFactsBundleError("malformed_bundle")
    if signature.get("algorithm") != _ALGORITHM:
        raise RuntimeFactsBundleError("unsupported_signature_algorithm")
    key_id = _validated_key_id(signature.get("key_id", ""))
    supplied = str(signature.get("value") or "")
    expected = hmac.digest(signing_key, _signature_input(payload, key_id=key_id), "sha256").hex()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise RuntimeFactsBundleError("invalid_signature")
    if payload.get("schema_version") != _SCHEMA:
        raise RuntimeFactsBundleError("unsupported_schema")
    if str(payload.get("tenant_id") or "") != tenant_id:
        raise RuntimeFactsBundleError("tenant_mismatch")
    correlation_id = str(payload.get("correlation_id") or "").strip()
    manifest_sha256 = str(payload.get("manifest_sha256") or "")
    if not correlation_id:
        raise RuntimeFactsBundleError("invalid_identity")
    if _SHA256_RE.fullmatch(manifest_sha256) is None:
        raise RuntimeFactsBundleError("invalid_manifest_hash")
    evidence_freshness = str(payload.get("evidence_freshness") or "")
    if evidence_freshness not in {"fresh", "stale_allowed"}:
        raise RuntimeFactsBundleError("invalid_evidence_freshness")
    raw_analysis_bounds = payload.get("analysis_bounds")
    if not isinstance(raw_analysis_bounds, Mapping):
        raise RuntimeFactsBundleError("invalid_analysis_bounds")
    analysis_bounds = _validated_analysis_bounds(raw_analysis_bounds)

    issued_at = _parse_timestamp(payload.get("issued_at"))
    expires_at = _parse_timestamp(payload.get("expires_at"))
    moment = _utc(now or datetime.now(timezone.utc))
    if issued_at - moment > timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS):
        raise RuntimeFactsBundleError("bundle_not_yet_valid")
    if expires_at <= issued_at or expires_at - issued_at > timedelta(seconds=_MAX_TTL_SECONDS):
        raise RuntimeFactsBundleError("invalid_expiry")
    if moment >= expires_at:
        raise RuntimeFactsBundleError("bundle_expired")
    raw_input_freshness = payload.get("input_freshness")
    if raw_input_freshness is not None:
        if not isinstance(raw_input_freshness, Mapping):
            raise RuntimeFactsBundleError("invalid_input_freshness")
        _normalized_at_issue, freshness_at_issue, _fresh_until = _validated_input_freshness(
            raw_input_freshness,
            at=issued_at,
        )
        if freshness_at_issue != evidence_freshness:
            raise RuntimeFactsBundleError("invalid_input_freshness")
        _normalized_now, evidence_freshness, _fresh_until = _validated_input_freshness(
            raw_input_freshness,
            at=moment,
        )

    by_agent: dict[str, AgentReachability] = {}
    raw_facts = payload.get("facts")
    if not isinstance(raw_facts, list):
        raise RuntimeFactsBundleError("malformed_facts")
    for raw in raw_facts:
        if not isinstance(raw, Mapping):
            raise RuntimeFactsBundleError("malformed_facts")
        agent_id = str(raw.get("agent_id") or "").strip()
        if not agent_id:
            raise RuntimeFactsBundleError("malformed_facts")
        node_ids = raw.get("node_ids")
        node_labels = raw.get("node_labels")
        if not isinstance(node_ids, list) or not isinstance(node_labels, list):
            raise RuntimeFactsBundleError("malformed_facts")
        by_agent[agent_id.lower()] = AgentReachability(
            agent_id=agent_id,
            node_ids=frozenset(str(item) for item in node_ids if str(item)),
            node_labels=frozenset(str(item) for item in node_labels if str(item)),
            rule_id=str(raw.get("rule_id") or "AGENT_REACHES_PRIVILEGED"),
            severity=str(raw.get("severity") or "high"),
            detail=str(raw.get("detail") or ""),
        )
    return VerifiedRuntimeFacts(
        correlation_id=correlation_id,
        tenant_id=tenant_id,
        manifest_sha256=manifest_sha256,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=key_id,
        evidence_freshness=evidence_freshness,
        analysis_complete=bool(analysis_bounds["complete"]),
        analysis_bounds=analysis_bounds,
        reachability=ReachabilityMap(by_agent=by_agent),
    )


class RuntimeFactsPoller:
    """Fetch verified bundles while retaining the last unexpired valid value."""

    def __init__(
        self,
        *,
        fetch: Callable[[], Awaitable[Mapping[str, Any]]],
        signing_key: bytes,
        tenant_id: str,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._fetch = fetch
        self._signing_key = signing_key
        self._tenant_id = tenant_id
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._current: VerifiedRuntimeFacts | None = None
        self.last_error = ""

    async def refresh(self) -> bool:
        try:
            bundle = await self._fetch()
            verified = verify_runtime_facts_bundle(
                bundle,
                signing_key=self._signing_key,
                tenant_id=self._tenant_id,
                now=self._now(),
            )
        except RuntimeFactsBundleError as exc:
            self.last_error = exc.code
            if exc.code in RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS:
                self._current = None
            return False
        except Exception:  # noqa: BLE001 - external details are intentionally discarded
            self.last_error = "bundle_fetch_failed"
            return False
        self._current = verified
        self.last_error = ""
        return True

    def current(self) -> VerifiedRuntimeFacts | None:
        if self._current is None:
            return None
        if _utc(self._now()) >= self._current.expires_at:
            return None
        return self._current


__all__ = [
    "RuntimeFactsBundleError",
    "RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS",
    "RuntimeFactsPoller",
    "VerifiedRuntimeFacts",
    "create_runtime_facts_bundle",
    "create_runtime_facts_bundle_from_correlation",
    "verify_runtime_facts_bundle",
]
