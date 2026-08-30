"""Signed, expiring correlation facts consumed by the runtime gateway."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping

from agent_bom.runtime.graph_reachability import AgentReachability, ReachabilityMap

_SCHEMA = "agent-bom.runtime-facts/v1"
_ALGORITHM = "HMAC-SHA256"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


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
) -> dict[str, Any]:
    """Create an HMAC-authenticated runtime-facts envelope."""

    _validate_key(signing_key)
    if not correlation_id or not tenant_id:
        raise RuntimeFactsBundleError("invalid_identity")
    if not manifest_sha256.startswith("sha256:") or len(manifest_sha256) != 71:
        raise RuntimeFactsBundleError("invalid_manifest_hash")
    if not 1 <= ttl_seconds <= 86400:
        raise RuntimeFactsBundleError("invalid_ttl")
    if evidence_freshness not in {"fresh", "stale_allowed"}:
        raise RuntimeFactsBundleError("invalid_evidence_freshness")
    issued = _utc(now or datetime.now(timezone.utc))
    payload = {
        "schema_version": _SCHEMA,
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "manifest_sha256": manifest_sha256,
        "evidence_freshness": evidence_freshness,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(seconds=ttl_seconds)).isoformat(),
        "facts": _facts(reachability),
    }
    signature = hmac.digest(signing_key, _canonical(payload), "sha256").hex()
    return {
        "payload": payload,
        "signature": {
            "algorithm": _ALGORITHM,
            "key_id": key_id,
            "value": signature,
        },
    }


def _reachability_from_correlation_graph(graph: Any) -> ReachabilityMap:
    from agent_bom.graph.types import EntityType

    target_types = {EntityType.TOOL, EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF}
    by_agent: dict[str, AgentReachability] = {}
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
        queue: list[tuple[str, int]] = [(agent.id, 0)]
        visited = {agent.id}
        while queue and len(visited) <= 5000:
            source, depth = queue.pop(0)
            if depth >= 6:
                continue
            for edge in graph.adjacency.get(source, []):
                correlation = edge.provenance.get("correlation") if isinstance(edge.provenance, dict) else None
                source_ids = correlation.get("source_scan_ids") if isinstance(correlation, dict) else None
                has_provenance = bool(source_ids or edge.source_scan_id or graph.scan_id)
                if not edge.traversable or not has_provenance or edge.target in visited:
                    continue
                visited.add(edge.target)
                target = graph.nodes.get(edge.target)
                if target is None:
                    continue
                if target.entity_type in target_types:
                    node_ids.add(target.id)
                    node_labels.add(target.label or target.id)
                queue.append((target.id, depth + 1))
        if node_ids or node_labels:
            by_agent[runtime_id.lower()] = AgentReachability(
                agent_id=runtime_id,
                node_ids=frozenset(node_ids),
                node_labels=frozenset(node_labels),
                detail="Derived from directed, traversable correlation graph relationships.",
            )
    return ReachabilityMap(by_agent=by_agent)


def create_runtime_facts_bundle_from_correlation(
    run: Any,
    graph: Any,
    *,
    signing_key: bytes,
    ttl_seconds: int,
    now: datetime | None = None,
    key_id: str = "",
) -> dict[str, Any]:
    """Produce runtime facts only from a completed, tenant-bound correlation."""

    from agent_bom.graph.correlation import CorrelationRunStatus

    if run.status is not CorrelationRunStatus.COMPLETE:
        raise RuntimeFactsBundleError("correlation_not_complete")
    if run.output_scan_id != run.correlation_id or graph.scan_id != run.correlation_id:
        raise RuntimeFactsBundleError("correlation_output_mismatch")
    if graph.tenant_id != run.tenant_id:
        raise RuntimeFactsBundleError("tenant_mismatch")
    evidence_freshness = (
        "stale_allowed" if any(str(item.get("freshness") or "") == "stale_allowed" for item in run.input_manifest) else "fresh"
    )
    return create_runtime_facts_bundle(
        correlation_id=run.correlation_id,
        tenant_id=run.tenant_id,
        manifest_sha256=run.manifest_sha256,
        reachability=_reachability_from_correlation_graph(graph),
        signing_key=signing_key,
        ttl_seconds=ttl_seconds,
        now=now,
        key_id=key_id,
        evidence_freshness=evidence_freshness,
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
    supplied = str(signature.get("value") or "")
    expected = hmac.digest(signing_key, _canonical(payload), "sha256").hex()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise RuntimeFactsBundleError("invalid_signature")
    if payload.get("schema_version") != _SCHEMA:
        raise RuntimeFactsBundleError("unsupported_schema")
    if str(payload.get("tenant_id") or "") != tenant_id:
        raise RuntimeFactsBundleError("tenant_mismatch")
    evidence_freshness = str(payload.get("evidence_freshness") or "")
    if evidence_freshness not in {"fresh", "stale_allowed"}:
        raise RuntimeFactsBundleError("invalid_evidence_freshness")

    issued_at = _parse_timestamp(payload.get("issued_at"))
    expires_at = _parse_timestamp(payload.get("expires_at"))
    moment = _utc(now or datetime.now(timezone.utc))
    if expires_at <= issued_at:
        raise RuntimeFactsBundleError("invalid_expiry")
    if moment >= expires_at:
        raise RuntimeFactsBundleError("bundle_expired")

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
        correlation_id=str(payload.get("correlation_id") or ""),
        tenant_id=tenant_id,
        manifest_sha256=str(payload.get("manifest_sha256") or ""),
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=str(signature.get("key_id") or ""),
        evidence_freshness=evidence_freshness,
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
    "RuntimeFactsPoller",
    "VerifiedRuntimeFacts",
    "create_runtime_facts_bundle",
    "create_runtime_facts_bundle_from_correlation",
    "verify_runtime_facts_bundle",
]
