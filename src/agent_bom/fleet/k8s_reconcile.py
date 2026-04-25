"""Continuous Kubernetes inventory reconciliation helpers.

The scanner already discovers Kubernetes workloads point-in-time. This module
adds the stable identity and diff contract needed by scheduled jobs,
DaemonSets, or future operators to answer "what changed since the last
inventory observation?" without treating pod churn as a new asset.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

_SCHEMA_VERSION = 1
_DEFAULT_STALE_AFTER_SECONDS = 6 * 60 * 60


@dataclass(frozen=True)
class K8sInventoryObservation:
    """A normalized Kubernetes inventory observation."""

    tenant_id: str
    cluster: str
    namespace: str
    workload: str
    agent_name: str
    server_name: str
    surface: str
    observed_at: str | None = None
    node_name: str | None = None
    image: str | None = None
    endpoint: str | None = None
    discovery_sources: tuple[str, ...] = ()
    raw: Mapping[str, Any] | None = None

    @property
    def identity(self) -> dict[str, str]:
        """Return the fields that define the logical Kubernetes asset."""
        return {
            "tenant_id": self.tenant_id,
            "cluster": self.cluster,
            "namespace": self.namespace,
            "workload": self.workload,
            "agent_name": self.agent_name,
            "server_name": self.server_name,
            "surface": self.surface,
        }

    @property
    def key(self) -> str:
        """Stable key that survives pod UID/name churn."""
        material = "|".join(self.identity[field] for field in sorted(self.identity))
        return "k8s:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]

    @property
    def fingerprint(self) -> str:
        """Fingerprint mutable evidence so reconciliation can flag changes."""
        evidence = {
            "image": self.image or "",
            "endpoint": self.endpoint or "",
            "node_name": self.node_name or "",
            "discovery_sources": sorted(self.discovery_sources),
            "raw": _stable_raw(self.raw or {}),
        }
        return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def load_k8s_inventory_snapshot(path: str | Path) -> list[K8sInventoryObservation]:
    """Load a JSON snapshot and normalize supported inventory shapes."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return extract_k8s_inventory_observations(payload)


def extract_k8s_inventory_observations(payload: Mapping[str, Any]) -> list[K8sInventoryObservation]:
    """Normalize explicit observations or standard inventory JSON.

    Supported inputs:
    - ``{"k8s_inventory_observations": [...]}`` emitted by a reconciler.
    - standard agent-bom inventory JSON with ``agents[].mcp_servers[]``.
    """
    explicit = payload.get("k8s_inventory_observations")
    if isinstance(explicit, list):
        return [_normalize_observation(item, payload) for item in explicit if isinstance(item, Mapping)]

    observations: list[K8sInventoryObservation] = []
    agents = payload.get("agents", [])
    if not isinstance(agents, list):
        return observations

    for agent in agents:
        if not isinstance(agent, Mapping):
            continue
        agent_meta = _metadata(agent)
        servers = agent.get("mcp_servers", [])
        if not isinstance(servers, list):
            continue
        for server in servers:
            if not isinstance(server, Mapping):
                continue
            merged = {
                **_metadata(payload),
                **agent_meta,
                **_metadata(server),
                "tenant_id": _first_string(server, agent, payload, names=("tenant_id", "tenant")),
                "cluster": _first_string(server, agent, payload, names=("cluster", "cluster_name", "k8s_cluster")),
                "namespace": _first_string(server, agent, payload, names=("namespace", "k8s_namespace")),
                "workload": _first_string(server, agent, names=("workload", "deployment", "pod_name")),
                "agent_name": str(agent.get("name") or "unknown-agent"),
                "server_name": str(server.get("name") or "unknown-server"),
                "surface": str(server.get("surface") or "mcp-server"),
                "image": _first_string(server, agent, names=("image", "image_ref", "container_image")),
                "endpoint": _first_string(server, agent, names=("url", "endpoint", "base_url")),
                "node_name": _first_string(server, agent, names=("node", "node_name")),
                "discovery_sources": server.get("discovery_sources") or agent.get("discovery_sources") or [],
                "observed_at": _first_string(server, agent, payload, names=("observed_at", "last_seen_at", "scan_started_at")),
            }
            observations.append(_normalize_observation(merged, payload))
    return observations


def reconcile_k8s_inventory(
    previous: list[K8sInventoryObservation] | list[Mapping[str, Any]],
    current: list[K8sInventoryObservation] | list[Mapping[str, Any]],
    *,
    generated_at: datetime | None = None,
    stale_after_seconds: int = _DEFAULT_STALE_AFTER_SECONDS,
) -> dict[str, Any]:
    """Compare previous and current Kubernetes inventory observations."""
    now = generated_at or datetime.now(timezone.utc)
    generated = _iso(now)
    previous_obs = [_ensure_observation(item, {}) for item in previous]
    current_obs = [_ensure_observation(item, {}) for item in current]

    previous_by_key = {obs.key: obs for obs in previous_obs}
    current_by_key = {obs.key: obs for obs in current_obs}
    records: list[dict[str, Any]] = []
    summary = {
        "previous": len(previous_by_key),
        "current": len(current_by_key),
        "added": 0,
        "changed": 0,
        "unchanged": 0,
        "missing": 0,
        "stale": 0,
    }

    for key, obs in sorted(current_by_key.items()):
        prior = previous_by_key.get(key)
        if prior is None:
            status = "added"
        elif prior.fingerprint != obs.fingerprint:
            status = "changed"
        else:
            status = "unchanged"
        summary[status] += 1
        records.append(_record(obs, status=status, generated_at=generated, previous=prior))

    for key, prior in sorted(previous_by_key.items()):
        if key in current_by_key:
            continue
        status = "stale" if _is_stale(prior.observed_at, now=now, stale_after_seconds=stale_after_seconds) else "missing"
        summary[status] += 1
        records.append(_record(prior, status=status, generated_at=generated, previous=prior, current_seen=False))

    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": "k8s_inventory_reconciliation",
        "generated_at": generated,
        "stale_after_seconds": stale_after_seconds,
        "summary": summary,
        "records": records,
    }


def _ensure_observation(item: K8sInventoryObservation | Mapping[str, Any], defaults: Mapping[str, Any]) -> K8sInventoryObservation:
    if isinstance(item, K8sInventoryObservation):
        return item
    return _normalize_observation(item, defaults)


def _normalize_observation(item: Mapping[str, Any], defaults: Mapping[str, Any]) -> K8sInventoryObservation:
    merged = {**_metadata(defaults), **_metadata(item), **dict(item)}
    sources = merged.get("discovery_sources") or ()
    source_tuple: tuple[str, ...]
    if isinstance(sources, str):
        source_tuple = (sources,)
    elif isinstance(sources, list | tuple | set):
        source_tuple = tuple(str(source) for source in sources if str(source).strip())
    else:
        source_tuple = ()
    return K8sInventoryObservation(
        tenant_id=str(merged.get("tenant_id") or merged.get("tenant") or "default"),
        cluster=str(merged.get("cluster") or merged.get("cluster_name") or merged.get("k8s_cluster") or "unknown-cluster"),
        namespace=str(merged.get("namespace") or merged.get("k8s_namespace") or "default"),
        workload=str(
            merged.get("workload") or merged.get("deployment") or merged.get("pod_name") or merged.get("node_name") or "unknown-workload"
        ),
        agent_name=str(merged.get("agent_name") or merged.get("agent") or "unknown-agent"),
        server_name=str(merged.get("server_name") or merged.get("mcp_server") or merged.get("server") or "unknown-server"),
        surface=str(merged.get("surface") or "mcp-server"),
        observed_at=_optional_string(merged.get("observed_at") or merged.get("last_seen_at")),
        node_name=_optional_string(merged.get("node_name") or merged.get("node")),
        image=_optional_string(merged.get("image") or merged.get("image_ref") or merged.get("container_image")),
        endpoint=_optional_string(merged.get("endpoint") or merged.get("url") or merged.get("base_url")),
        discovery_sources=source_tuple,
        raw=merged,
    )


def _record(
    obs: K8sInventoryObservation,
    *,
    status: str,
    generated_at: str,
    previous: K8sInventoryObservation | None = None,
    current_seen: bool = True,
) -> dict[str, Any]:
    record = {
        "key": obs.key,
        "status": status,
        "identity": obs.identity,
        "fingerprint": obs.fingerprint,
        "observed_at": obs.observed_at,
        "current_seen": current_seen,
        "generated_at": generated_at,
        "evidence": {
            "image": obs.image,
            "endpoint": obs.endpoint,
            "node_name": obs.node_name,
            "discovery_sources": list(obs.discovery_sources),
        },
    }
    if previous is not None:
        record["previous_observed_at"] = previous.observed_at
        record["previous_fingerprint"] = previous.fingerprint
    return record


def _metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    metadata = value.get("metadata")
    return dict(metadata) if isinstance(metadata, Mapping) else {}


def _first_string(*values: Mapping[str, Any], names: tuple[str, ...]) -> str | None:
    for value in values:
        meta = _metadata(value)
        for name in names:
            candidate = value.get(name, meta.get(name))
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return None


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _stable_raw(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in raw.items()
        if key
        not in {
            "observed_at",
            "last_seen_at",
            "scan_started_at",
            "last_error",
        }
    }


def _is_stale(observed_at: str | None, *, now: datetime, stale_after_seconds: int) -> bool:
    if not observed_at:
        return True
    try:
        seen_at = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    if seen_at.tzinfo is None:
        seen_at = seen_at.replace(tzinfo=timezone.utc)
    return (now - seen_at).total_seconds() >= stale_after_seconds


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
