"""Bounded projection of persisted graph paths onto finding-list rows.

The graph store is the durable source for ranked ExposurePaths. Findings are a
separate current-state projection, so this module joins only the current page
to a bounded path window and leaves unassessed rows unknown instead of
inventing ``False`` evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from agent_bom.api.graph_store import GraphStoreProtocol
    from agent_bom.graph.container import AttackPath


MAX_FINDING_REACHABILITY_PATHS = 1000


@dataclass(frozen=True, slots=True)
class FindingReachabilityProjection:
    rows: list[dict[str, Any]]
    truncated: bool


@dataclass(slots=True)
class _ReachabilityEvidence:
    min_hops: int
    agents: set[str]


def _text(value: object) -> str:
    return str(value).strip() if isinstance(value, str) else ""


def _vulnerability_id(value: object) -> str:
    normalized = _text(value)
    if not normalized:
        return ""
    lowered = normalized.lower()
    for prefix in ("vuln:", "finding:"):
        if lowered.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    return normalized.upper()


def _row_vulnerability_ids(row: Mapping[str, Any]) -> set[str]:
    values: list[object] = [row.get("cve_id"), row.get("vulnerability_id")]
    for key in ("cve_ids", "advisory_ids", "aliases", "advisory_aliases"):
        collection = row.get(key)
        if isinstance(collection, list):
            values.extend(collection)
    return {identifier for value in values if (identifier := _vulnerability_id(value))}


def _path_vulnerability_ids(path: AttackPath) -> set[str]:
    values: list[object] = list(path.vuln_ids)
    values.append(path.target)
    values.extend(path.hops)
    return {
        identifier
        for value in values
        if (identifier := _vulnerability_id(value)).startswith(("CVE-", "GHSA-", "MAL-"))
    }


def _row_node_ids(row: Mapping[str, Any]) -> set[str]:
    return {node_id for key in ("node_id", "finding_node_id") if (node_id := _text(row.get(key)))}


def _row_finding_ids(row: Mapping[str, Any]) -> set[str]:
    return {finding_id for key in ("id", "canonical_id") if (finding_id := _text(row.get(key)))}


def _path_matches_row(path: AttackPath, row: Mapping[str, Any]) -> bool:
    finding_ids = _row_finding_ids(row)
    if finding_ids.intersection(path.finding_ids):
        return True

    if not _row_vulnerability_ids(row).intersection(_path_vulnerability_ids(path)):
        return False

    # When the finding carries graph FKs, require one on the path. This avoids
    # marking every asset-specific occurrence of a shared CVE reachable because
    # a different package/server occurrence has a path.
    row_nodes = _row_node_ids(row)
    if not row_nodes:
        return True
    return bool(row_nodes.intersection({path.source, path.target, *path.hops}))


def _path_hop_distance(path: AttackPath, row: Mapping[str, Any]) -> int:
    hops = list(path.hops)
    if not hops:
        return 0
    try:
        source_index = hops.index(path.source)
    except ValueError:
        source_index = 0

    row_nodes = _row_node_ids(row)
    matching_indexes = [index for index, node_id in enumerate(hops) if node_id in row_nodes]
    if matching_indexes:
        forward = [index - source_index for index in matching_indexes if index >= source_index]
        if forward:
            return min(forward)
    try:
        target_index = hops.index(path.target)
    except ValueError:
        target_index = len(hops) - 1
    return max(0, target_index - source_index)


def _reaching_agents(path: AttackPath) -> set[str]:
    agents = {node_id for node_id in (path.source, *path.hops) if node_id.startswith("agent:")}
    return agents


def project_persisted_graph_reachability(
    rows: list[dict[str, Any]],
    *,
    graph_store: GraphStoreProtocol,
    tenant_id: str,
    scan_id: str | None,
    path_limit: int = MAX_FINDING_REACHABILITY_PATHS,
) -> FindingReachabilityProjection:
    """Project one bounded, tenant-scoped path read onto a findings page.

    A missing match is not proof of unreachability, particularly when the path
    window is truncated, so non-overlapping rows retain their prior value and
    otherwise remain ``None``.
    """

    projected = [dict(row) for row in rows]
    for row in projected:
        row.setdefault("graph_reachable", None)
        row.setdefault("graph_min_hop_distance", None)
        row.setdefault("graph_reachable_from_agents", [])
    if not projected or not any(_row_vulnerability_ids(row) or _row_finding_ids(row) for row in projected):
        return FindingReachabilityProjection(projected, truncated=False)

    bounded_limit = max(1, min(int(path_limit), MAX_FINDING_REACHABILITY_PATHS))
    _effective_scan_id, _created_at, paths, total = graph_store.attack_paths(
        tenant_id=tenant_id,
        scan_id=scan_id or "",
        offset=0,
        limit=bounded_limit,
    )

    paths_by_finding: dict[str, list[AttackPath]] = {}
    paths_by_vulnerability: dict[str, list[AttackPath]] = {}
    for path in paths:
        for finding_id in set(path.finding_ids):
            paths_by_finding.setdefault(finding_id, []).append(path)
        for vulnerability_id in _path_vulnerability_ids(path):
            paths_by_vulnerability.setdefault(vulnerability_id, []).append(path)

    evidence_by_row: dict[int, _ReachabilityEvidence] = {}
    for index, row in enumerate(projected):
        candidates: dict[int, AttackPath] = {}
        for finding_id in _row_finding_ids(row):
            candidates.update((id(path), path) for path in paths_by_finding.get(finding_id, ()))
        for vulnerability_id in _row_vulnerability_ids(row):
            candidates.update((id(path), path) for path in paths_by_vulnerability.get(vulnerability_id, ()))
        for path in candidates.values():
            if not _path_matches_row(path, row):
                continue
            distance = _path_hop_distance(path, row)
            evidence = evidence_by_row.get(index)
            if evidence is None:
                evidence = _ReachabilityEvidence(min_hops=distance, agents=set())
                evidence_by_row[index] = evidence
            else:
                evidence.min_hops = min(evidence.min_hops, distance)
            evidence.agents.update(_reaching_agents(path))

    for index, evidence in evidence_by_row.items():
        row = projected[index]
        prior_distance = row.get("graph_min_hop_distance")
        row["graph_reachable"] = True
        row["graph_min_hop_distance"] = (
            min(prior_distance, evidence.min_hops)
            if isinstance(prior_distance, int) and not isinstance(prior_distance, bool) and prior_distance >= 0
            else evidence.min_hops
        )
        prior_agents = row.get("graph_reachable_from_agents")
        if isinstance(prior_agents, list):
            evidence.agents.update(_text(value) for value in prior_agents if _text(value))
        row["graph_reachable_from_agents"] = sorted(evidence.agents)

    return FindingReachabilityProjection(projected, truncated=total > len(paths))
