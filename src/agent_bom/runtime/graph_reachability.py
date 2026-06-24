"""Graph-derived reachability facts → runtime gateway enforcement (consume side).

The unified graph already detects, statically, which AI agents can reach a
credential or privileged-tool node along their tool-use chain — the
``AGENT_REACHES_PRIVILEGED`` toxic-combination rule
(:mod:`agent_bom.graph.toxic_findings`). Today that signal is *advisory*: it
surfaces as a Finding but the runtime gateway / proxy never consults it, so a
prompt-injected or compromised agent is only stopped *after* a runtime detector
correlates a suspicious call sequence — never pre-emptively on the first attempt.

This module is the **consume** direction of that loop: it parses a scan report's
toxic-combination findings into a read-only ``agent_id -> reachable privileged
node ids / tool names`` map that the gateway enforcement point can check in-path,
blocking (or, in dry-run, warning on) the *first* call an over-reaching agent
makes against one of those privileged targets.

It is intentionally:

* **Read-only / no network.** Only ``Path.read_text`` + ``json.loads``.
* **Fail-safe.** A missing / malformed / empty report yields an empty map; the
  caller treats an empty map as a no-op (current default-allow behaviour).
* **Declarative.** Facts come straight from the graph findings; nothing about
  which agents or tools are "privileged" is hardcoded here.

The reverse direction — feeding *runtime* observations back into the graph to
refine reachability (the runtime→graph feedback loop) — is a deliberate
follow-up and is **not** built here.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

#: The toxic-combination rule whose findings carry agent→privileged reachability.
REACHABILITY_RULE_ID = "AGENT_REACHES_PRIVILEGED"


def _norm(value: object) -> str:
    """Lower-cased, stripped string form for case-insensitive matching."""
    return str(value or "").strip().lower()


@dataclass(frozen=True)
class AgentReachability:
    """Reachability facts for one source agent, derived from the graph.

    ``node_ids`` are the credential / privileged-tool *graph node ids* the agent
    can reach; ``node_labels`` are their human labels (often the tool name a
    runtime call targets). ``rule_id`` / ``severity`` carry the originating
    toxic-combination rule so the enforcement audit/governance event matches the
    finding an operator already triaged.
    """

    agent_id: str
    node_ids: frozenset[str] = frozenset()
    node_labels: frozenset[str] = frozenset()
    rule_id: str = REACHABILITY_RULE_ID
    severity: str = "high"
    detail: str = ""

    def reaches(self, target: str) -> bool:
        """True if ``target`` (a node id or tool/label) is a reachable privileged node."""
        key = _norm(target)
        if not key:
            return False
        return key in {_norm(n) for n in self.node_ids} or key in {_norm(label) for label in self.node_labels}


@dataclass(frozen=True)
class ReachabilityMap:
    """Read-only ``agent_id -> AgentReachability`` lookup with a fail-safe API.

    An empty map (the default for absent / unreadable facts) is a hard no-op:
    :meth:`lookup` returns ``None`` for every agent so the gateway falls through
    to its existing default-allow behaviour.
    """

    by_agent: Mapping[str, AgentReachability] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.by_agent)

    def lookup(self, agent_id: str) -> AgentReachability | None:
        """Return the facts for ``agent_id`` (case-insensitive), or ``None``."""
        key = _norm(agent_id)
        if not key:
            return None
        return self.by_agent.get(key)

    def reaches_privileged(self, agent_id: str, target: str) -> AgentReachability | None:
        """Return the matching facts when ``agent_id`` is known to reach ``target``.

        ``target`` is matched against both reachable node ids and node labels
        (tool names). Returns ``None`` when the agent is unknown or the target is
        not one of its reachable privileged nodes — the fail-safe / no-op path.
        """
        facts = self.lookup(agent_id)
        if facts is None:
            return None
        return facts if facts.reaches(target) else None


def _iter_finding_dicts(payload: object) -> Iterable[dict]:
    """Yield finding-shaped dicts from a parsed report.

    Robust to the two places a report serializes these (the unified top-level
    ``findings`` list and the standalone ``toxic_combinations_graph.findings``
    block), as well as a bare list of finding dicts.
    """
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(payload, dict):
        return
    seen: set[int] = set()
    for finding in payload.get("findings") or []:
        if isinstance(finding, dict):
            seen.add(id(finding))
            yield finding
    graph_block = payload.get("toxic_combinations_graph")
    if isinstance(graph_block, dict):
        for finding in graph_block.get("findings") or []:
            if isinstance(finding, dict) and id(finding) not in seen:
                yield finding


def _is_reachability_finding(finding: dict) -> bool:
    evidence = finding.get("evidence")
    rule_id = ""
    if isinstance(evidence, dict):
        rule_id = str(evidence.get("rule_id") or evidence.get("toxic_combination") or "")
    if not rule_id:
        rule_id = str(finding.get("rule_id") or finding.get("toxic_combination") or "")
    return rule_id.strip().upper() == REACHABILITY_RULE_ID


def _agent_id_of(finding: dict) -> str:
    """The source agent for a reachability finding (the finding's asset)."""
    asset = finding.get("asset")
    if isinstance(asset, dict):
        for key in ("name", "identifier", "canonical_id", "stable_id"):
            value = asset.get(key)
            if value:
                return str(value)
    return ""


def _privileged_nodes(finding: dict) -> tuple[frozenset[str], frozenset[str]]:
    """Return (node_ids, node_labels) for the privileged nodes a finding names.

    The agent's own node is excluded so the map only carries *targets* the agent
    reaches — the agent id is recorded separately via :func:`_agent_id_of`.
    """
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return frozenset(), frozenset()
    agent_id = _agent_id_of(finding)
    node_ids: set[str] = set()
    labels: set[str] = set()
    # Node ids that belong to the *agent itself* — never enforcement targets.
    agent_node_ids: set[str] = set()

    participating = evidence.get("participating_nodes")
    if isinstance(participating, list):
        for node in participating:
            if not isinstance(node, dict):
                continue
            nid = node.get("id")
            entity_type = _norm(node.get("entity_type"))
            # The agent's own node participates first; never treat it as a target.
            if entity_type == "agent":
                if nid:
                    agent_node_ids.add(_norm(nid))
                continue
            label = node.get("label")
            if nid:
                node_ids.add(str(nid))
            if label:
                labels.add(str(label))

    raw_ids = evidence.get("node_ids")
    if isinstance(raw_ids, list):
        for nid in raw_ids:
            key = _norm(nid)
            if nid and key != _norm(agent_id) and key not in agent_node_ids:
                node_ids.add(str(nid))

    return frozenset(node_ids), frozenset(labels)


def reachability_map_from_report_data(payload: object) -> ReachabilityMap:
    """Build a :class:`ReachabilityMap` from parsed report JSON (never raises)."""
    by_agent: dict[str, AgentReachability] = {}
    try:
        for finding in _iter_finding_dicts(payload):
            if not _is_reachability_finding(finding):
                continue
            agent_id = _agent_id_of(finding)
            if not agent_id:
                continue
            node_ids, labels = _privileged_nodes(finding)
            if not node_ids and not labels:
                continue
            evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
            severity = str(finding.get("severity") or finding.get("effective_severity") or "high")
            detail = ""
            if isinstance(evidence, dict):
                detail = str(evidence.get("detail") or "")

            key = _norm(agent_id)
            existing = by_agent.get(key)
            if existing is not None:
                node_ids = existing.node_ids | node_ids
                labels = existing.node_labels | labels
            by_agent[key] = AgentReachability(
                agent_id=agent_id,
                node_ids=node_ids,
                node_labels=labels,
                rule_id=REACHABILITY_RULE_ID,
                severity=severity,
                detail=detail or (existing.detail if existing else ""),
            )
    except Exception:  # noqa: BLE001 — fail-safe: a bad payload must never break the relay
        return ReachabilityMap(by_agent={})
    return ReachabilityMap(by_agent=by_agent)


def load_reachability_map(path: str | Path | None) -> ReachabilityMap:
    """Load reachability facts from a scan-report JSON file.

    Returns an empty (no-op) map when ``path`` is ``None`` / missing / unreadable
    / malformed — enforcement is then a no-op and the relay is never broken.
    Read-only, no network.
    """
    if path is None:
        return ReachabilityMap(by_agent={})
    file_path = Path(path)
    try:
        if not file_path.is_file():
            return ReachabilityMap(by_agent={})
        payload = json.loads(file_path.read_text())
    except (OSError, ValueError):
        return ReachabilityMap(by_agent={})
    return reachability_map_from_report_data(payload)


__all__ = [
    "REACHABILITY_RULE_ID",
    "AgentReachability",
    "ReachabilityMap",
    "reachability_map_from_report_data",
    "load_reachability_map",
]
