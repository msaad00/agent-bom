"""Declarative graph toxic-combination rule evaluator → enforceable Findings.

The CNAPP overlay (:mod:`agent_bom.graph.cnapp_overlay`), the effective-permissions
overlay, and the attack-path fusion engine (:mod:`agent_bom.graph.attack_path_fusion`)
all reason over the *same* unified graph and stamp high-signal attributes
(``internet_exposed``, ``toxic_exposed_vulnerable``, ``toxic_exposed_sensitive``,
``data_sensitivity``, ``escalates_to_admin``) plus first-class edges
(``EXPOSED_TO``, ``STORES``, ``HAS_PERMISSION``, ``REACHES_TOOL``). On their own
those signals never reach :meth:`AIBOMReport.to_findings` or the
``--fail-on-severity`` exit-code gate.

This module closes that gap. It runs a set of declarative :class:`ToxicRule`
patterns over the enriched graph and emits unified :class:`Finding` objects so a
toxic combination — several individually-tolerable conditions that together form
one exploitable path — is enforced like any other finding.

Design notes:

* **Read-only / no network.** Every rule is a pure function of the graph that the
  builder already enriched in process; nothing here performs IO.
* **Reuse, don't recompute.** Rules consume the flags the overlays already wrote
  rather than re-deriving exposure / sensitivity / escalation.
* **Severity escalation.** A combination is worse than the sum of its parts: a
  finding's severity is one tier above the maximum component severity, capped at
  ``critical``.
* **Data-driven.** Adding a sixth rule is a single :class:`ToxicRule` entry plus a
  match function; no wiring changes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Optional

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.severity import severity_rank
from agent_bom.graph.types import EntityType, RelationshipType

_GRAPH_SOURCE = "graph-toxic-combination"

# ── Severity model ───────────────────────────────────────────────────────────
_ESCALATION_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RISK = {"info": 1.0, "low": 3.0, "medium": 5.0, "high": 7.5, "critical": 9.5}

# Principal entity types that can hold (over-)permissions to data.
_PRINCIPAL_TYPES = frozenset(
    {
        EntityType.USER,
        EntityType.ROLE,
        EntityType.SERVICE_ACCOUNT,
        EntityType.SERVICE_PRINCIPAL,
        EntityType.AGENT,
        EntityType.MANAGED_IDENTITY,
        EntityType.FEDERATED_IDENTITY,
    }
)

# Edges that move a principal toward effective control of a resource.
_LATERAL_RELS = frozenset(
    {
        RelationshipType.ASSUMES,
        RelationshipType.CAN_ACCESS,
        RelationshipType.HAS_PERMISSION,
        RelationshipType.CROSS_ACCOUNT_TRUST,
        RelationshipType.TRUSTS,
    }
)

# Account-scoped targets reached by lateral movement.
_LATERAL_TARGET_TYPES = frozenset(
    {
        EntityType.ACCOUNT,
        EntityType.ROLE,
        EntityType.SERVICE_ACCOUNT,
        EntityType.SERVICE_PRINCIPAL,
    }
)

# Tokens in HAS_PERMISSION evidence that indicate admin/write (not read-only).
_WRITE_PRIVILEGE_TOKENS = (
    "admin",
    "owner",
    "root",
    "write",
    "fullaccess",
    "full_access",
    "all_privileges",
    "ownership",
    "modify",
    "delete",
    "*:*",
)


# ── Match evidence ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ToxicMatch:
    """One concrete hit of a :class:`ToxicRule` against the graph.

    ``entry`` is the most-actionable node (the finding's asset). ``node_ids`` are
    every participating node; ``path`` is the ordered relationship walk; the
    per-component ``severities`` drive escalation.
    """

    entry: UnifiedNode
    node_ids: tuple[str, ...]
    path: tuple[str, ...]
    severities: tuple[str, ...]
    detail: str = ""

    @property
    def dedupe_key(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.node_ids)))


# ── Declarative rule ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ToxicRule:
    """A declarative toxic-combination pattern.

    ``match`` is a pure callable ``(graph) -> list[ToxicMatch]``. ``severity`` is
    the *base* tier of the worst single component the rule looks for; the actual
    finding escalates one tier above the matched components (see
    :func:`_escalate`).
    """

    id: str
    title: str
    severity: str
    mitre: tuple[str, ...]
    description: str
    remediation: str
    match: Callable[[UnifiedGraph], list[ToxicMatch]]
    owasp_tags: tuple[str, ...] = field(default_factory=tuple)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _node_severity(node: UnifiedNode) -> str:
    sev = (node.severity or "").lower()
    return sev if sev in _ESCALATION_SEVERITIES else "low"


def _escalate(component_severities: tuple[str, ...], floor: str) -> str:
    """Combination severity = one tier above the max component, capped critical.

    ``floor`` guarantees a rule that asserts an inherently severe pattern never
    drops below its declared base tier even if its component nodes carry thin
    severity metadata.
    """
    base_rank = max((severity_rank(s) for s in component_severities), default=severity_rank("info"))
    escalated = min(base_rank + 1, severity_rank("critical"))
    floored = max(escalated, severity_rank(floor))
    index = max(0, min(floored - severity_rank("info"), len(_ESCALATION_SEVERITIES) - 1))
    return _ESCALATION_SEVERITIES[index]


def _asset_for(node: UnifiedNode) -> Asset:
    attrs = node.attributes
    et = node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)
    identifier = None
    for key in ("canonical_id", "arn", "resource_id", "principal_id", "object_fqn"):
        val = attrs.get(key)
        if isinstance(val, str) and val.strip():
            identifier = val
            break
    location = None
    for key in ("region", "location", "provider", "cloud_provider", "account"):
        val = attrs.get(key)
        if isinstance(val, str) and val.strip():
            location = val
            break
    return Asset(name=node.label, asset_type=et, identifier=identifier or node.id, location=location)


def _label(graph: UnifiedGraph, node_id: str) -> str:
    node = graph.nodes.get(node_id)
    return node.label if node is not None else node_id


def _is_write_permission(edge_evidence: dict) -> bool:
    """True when a HAS_PERMISSION edge grants admin/write, not read-only."""
    if not isinstance(edge_evidence, dict):
        return False
    if edge_evidence.get("privileged") is True:
        return True
    haystack_parts: list[str] = []
    for key in ("access", "privilege", "role", "roles", "level"):
        val = edge_evidence.get(key)
        if isinstance(val, str):
            haystack_parts.append(val)
        elif isinstance(val, (list, tuple)):
            haystack_parts.extend(str(v) for v in val)
    haystack = " ".join(haystack_parts).lower()
    return any(tok in haystack for tok in _WRITE_PRIVILEGE_TOKENS)


# ── Rule match functions ─────────────────────────────────────────────────────


def _match_public_exposed_vulnerable(graph: UnifiedGraph) -> list[ToxicMatch]:
    """Internet-exposed resource that also carries a known vulnerability."""
    return _match_public_exposed_vulnerability_where(
        graph,
        predicate=lambda _vuln: True,
        detail="is reachable from the public internet and carries a known vulnerability.",
    )


def _match_public_exposed_vulnerability_where(
    graph: UnifiedGraph,
    *,
    predicate: Callable[[UnifiedNode], bool],
    detail: str,
) -> list[ToxicMatch]:
    matches: list[ToxicMatch] = []
    for node in graph.nodes.values():
        if not node.attributes.get("toxic_exposed_vulnerable"):
            continue
        vuln_ids = [
            e.target
            for e in graph.adjacency.get(node.id, [])
            if e.relationship == RelationshipType.VULNERABLE_TO and graph.nodes.get(e.target) is not None
            and predicate(graph.nodes[e.target])
        ]
        if not vuln_ids:
            continue
        node_ids = (node.id, *sorted(set(vuln_ids)))
        sevs = (_node_severity(node), *(_node_severity(graph.nodes[v]) for v in vuln_ids if v in graph.nodes))
        matches.append(
            ToxicMatch(
                entry=node,
                node_ids=node_ids,
                path=("internet_exposed", RelationshipType.VULNERABLE_TO.value),
                severities=sevs or (_node_severity(node),),
                detail=f"{node.label} {detail}",
            )
        )
    return matches


def _match_public_exposed_kev(graph: UnifiedGraph) -> list[ToxicMatch]:
    return _match_public_exposed_vulnerability_where(
        graph,
        predicate=lambda vuln: bool(vuln.attributes.get("is_kev")),
        detail="is reachable from the public internet and carries a CISA KEV vulnerability.",
    )


def _match_public_exposed_rce(graph: UnifiedGraph) -> list[ToxicMatch]:
    return _match_public_exposed_vulnerability_where(
        graph,
        predicate=lambda vuln: vuln.attributes.get("impact_category") == "code-execution",
        detail="is reachable from the public internet and carries a CWE-backed code-execution vulnerability.",
    )


def _match_public_exposed_network_exploitable(graph: UnifiedGraph) -> list[ToxicMatch]:
    return _match_public_exposed_vulnerability_where(
        graph,
        predicate=lambda vuln: bool(vuln.attributes.get("network_exploitable")) or vuln.attributes.get("attack_vector") == "network",
        detail="is reachable from the public internet and carries a CVSS AV:N network-exploitable vulnerability.",
    )


def _match_public_to_sensitive_data(graph: UnifiedGraph) -> list[ToxicMatch]:
    """Internet-exposed resource that reaches a sensitive data store."""
    from agent_bom.graph.attack_path_fusion import _is_crown_jewel

    matches: list[ToxicMatch] = []
    for store in graph.nodes.values():
        if store.entity_type != EntityType.DATA_STORE:
            continue
        is_crown = _is_crown_jewel(store)
        directly_exposed = bool(store.attributes.get("toxic_exposed_sensitive"))
        if not is_crown and not directly_exposed:
            continue
        # Find an internet-exposed node that reaches this store via STORES/EXPOSED_TO/HAS_PERMISSION.
        reachers = [
            e.source
            for e in graph.reverse_adjacency.get(store.id, [])
            if e.relationship in (RelationshipType.STORES, RelationshipType.EXPOSED_TO, RelationshipType.HAS_PERMISSION)
            and (src := graph.nodes.get(e.source)) is not None
            and src.attributes.get("internet_exposed")
        ]
        node_ids: tuple[str, ...]
        sevs: tuple[str, ...]
        if directly_exposed and not reachers:
            # The store itself is flagged exposed+sensitive (sensitive data on a public store).
            entry = store
            node_ids = (store.id,)
            sevs = (_node_severity(store),)
        elif reachers:
            entry_id = sorted(set(reachers))[0]
            entry = graph.nodes[entry_id]
            node_ids = (entry.id, store.id)
            sevs = (_node_severity(entry), _node_severity(store))
        else:
            continue
        matches.append(
            ToxicMatch(
                entry=entry,
                node_ids=node_ids,
                path=("internet_exposed", RelationshipType.STORES.value),
                severities=sevs,
                detail=f"Internet-exposed path reaches sensitive data store {store.label}.",
            )
        )
    return matches


def _match_overpermissioned_to_sensitive(graph: UnifiedGraph) -> list[ToxicMatch]:
    """A principal with admin/write permission to a sensitive data store."""
    from agent_bom.graph.attack_path_fusion import _is_crown_jewel

    matches: list[ToxicMatch] = []
    for edge in graph.edges:
        if edge.relationship != RelationshipType.HAS_PERMISSION:
            continue
        principal = graph.nodes.get(edge.source)
        target = graph.nodes.get(edge.target)
        if principal is None or target is None:
            continue
        if principal.entity_type not in _PRINCIPAL_TYPES:
            continue
        sensitive = target.entity_type == EntityType.DATA_STORE and (_is_crown_jewel(target) or target.attributes.get("data_sensitivity"))
        if not sensitive:
            continue
        if not _is_write_permission(edge.evidence):
            continue
        matches.append(
            ToxicMatch(
                entry=principal,
                node_ids=(principal.id, target.id),
                path=(RelationshipType.HAS_PERMISSION.value,),
                severities=(_node_severity(principal), _node_severity(target)),
                detail=(
                    f"{principal.label} holds admin/write permission to sensitive data store {target.label} "
                    "(standing over-permission to regulated/sensitive data)."
                ),
            )
        )
    return matches


def _match_agent_reaches_privileged(graph: UnifiedGraph) -> list[ToxicMatch]:
    """An AGENT that reaches a credential / privileged tool — the agentic-AI moat."""
    matches: list[ToxicMatch] = []
    privileged_rels = frozenset(
        {
            RelationshipType.EXPOSES_CRED,
            RelationshipType.REACHES_TOOL,
            RelationshipType.USES,
            RelationshipType.USED_CREDENTIAL,
        }
    )
    # Precompute the set of nodes that are the source of any privileged edge in
    # a single O(E) pass, instead of re-scanning every edge per agent (which is
    # O(agents x edges)). Membership-testing this set per agent is O(1) amortized.
    priv_sources = {e.source for e in graph.edges if e.relationship in privileged_rels}
    for agent in graph.nodes_by_type(EntityType.AGENT):
        reached = graph.reachable_from(agent.id, max_depth=6, include_source=False)
        cred_hits: list[str] = []
        for nid in reached:
            target = graph.nodes.get(nid)
            if target is None:
                continue
            if target.entity_type in (EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF):
                cred_hits.append(nid)
        if not cred_hits:
            continue
        # Require the reach to actually traverse a credential/tool relationship
        # (not merely co-membership), so the path is a real harvest chain.
        if agent.id not in priv_sources and priv_sources.isdisjoint(reached):
            continue
        ranked = sorted(set(cred_hits))
        node_ids = (agent.id, *ranked)
        sevs = (_node_severity(agent), *(_node_severity(graph.nodes[c]) for c in ranked if c in graph.nodes))
        matches.append(
            ToxicMatch(
                entry=agent,
                node_ids=node_ids,
                path=(RelationshipType.USES.value, RelationshipType.EXPOSES_CRED.value, RelationshipType.REACHES_TOOL.value),
                severities=sevs,
                detail=(
                    f"Agent {agent.label} can reach {len(ranked)} credential/privileged tool node(s) along its "
                    "tool-use chain (agentic credential-harvest exposure)."
                ),
            )
        )
    return matches


def _match_public_permission_lateral(graph: UnifiedGraph) -> list[ToxicMatch]:
    """Internet-exposed node with permission/assume edges enabling lateral movement."""
    matches: list[ToxicMatch] = []
    for node in graph.nodes.values():
        if not node.attributes.get("internet_exposed"):
            continue
        lateral_targets: list[str] = []
        path_rels: set[str] = set()
        for edge in graph.adjacency.get(node.id, []):
            if edge.relationship not in _LATERAL_RELS:
                continue
            target = graph.nodes.get(edge.target)
            if target is None or target.id == node.id:
                continue
            if target.entity_type in _LATERAL_TARGET_TYPES:
                lateral_targets.append(target.id)
                path_rels.add(edge.relationship.value)
        if not lateral_targets:
            continue
        ranked = sorted(set(lateral_targets))
        node_ids = (node.id, *ranked)
        sevs = (_node_severity(node), *(_node_severity(graph.nodes[t]) for t in ranked if t in graph.nodes))
        matches.append(
            ToxicMatch(
                entry=node,
                node_ids=node_ids,
                path=tuple(sorted(path_rels)),
                severities=sevs,
                detail=(
                    f"Internet-exposed {node.label} can assume / access {len(ranked)} other account/role node(s), "
                    "enabling lateral movement from a public foothold."
                ),
            )
        )
    return matches


# ── Rule registry (data-driven — add a 6th by appending one entry) ───────────

TOXIC_RULES: tuple[ToxicRule, ...] = (
    ToxicRule(
        id="PUBLIC_EXPOSED_KEV",
        title="Public, internet-exposed resource with a CISA KEV vulnerability",
        severity="critical",
        mitre=("T1190",),
        description=(
            "A resource reachable from the public internet carries a vulnerability "
            "listed in CISA Known Exploited Vulnerabilities. This is observed "
            "exploitation plus public reachability."
        ),
        remediation=(
            "Patch or remove the vulnerable component immediately and remove public "
            "exposure until remediation is verified."
        ),
        match=_match_public_exposed_kev,
        owasp_tags=("A06:2021",),
    ),
    ToxicRule(
        id="PUBLIC_EXPOSED_RCE",
        title="Public, internet-exposed resource with a CWE-backed RCE vulnerability",
        severity="critical",
        mitre=("T1190", "T1059"),
        description=(
            "A resource reachable from the public internet carries a vulnerability "
            "whose CWE/advisory metadata supports code execution."
        ),
        remediation=(
            "Patch the vulnerable component or remove the public path before leaving "
            "the workload in service."
        ),
        match=_match_public_exposed_rce,
        owasp_tags=("A06:2021",),
    ),
    ToxicRule(
        id="PUBLIC_EXPOSED_NETWORK_EXPLOITABLE",
        title="Public, internet-exposed resource with a CVSS AV:N vulnerability",
        severity="critical",
        mitre=("T1190",),
        description=(
            "A resource reachable from the public internet carries a vulnerability "
            "whose CVSS vector says the attack vector is network."
        ),
        remediation=(
            "Restrict the public network path or patch the network-exploitable "
            "component; prioritize when paired with low complexity or no privileges."
        ),
        match=_match_public_exposed_network_exploitable,
        owasp_tags=("A06:2021",),
    ),
    ToxicRule(
        id="PUBLIC_EXPOSED_VULNERABLE",
        title="Public, internet-exposed resource with a known vulnerability",
        severity="high",
        mitre=("T1190",),
        description=(
            "A resource reachable from the public internet also carries a known "
            "vulnerability. Internet reachability plus an exploitable flaw is the "
            "classic externally-exploitable kill-chain."
        ),
        remediation=(
            "Remove public exposure (restrict the security group / firewall / public "
            "access block) or patch the vulnerable component — ideally both."
        ),
        match=_match_public_exposed_vulnerable,
        owasp_tags=("A06:2021",),
    ),
    ToxicRule(
        id="PUBLIC_TO_SENSITIVE_DATA",
        title="Internet-exposed path to a sensitive data store",
        severity="high",
        mitre=("T1530",),
        description=(
            "An internet-exposed resource reaches a data store classified as holding "
            "sensitive / regulated data. A public foothold with a path to sensitive "
            "data is a direct data-exfiltration risk."
        ),
        remediation=(
            "Cut the public exposure on the path, or move the sensitive store behind a "
            "private network boundary and tighten its access policy."
        ),
        match=_match_public_to_sensitive_data,
        owasp_tags=("A01:2021",),
    ),
    ToxicRule(
        id="OVERPERMISSIONED_TO_SENSITIVE",
        title="Principal with admin/write permission to sensitive data",
        severity="high",
        mitre=("T1078",),
        description=(
            "A principal (user, role, service account, or agent identity) holds admin "
            "or write permission to a data store classified as sensitive. Standing "
            "over-permission to regulated data is a high-impact insider / takeover risk."
        ),
        remediation=(
            "Right-size the grant to read-only or scoped access, or remove it. Apply "
            "least-privilege and require just-in-time elevation for write access."
        ),
        match=_match_overpermissioned_to_sensitive,
        owasp_tags=("A01:2021",),
    ),
    ToxicRule(
        id="AGENT_REACHES_PRIVILEGED",
        title="AI agent can reach a credential or privileged tool",
        severity="high",
        mitre=("T1552",),
        description=(
            "An AI agent's tool-use chain reaches a credential or privileged tool node. "
            "A compromised or prompt-injected agent could harvest those credentials, "
            "turning a single agent into a lateral-movement pivot."
        ),
        remediation=(
            "Broker credentials through a short-lived token issuer instead of exposing "
            "them to the agent, and scope the agent's tools to the minimum required."
        ),
        match=_match_agent_reaches_privileged,
        owasp_tags=("LLM06:2025",),
    ),
    ToxicRule(
        id="PUBLIC_PERMISSION_LATERAL",
        title="Public foothold with lateral-movement permissions",
        severity="high",
        mitre=("T1078.004",),
        description=(
            "An internet-exposed node carries assume-role / cross-account / permission "
            "edges that let it move laterally to another account or role. A public entry "
            "point with lateral reach lets an attacker pivot deeper into the estate."
        ),
        remediation=(
            "Remove the public exposure or constrain the trust / assume-role policy so "
            "the exposed identity cannot pivot across accounts or roles."
        ),
        match=_match_public_permission_lateral,
        owasp_tags=("A01:2021",),
    ),
)


# ── Public API ───────────────────────────────────────────────────────────────


def build_toxic_combination_findings(graph: UnifiedGraph) -> list[Finding]:
    """Run every toxic-combination rule and return enforceable Findings.

    Pure, read-only, no network. Severity is escalated one tier above the worst
    participating component (capped at ``critical``). Deduped by
    ``(rule_id, sorted node-id set)``. Never raises into the builder.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    if not graph.nodes:
        return findings

    for rule in TOXIC_RULES:
        try:
            rule_matches = rule.match(graph)
        except Exception:  # noqa: BLE001 — a single bad rule must not kill the rest
            continue
        for m in rule_matches:
            dedupe = (rule.id, m.dedupe_key)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            findings.append(_finding_from_match(graph, rule, m))
    return findings


def _finding_from_match(graph: UnifiedGraph, rule: ToxicRule, match: ToxicMatch) -> Finding:
    severity = _escalate(match.severities, rule.severity)
    participating = [{"id": nid, "label": _label(graph, nid), "entity_type": _entity_type_of(graph, nid)} for nid in match.node_ids]
    evidence = {
        "rule_id": rule.id,
        "toxic_combination": rule.id,
        "node_ids": list(match.node_ids),
        "participating_nodes": participating,
        "relationship_path": list(match.path),
        "component_severities": list(match.severities),
        "escalated_severity": severity,
        "mitre_attack": list(rule.mitre),
        "detail": match.detail or rule.description,
        "source": _GRAPH_SOURCE,
    }
    return Finding(
        finding_type=FindingType.COMBINATION,
        source=FindingSource.GRAPH_ANALYSIS,
        asset=_asset_for(match.entry),
        severity=severity,
        title=f"{rule.title}: {match.entry.label}",
        description=f"{rule.description} {match.detail}".strip(),
        remediation_guidance=rule.remediation,
        attack_tags=list(rule.mitre),
        owasp_tags=list(rule.owasp_tags),
        evidence=evidence,
        risk_score=_SEVERITY_RISK.get(severity, 5.0),
        is_actionable=True,
        impact_category="toxic_combination",
        id=_combination_finding_id(rule.id, match.dedupe_key),
    )


def _entity_type_of(graph: UnifiedGraph, node_id: str) -> str:
    node = graph.nodes.get(node_id)
    if node is None:
        return ""
    return node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)


def _combination_finding_id(rule_id: str, dedupe_key: tuple[str, ...]) -> str:
    from agent_bom.finding import stable_id

    return stable_id("toxic_combination", rule_id, *dedupe_key)


def build_toxic_combination_findings_data(graph: UnifiedGraph) -> list[dict]:
    """Serializable form stored on the report at the graph-build call site.

    The report carries the dicts; :meth:`AIBOMReport.to_findings` rehydrates them
    into :class:`Finding` objects (mirrors the secret-scanner side-block pattern).
    """
    return [f.to_dict() for f in build_toxic_combination_findings(graph)]


__all__ = [
    "ToxicRule",
    "ToxicMatch",
    "TOXIC_RULES",
    "build_toxic_combination_findings",
    "build_toxic_combination_findings_data",
    "toxic_combination_findings_from_data",
]


def toxic_combination_findings_from_data(data: list[dict]) -> list[Finding]:
    """Rehydrate stored toxic-combination dicts into Findings for the unified stream."""
    findings: list[Finding] = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        finding = _finding_from_dict(item)
        if finding is not None:
            findings.append(finding)
    return findings


def _finding_from_dict(item: dict) -> Optional[Finding]:
    asset_data = item.get("asset") or {}
    asset = Asset(
        name=str(asset_data.get("name", "")),
        asset_type=str(asset_data.get("asset_type", "cloud_resource")),
        identifier=asset_data.get("identifier"),
        location=asset_data.get("location"),
    )
    try:
        finding_type = FindingType(item.get("finding_type", FindingType.COMBINATION.value))
    except ValueError:
        finding_type = FindingType.COMBINATION
    try:
        source = FindingSource(item.get("source", FindingSource.GRAPH_ANALYSIS.value))
    except ValueError:
        source = FindingSource.GRAPH_ANALYSIS
    return Finding(
        finding_type=finding_type,
        source=source,
        asset=asset,
        severity=str(item.get("severity", "high")),
        title=str(item.get("title", "")),
        description=str(item.get("description", "")),
        remediation_guidance=item.get("remediation_guidance"),
        attack_tags=list(item.get("attack_tags", []) or []),
        owasp_tags=list(item.get("owasp_tags", []) or []),
        evidence=item.get("evidence", {}) or {},
        risk_score=float(item.get("risk_score", 0.0) or 0.0),
        is_actionable=item.get("is_actionable"),
        impact_category=item.get("impact_category"),
        id=str(item.get("id", "")),
    )
