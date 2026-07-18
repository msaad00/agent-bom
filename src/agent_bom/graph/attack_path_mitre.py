"""Typed MITRE ATT&CK / ATLAS technique enrichment for attack paths (#4108).

Derives *potential* technique/tactic mappings for each hop of an
:class:`~agent_bom.graph.container.AttackPath` from the OBSERVED GRAPH EVIDENCE —
the hop's edge relationship type, the target node's entity type, and the edge's
evidence dict — never by parsing the human-readable ``summary`` / edge-label
text. A hop whose evidence maps to no known technique is left UNMAPPED
(fail-closed / honest): the kill-chain surfaces only the techniques the evidence
supports.

Every emitted ``technique_id`` and its ``tactics`` resolve against the bundled
catalogs (``mitre_fetch`` for ATT&CK, ``atlas_fetch`` for ATLAS) exactly like the
catalog-freshness tests validate — no dangling identifiers. Tactics are read from
the catalog, never hardcoded here.

Honesty: these are mapped/potential techniques for the kill-chain *sequence*, not
detections. Nothing in this module asserts observed attacker activity.
"""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, TechniqueMapping, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

# ── Evidence → technique rules ───────────────────────────────────────────────
#
# Each rule keys off the OBSERVED edge relationship (and, where the signal needs
# it, the target node's entity type or the edge evidence). ``catalog`` selects
# which bundled catalog validates the id and supplies its tactics.

_ATTACK = "attack"
_ATLAS = "atlas"

# Data-store targets — reaching a crown-jewel store is a "collection" signal.
_DATA_ACCESS_RELS = frozenset(
    {
        RelationshipType.STORES,
        RelationshipType.HAS_PERMISSION,
        RelationshipType.CAN_ACCESS,
        RelationshipType.ACCESSED,
    }
)
_VULN_RELS = frozenset({RelationshipType.VULNERABLE_TO, RelationshipType.EXPLOITABLE_VIA})
_CRED_RELS = frozenset({RelationshipType.EXPOSES_CRED})
_TOOL_RELS = frozenset({RelationshipType.REACHES_TOOL, RelationshipType.PROVIDES_TOOL})
_ASSUME_RELS = frozenset({RelationshipType.ASSUMES, RelationshipType.INHERITS})
_CRED_TYPES = frozenset({EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF})


def _resolve_hop(
    graph: UnifiedGraph,
    source_id: str,
    target_id: str,
    rel: RelationshipType,
) -> UnifiedEdge | None:
    """Return the observed edge object for this hop (carries edge evidence)."""
    for edge in graph.adjacency.get(source_id, []):
        if edge.target == target_id and edge.relationship == rel:
            return edge
    return None


def _candidate(
    rel: RelationshipType,
    source: UnifiedNode | None,
    target: UnifiedNode | None,
    edge: UnifiedEdge | None,
) -> tuple[str, str, float, str] | None:
    """Map one hop's observed evidence to ``(technique_id, catalog, confidence, provenance)``.

    Returns ``None`` when no evidence maps to a technique (the hop stays unmapped).
    Provenance is composed only from the relationship enum + node entity type +
    edge evidence — never from the path summary or human edge-label text.
    """
    target_type = target.entity_type if target is not None else None
    target_ref = target.id if target is not None else "?"
    prov_target = target_type.value if target_type is not None else "node"

    # Reaching a crown-jewel data store — Data from Cloud Storage (collection).
    if target_type == EntityType.DATA_STORE and rel in _DATA_ACCESS_RELS:
        return "T1530", _ATTACK, 0.7, f"observed {rel.value} edge into {prov_target} '{target_ref}'"

    # Exploiting a vulnerability. From an internet-exposed entry it maps to
    # Exploit Public-Facing Application; elsewhere to Exploitation for Priv Esc.
    if rel in _VULN_RELS or target_type == EntityType.VULNERABILITY:
        if source is not None and source.attributes.get("internet_exposed"):
            return "T1190", _ATTACK, 0.85, f"observed {rel.value} edge from internet-exposed entry into {prov_target} '{target_ref}'"
        return "T1068", _ATTACK, 0.8, f"observed {rel.value} edge into {prov_target} '{target_ref}'"

    # Harvesting exposed credentials — Unsecured Credentials (credential-access).
    if rel in _CRED_RELS or target_type in _CRED_TYPES:
        return "T1552", _ATTACK, 0.8, f"observed {rel.value} edge into {prov_target} '{target_ref}'"

    # Reaching an agent tool — ATLAS AI Agent Tool Invocation.
    if rel in _TOOL_RELS or target_type == EntityType.TOOL:
        return "AML.T0053", _ATLAS, 0.65, f"observed {rel.value} edge into {prov_target} '{target_ref}'"

    # Privilege escalation via an assume-chain effective permission.
    if rel == RelationshipType.HAS_PERMISSION and (edge is not None and (edge.evidence or {}).get("access") == "assume_chain"):
        return "T1548", _ATTACK, 0.75, f"observed {rel.value} edge (assume_chain) into {prov_target} '{target_ref}'"

    # Assuming a role / inheriting a principal — Valid Accounts.
    if rel in _ASSUME_RELS:
        return "T1078", _ATTACK, 0.7, f"observed {rel.value} edge into {prov_target} '{target_ref}'"

    # Internet exposure edge — Exploit Public-Facing Application (initial-access).
    if rel == RelationshipType.EXPOSED_TO:
        return "T1190", _ATTACK, 0.7, f"observed {rel.value} edge into {prov_target} '{target_ref}'"

    return None


def _attack_tactics(technique_id: str) -> list[str] | None:
    """Tactic phase names for an ATT&CK id, or ``None`` if not in the catalog."""
    from agent_bom.mitre_fetch import get_techniques

    meta = get_techniques().get(technique_id)
    if meta is None:
        return None
    return list(meta.get("tactics", []))


def _atlas_meta(technique_id: str) -> tuple[str, list[str]] | None:
    """``(name, tactic_ids)`` for a curated ATLAS id, or ``None`` if unknown."""
    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.atlas_fetch import get_techniques as atlas_techniques

    if technique_id not in ATLAS_TECHNIQUES:
        return None
    meta = atlas_techniques().get(technique_id, {})
    name = meta.get("name") or ATLAS_TECHNIQUES.get(technique_id, "")
    return name, list(meta.get("tactics", []))


def derive_attack_path_techniques(path: AttackPath, graph: UnifiedGraph) -> list[TechniqueMapping]:
    """Derive ordered, catalog-resolved technique mappings for ``path``.

    One mapping per hop that carries mappable evidence, in kill-chain order.
    Hops with no mappable evidence — or whose candidate technique does not
    resolve in the bundled catalog — are skipped (fail-closed). Never raises.
    """
    mappings: list[TechniqueMapping] = []
    edges = path.edges or []
    hops = path.hops or []
    for i, rel_value in enumerate(edges):
        if i + 1 >= len(hops):
            break
        try:
            rel = RelationshipType(rel_value)
        except ValueError:
            continue
        source = graph.nodes.get(hops[i])
        target = graph.nodes.get(hops[i + 1])
        edge = _resolve_hop(graph, hops[i], hops[i + 1], rel)
        candidate = _candidate(rel, source, target, edge)
        if candidate is None:
            continue
        technique_id, catalog, confidence, provenance = candidate
        if catalog == _ATLAS:
            resolved = _atlas_meta(technique_id)
            if resolved is None:
                continue  # dangling id — fail closed
            name, tactics = resolved
        else:
            tactics_or_none = _attack_tactics(technique_id)
            if tactics_or_none is None:
                continue  # dangling id — fail closed
            from agent_bom.mitre_attack import ATTACK_TECHNIQUES

            name = ATTACK_TECHNIQUES.get(technique_id, "")
            tactics = tactics_or_none
        mappings.append(
            TechniqueMapping(
                hop_index=i,
                technique_id=technique_id,
                technique_name=name,
                catalog=catalog,
                tactics=tactics,
                provenance=provenance,
                confidence=confidence,
            )
        )
    return mappings


def apply_attack_path_technique_mappings(graph: UnifiedGraph) -> int:
    """Populate ``technique_mappings`` on every attack path in ``graph``.

    Idempotent: recomputes from the current evidence each call. Returns the
    number of mappings materialised. Never raises into the builder.
    """
    total = 0
    for path in graph.attack_paths:
        path.technique_mappings = derive_attack_path_techniques(path, graph)
        total += len(path.technique_mappings)
    return total
