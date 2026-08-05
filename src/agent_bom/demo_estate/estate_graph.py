"""Project the enterprise demo estate into the unified graph.

:mod:`agent_bom.demo_estate.enterprise_composition` inventories 2,068 assets and
:mod:`agent_bom.demo_estate.enterprise_findings` raises 439 findings on 407 of
them, but that evidence reached only the demo story endpoint. The graph a
prospect actually clicks was seeded independently from a 112-node hand-built
showcase, so "one correlated graph at enterprise scale" rested on the 112.

This module closes the gap. Three decisions carry the weight:

**One id scheme.** A projected asset's graph node id *is* its estate
``asset_id`` — the same string ``Finding.asset.identifier`` carries, the same
string a correlation's ``asset_path`` walks, the same string an observation's
``resource_ids`` names. Translating it here would be the split identity #4637
removed for live cloud scans, re-created inside the demo. The grouping nodes the
estate does not inventory (accounts, environments) use the graph builder's own
identity-node spellings — ``account:<provider>:<id>``,
``env:<provider>:<account>:<environment>`` — so an account discovered by a live
scan and the same account in the estate are one node, not two.

**Findings land on the inventoried asset.** Every misconfiguration node is
``AFFECTS``-linked to a node that already exists because the estate inventoried
it; a finding never materialises its own stub target. The node carries the
``Finding.id`` it was projected from, so the findings list and the graph join on
an identifier rather than on a label heuristic.

**The hierarchy is the readable view.** Assets hang off
org → account → environment via ``CONTAINS``, which is the only structure
:mod:`agent_bom.graph.rollup` can collapse. Without it a 2,000-node estate
renders as a hairball at any framerate.

Nothing here invents severity or exposure: a node's severity is the worst
severity of the findings actually raised against it, and an asset with no
finding stays unrated rather than being quietly coloured.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from agent_bom.demo_estate.enterprise import EnterpriseEstate, EstateAsset
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.severity import SEVERITY_RISK_SCORE, normalize_severity
from agent_bom.graph.types import EntityType, RelationshipType

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.demo_estate.enterprise_correlation import EnterpriseCorrelation
    from agent_bom.finding import Finding

ESTATE_GRAPH_VERSION = "estate_graph.v1"

# Data source stamped on every projected node/edge so a demo estate can always
# be told apart from a real scan in the same graph.
ESTATE_DATA_SOURCE = "demo-estate"

# The estate resource type that *is* the organization, lifted out of the
# account/environment hierarchy because it is the hierarchy's root.
_ORG_RESOURCE_TYPE = "organization"

# Estate resource type → graph entity type. Deliberately explicit rather than a
# heuristic: an unmapped type falls back to CLOUD_RESOURCE, which the canvas
# renders, instead of an ad-hoc string the canvas would silently drop (#4640).
_RESOURCE_ENTITY_TYPES: dict[str, EntityType] = {
    # Identities — the principal half of every correlated finding.
    "iam_role": EntityType.ROLE,
    "role": EntityType.ROLE,
    "service_account": EntityType.SERVICE_ACCOUNT,
    "service_principal": EntityType.SERVICE_PRINCIPAL,
    # Data surfaces — what an attack path is trying to reach.
    "bucket": EntityType.DATA_STORE,
    "storage_account": EntityType.DATA_STORE,
    "database": EntityType.DATA_STORE,
    "sql_database": EntityType.DATA_STORE,
    "table": EntityType.DATA_STORE,
    "stage": EntityType.DATA_STORE,
    "share": EntityType.DATA_STORE,
    # Compute / platform.
    "instance": EntityType.CLOUD_RESOURCE,
    "virtual_machine": EntityType.CLOUD_RESOURCE,
    "function": EntityType.CLOUD_RESOURCE,
    "function_app": EntityType.CLOUD_RESOURCE,
    "warehouse": EntityType.CLOUD_RESOURCE,
    "key_vault": EntityType.CLOUD_RESOURCE,
    "cluster": EntityType.CLUSTER,
    "deployment": EntityType.CONTAINER,
    "container_image": EntityType.CONTAINER,
    # Code / CI.
    "repository": EntityType.APPLICATION,
    "workflow": EntityType.CI_JOB,
    # AI estate.
    "hosted_model": EntityType.MODEL,
    "model_artifact": EntityType.MODEL,
    "server": EntityType.SERVER,
    "tool": EntityType.TOOL,
}

_DEFAULT_ENTITY_TYPE = EntityType.CLOUD_RESOURCE

# Which provider names an account scope when several report assets into it. An
# EKS cluster and the S3 buckets beside it share one AWS account number, so
# keying the account node on ``(provider, scope)`` verbatim would split one
# account into two. Preference order is fixed so the choice is deterministic and
# the cloud that owns the billing boundary always wins.
_ACCOUNT_PROVIDER_PREFERENCE: tuple[str, ...] = (
    "aws",
    "azure",
    "gcp",
    "snowflake",
    "kubernetes",
    "github",
    "mcp",
    "openai",
    "anthropic",
    "huggingface",
    "enterprise",
)

# Correlation kinds whose asset path is a real multi-hop chain worth drawing.
# A single-asset correlation has no path to draw.
_MIN_CHAIN_HOPS = 2


def estate_org_node_id(estate: EnterpriseEstate) -> str:
    """The estate's organization asset id — the containment root."""
    for asset in estate.assets:
        if asset.resource_type == _ORG_RESOURCE_TYPE:
            return asset.asset_id
    return f"organization:{estate.estate_id}"


def _account_providers(estate: EnterpriseEstate) -> dict[str, str]:
    """Map every account scope to the one provider that names its node."""
    seen: dict[str, set[str]] = {}
    for asset in estate.assets:
        if asset.resource_type == _ORG_RESOURCE_TYPE:
            continue
        seen.setdefault(asset.account_scope, set()).add(asset.provider)
    resolved: dict[str, str] = {}
    for scope, providers in seen.items():
        for candidate in _ACCOUNT_PROVIDER_PREFERENCE:
            if candidate in providers:
                resolved[scope] = candidate
                break
        else:
            resolved[scope] = sorted(providers)[0]
    return resolved


def estate_account_node_id(estate: EnterpriseEstate, account_scope: str) -> str:
    """Graph node id for an account scope, in the builder's own spelling."""
    provider = _account_providers(estate).get(account_scope, "cloud")
    return f"account:{provider}:{account_scope}"


def estate_environment_node_id(estate: EnterpriseEstate, account_scope: str, environment: str) -> str:
    """Graph node id for one environment inside one account."""
    provider = _account_providers(estate).get(account_scope, "cloud")
    return f"env:{provider}:{account_scope}:{environment}"


def entity_type_for_resource_type(resource_type: str) -> EntityType:
    """Map an estate resource type onto a canvas-renderable entity type."""
    return _RESOURCE_ENTITY_TYPES.get(resource_type, _DEFAULT_ENTITY_TYPE)


def _compliance_tags(asset: EstateAsset) -> list[str]:
    return sorted({classification.upper() for classification in asset.data_classifications})


def _asset_node(asset: EstateAsset, estate: EnterpriseEstate) -> UnifiedNode:
    """An inventory node, deliberately unrated.

    Severity belongs to the finding, not to the thing it was raised against —
    which is also what the live graph builder does for cloud resources. Copying
    the worst finding's severity onto the asset would make the roll-up histogram
    count the same risk twice and stop it reconciling with
    ``summarize_estate_findings``.
    """
    return UnifiedNode(
        id=asset.asset_id,
        entity_type=entity_type_for_resource_type(asset.resource_type),
        label=asset.display_name,
        attributes={
            "asset_id": asset.asset_id,
            "native_id": asset.native_id,
            "resource_id": asset.native_id,
            "resource_name": asset.display_name,
            "resource_type": asset.resource_type,
            "cloud_provider": asset.provider,
            "account_id": asset.account_scope,
            "account_scope": asset.account_scope,
            "region": asset.region,
            "environment": asset.environment,
            "owner": asset.owner,
            "cost_center": asset.cost_center,
            "data_classifications": list(asset.data_classifications),
            "tags": dict(asset.tags),
            "synthetic": True,
            "fictional": True,
            "estate_id": estate.estate_id,
        },
        compliance_tags=_compliance_tags(asset),
        data_sources=[ESTATE_DATA_SOURCE],
        dimensions=NodeDimensions(
            cloud_provider=asset.provider,
            environment=asset.environment,
            surface=asset.resource_type,
        ),
    )


def _finding_node_id(finding: Finding) -> str:
    return f"misconfig:demo-estate:{finding.id}"


def project_estate_into_graph(
    graph: UnifiedGraph,
    estate: EnterpriseEstate,
    *,
    findings: Sequence[Finding] = (),
    correlations: Sequence[EnterpriseCorrelation] = (),
) -> dict[str, object]:
    """Project ``estate`` — inventory, posture, identity and incident chain — into ``graph``.

    Returns the shape it produced so a caller (the demo bootstrap, a test, the
    surfaces gate) can assert on it instead of re-counting the graph.

    The graph is *extended*, never cleared: ``UnifiedGraph.add_node`` merges by
    id, so an id the caller already seeded keeps its attributes and gains the
    estate's. That is what lets the hand-built showcase chain and the estate
    occupy one snapshot.
    """
    org_id = estate_org_node_id(estate)
    account_providers = _account_providers(estate)

    org_asset = next((a for a in estate.assets if a.asset_id == org_id), None)
    graph.add_node(
        UnifiedNode(
            id=org_id,
            entity_type=EntityType.ORG,
            label=org_asset.display_name if org_asset is not None else estate.display_name,
            attributes={
                "org_id": org_asset.native_id if org_asset is not None else estate.estate_id,
                "estate_id": estate.estate_id,
                "synthetic": True,
                "fictional": True,
                "disclosure": estate.disclosure,
            },
            data_sources=[ESTATE_DATA_SOURCE],
        )
    )

    def _edge(source: str, target: str, relationship: RelationshipType, **kwargs: object) -> None:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, **kwargs))  # type: ignore[arg-type]

    accounts: set[str] = set()
    environments: set[str] = set()
    for asset in estate.assets:
        if asset.asset_id == org_id:
            continue
        provider = account_providers[asset.account_scope]
        account_id = f"account:{provider}:{asset.account_scope}"
        env_id = f"env:{provider}:{asset.account_scope}:{asset.environment}"

        if account_id not in accounts:
            accounts.add(account_id)
            graph.add_node(
                UnifiedNode(
                    id=account_id,
                    entity_type=EntityType.ACCOUNT,
                    label=asset.account_scope,
                    attributes={
                        "account_id": asset.account_scope,
                        "cloud_provider": provider,
                        "estate_id": estate.estate_id,
                        "synthetic": True,
                    },
                    data_sources=[ESTATE_DATA_SOURCE],
                    dimensions=NodeDimensions(cloud_provider=provider),
                )
            )
            _edge(org_id, account_id, RelationshipType.CONTAINS)

        if env_id not in environments:
            environments.add(env_id)
            graph.add_node(
                UnifiedNode(
                    id=env_id,
                    entity_type=EntityType.ENVIRONMENT,
                    label=asset.environment,
                    attributes={
                        "environment": asset.environment,
                        "account_id": asset.account_scope,
                        "cloud_provider": provider,
                        "estate_id": estate.estate_id,
                        "synthetic": True,
                    },
                    data_sources=[ESTATE_DATA_SOURCE],
                    dimensions=NodeDimensions(cloud_provider=provider, environment=asset.environment),
                )
            )
            _edge(account_id, env_id, RelationshipType.CONTAINS)

        graph.add_node(_asset_node(asset, estate))
        _edge(env_id, asset.asset_id, RelationshipType.CONTAINS)

    finding_count = 0
    identity_edges = 0
    known_assets = {asset.asset_id for asset in estate.assets}
    # Worst finding risk per asset. The asset node itself stays unrated (see
    # ``_asset_node``), so this is the only place the posture on a hop is
    # available to score a chain.
    risk_by_asset: dict[str, float] = {}
    for finding in findings:
        asset_id = finding.asset.identifier or ""
        if asset_id not in known_assets:
            # A finding whose asset was never inventoried would need a stub
            # target, which is precisely the split identity this module exists
            # to avoid. ``enterprise_findings`` guarantees this never happens;
            # skipping rather than fabricating keeps that guarantee testable.
            continue
        severity = normalize_severity(finding.severity)
        risk = SEVERITY_RISK_SCORE.get(severity, 0.0)
        risk_by_asset[asset_id] = max(risk_by_asset.get(asset_id, 0.0), risk)
        node_id = _finding_node_id(finding)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.MISCONFIGURATION,
                label=finding.title,
                severity=severity,
                risk_score=SEVERITY_RISK_SCORE.get(severity, 0.0),
                attributes={
                    "finding_id": finding.id,
                    "canonical_finding_id": finding.canonical_id,
                    "finding_type": finding.finding_type.value,
                    "check_id": str(finding.evidence.get("control_id") or ""),
                    "cloud_provider": finding.provider or "",
                    "resource_ids": [asset_id],
                    # The prose, not the structured advisory. ``Finding.remediation``
                    # is a ``Remediation`` dataclass; the graph store persists
                    # attributes with ``json.dumps(..., default=str)``, so putting
                    # it here did not fail — it froze the object's Python ``repr``
                    # into the snapshot and served it as the node's remediation
                    # text. ``remediation_guidance`` is the plain string the live
                    # cloud builder already puts under this key.
                    "recommendation": finding.remediation_guidance or "",
                    "configuration": finding.evidence.get("configuration") or {},
                    "synthetic": True,
                    "estate_id": estate.estate_id,
                },
                compliance_tags=[f"{tag.framework}:{tag.control}" for tag in finding.normalized_controls()],
                data_sources=[ESTATE_DATA_SOURCE],
                dimensions=NodeDimensions(
                    cloud_provider=finding.provider or "",
                    environment=finding.environment or "",
                ),
            )
        )
        # Two edges, two jobs. AFFECTS is the correlation the rest of the
        # product reads (it is what the live builder emits for a CIS
        # misconfiguration, and what attack-path fusion and the CNAPP overlay
        # traverse). CONTAINS is what the roll-up walks: without it 439 findings
        # sit outside the containment tree, blow past the 200-orphan cap, and the
        # default estate view degrades into a truncated chip list instead of
        # account → environment → resource → finding.
        _edge(node_id, asset_id, RelationshipType.AFFECTS)
        _edge(asset_id, node_id, RelationshipType.CONTAINS)
        finding_count += 1

        principal = str(finding.evidence.get("identity_asset_id") or "")
        if principal and principal in known_assets and principal != asset_id:
            _edge(
                principal,
                asset_id,
                RelationshipType.CAN_ACCESS,
                evidence={"reason": "estate_posture_finding", "finding_id": finding.id},
            )
            identity_edges += 1

    chain_edges, paths = _project_incident_chains(graph, correlations, known_assets, risk_by_asset)

    return {
        "version": ESTATE_GRAPH_VERSION,
        "estate_id": estate.estate_id,
        "assets": len(estate.assets),
        "accounts": len(accounts),
        "environments": len(environments),
        "findings": finding_count,
        "identity_edges": identity_edges,
        "chain_edges": chain_edges,
        "attack_paths": paths,
    }


def _project_incident_chains(
    graph: UnifiedGraph,
    correlations: Sequence[EnterpriseCorrelation],
    known_assets: set[str],
    risk_by_asset: dict[str, float],
) -> tuple[int, int]:
    """Draw every multi-hop correlated chain as consecutive traversable edges.

    ``ACCESSED`` is the runtime relationship: each hop is a step the estate's own
    audit evidence recorded, not an inferred network reachability claim.
    """
    chain_edges = 0
    paths = 0
    # ``UnifiedGraph.add_node``/``add_edge`` dedupe by identity, but
    # ``attack_paths`` is a plain list: re-projecting onto the same graph
    # appended a second copy of every chain, which double-counts on the
    # exposure-path queue and in ``stats.attack_path_count``.
    existing_paths = {tuple(path.hops) for path in graph.attack_paths}
    for correlation in sorted(correlations, key=lambda c: c.correlation_id):
        hops = [asset_id for asset_id in correlation.asset_path if asset_id in known_assets]
        if len(hops) < _MIN_CHAIN_HOPS or tuple(hops) in existing_paths:
            continue
        existing_paths.add(tuple(hops))
        edge_ids: list[str] = []
        for source, target in zip(hops, hops[1:], strict=False):
            graph.add_edge(
                UnifiedEdge(
                    source=source,
                    target=target,
                    relationship=RelationshipType.ACCESSED,
                    evidence={
                        "correlation_id": correlation.correlation_id,
                        "correlation_kind": correlation.kind,
                        "evidence_quality": correlation.evidence_quality,
                    },
                    provenance={"source": ESTATE_DATA_SOURCE, "trace_id": correlation.trace_id},
                )
            )
            edge_ids.append(f"{RelationshipType.ACCESSED.value}:{source}:{target}")
            chain_edges += 1
        graph.attack_paths.append(
            AttackPath(
                source=hops[0],
                target=hops[-1],
                hops=list(hops),
                edges=edge_ids,
                composite_risk=_chain_risk(graph, hops, risk_by_asset),
                summary=(
                    f"{correlation.kind.replace('_', ' ')} correlated across "
                    f"{len(hops)} assets from {len(correlation.sources)} evidence source(s)"
                ),
            )
        )
        paths += 1
    return chain_edges, paths


def _chain_risk(graph: UnifiedGraph, hops: Sequence[str], risk_by_asset: dict[str, float]) -> float:
    """Worst risk anywhere on the chain — from the hops' findings, not the hops.

    Inventory nodes are deliberately unrated, so scoring a chain from
    ``node.risk_score`` alone always returned 0.0 and sorted the estate's own
    incident below every hand-built path in the exposure-path queue.
    """
    worst = 0.0
    for hop in hops:
        worst = max(worst, risk_by_asset.get(hop, 0.0))
        node = graph.nodes.get(hop)
        if node is not None:
            worst = max(worst, float(node.risk_score or 0.0))
    return worst


__all__ = [
    "ESTATE_DATA_SOURCE",
    "ESTATE_GRAPH_VERSION",
    "entity_type_for_resource_type",
    "estate_account_node_id",
    "estate_environment_node_id",
    "estate_org_node_id",
    "project_estate_into_graph",
]
