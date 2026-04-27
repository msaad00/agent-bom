"""Unified graph builder from serialized AIBOM report data.

This ingests the JSON contract emitted by ``output.json_fmt.to_json()``
and builds the core inventory, finding, runtime, and compliance entities
used for current-state views, traversal, attack paths, and temporal diffs.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePath
from typing import Any

from agent_bom.api.tracing import get_tracer
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.severity import SEVERITY_RISK_SCORE
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.package_utils import canonical_package_key, normalize_package_name

try:
    from agent_bom.constants import is_credential_key as _is_credential_key
except ImportError:  # pragma: no cover

    def _is_credential_key(name: str) -> bool:
        low = name.lower()
        return any(p in low for p in ("key", "token", "secret", "password", "auth"))


_GRAPH_TRACER = get_tracer("agent_bom.graph")


def build_unified_graph_from_report(
    report_json: dict[str, Any],
    *,
    scan_id: str = "",
    tenant_id: str = "",
) -> UnifiedGraph:
    """Build a UnifiedGraph from the persisted AIBOM report JSON contract.

    Args:
        report_json: The dict produced by ``output.json_fmt.to_json(report)``.
        scan_id: Scan identifier (defaults to report's scan_id).
        tenant_id: Multi-tenant isolation key.

    Returns:
        A fully populated :class:`UnifiedGraph`.
    """
    span = _GRAPH_TRACER.start_span("graph.build_unified_graph_from_report") if _GRAPH_TRACER else None
    sid = scan_id or report_json.get("scan_id", "")
    graph = UnifiedGraph(scan_id=sid, tenant_id=tenant_id)

    agents_data = report_json.get("agents", [])
    blast_data = report_json.get("blast_radius", report_json.get("blast_radii", []))
    scan_sources = report_json.get("scan_sources", [])
    data_source_tag = scan_sources[0] if scan_sources else "mcp-scan"

    # Track shared resources for lateral movement edges
    server_to_agents: dict[str, list[str]] = defaultdict(list)
    cred_to_agents: dict[str, list[str]] = defaultdict(list)
    # Track server/package indexes for vuln edges
    pkg_key_to_servers: dict[str, list[str]] = defaultdict(list)
    package_name_to_ids: dict[str, list[str]] = defaultdict(list)
    server_name_to_ids: dict[str, list[str]] = defaultdict(list)
    agent_name_to_ids: dict[str, list[str]] = defaultdict(list)
    server_name_to_agent_servers: dict[str, dict[str, str]] = defaultdict(dict)
    agent_to_server_ids: dict[str, set[str]] = defaultdict(set)
    agent_config_path_to_id: dict[str, str] = {}

    # ── Agents → Servers → Packages → Tools → Credentials ───────────
    for agent_dict in agents_data:
        agent_name = agent_dict.get("name", "unknown")
        agent_id = f"agent:{agent_name}"
        agent_type = agent_dict.get("type", agent_dict.get("agent_type", ""))
        provider_name = str(agent_dict.get("source") or "local").strip() or "local"
        provider_id = f"provider:{provider_name}"
        agent_metadata = agent_dict.get("metadata", {})
        if not isinstance(agent_metadata, dict):
            agent_metadata = {}

        graph.add_node(
            UnifiedNode(
                id=provider_id,
                entity_type=EntityType.PROVIDER,
                label=provider_name,
                attributes={"provider": provider_name},
                data_sources=[data_source_tag],
            )
        )

        graph.add_node(
            UnifiedNode(
                id=agent_id,
                entity_type=EntityType.AGENT,
                label=agent_name,
                attributes={
                    "agent_type": agent_type,
                    "status": agent_dict.get("status", ""),
                    "stable_id": agent_dict.get("stable_id", ""),
                    "config_path": agent_dict.get("config_path", ""),
                    "source": provider_name,
                    "server_count": len(agent_dict.get("mcp_servers", [])),
                    "cloud_origin": agent_metadata.get("cloud_origin"),
                    "cloud_state": agent_metadata.get("cloud_state"),
                    "cloud_scope": agent_metadata.get("cloud_scope"),
                    "cloud_principal": agent_metadata.get("cloud_principal"),
                },
                dimensions=NodeDimensions(agent_type=agent_type),
                data_sources=[data_source_tag],
            )
        )
        agent_name_to_ids[agent_name].append(agent_id)
        config_path = str(agent_dict.get("config_path", "") or "").strip()
        if config_path:
            agent_config_path_to_id[config_path] = agent_id
        graph.add_edge(
            UnifiedEdge(
                source=provider_id,
                target=agent_id,
                relationship=RelationshipType.HOSTS,
            )
        )
        _add_agent_cloud_lineage(
            graph,
            agent_id=agent_id,
            agent_dict=agent_dict,
            agent_metadata=agent_metadata,
            data_source=data_source_tag,
        )

        for srv_dict in agent_dict.get("mcp_servers", []):
            srv_name = srv_dict.get("name", "unknown")
            srv_id = f"server:{agent_name}:{srv_name}"
            surface = srv_dict.get("surface", "mcp-server")

            graph.add_node(
                UnifiedNode(
                    id=srv_id,
                    entity_type=EntityType.SERVER,
                    label=srv_name,
                    attributes={
                        "command": srv_dict.get("command", ""),
                        "transport": srv_dict.get("transport", ""),
                        "url": srv_dict.get("url", ""),
                        "auth_mode": srv_dict.get("auth_mode", ""),
                        "mcp_version": srv_dict.get("mcp_version", ""),
                        "has_credentials": srv_dict.get("has_credentials", False),
                        "security_blocked": srv_dict.get("security_blocked", False),
                        "agent": agent_name,
                        "stable_id": srv_dict.get("stable_id", ""),
                        "fingerprint": srv_dict.get("fingerprint", ""),
                    },
                    dimensions=NodeDimensions(surface=surface),
                    data_sources=[data_source_tag],
                )
            )
            server_name_to_ids[srv_name].append(srv_id)
            graph.add_edge(
                UnifiedEdge(
                    source=agent_id,
                    target=srv_id,
                    relationship=RelationshipType.USES,
                )
            )
            server_to_agents[srv_name].append(agent_name)
            server_name_to_agent_servers[srv_name][agent_name] = srv_id
            agent_to_server_ids[agent_name].add(srv_id)

            # ── Packages ──
            for pkg_dict in srv_dict.get("packages", []):
                pkg_name = pkg_dict.get("name", "unknown")
                pkg_version = pkg_dict.get("version", "")
                ecosystem = pkg_dict.get("ecosystem", "")
                pkg_id = _package_node_id(pkg_dict)
                package_evidence = _package_evidence(pkg_dict, data_source_tag)

                graph.add_node(
                    UnifiedNode(
                        id=pkg_id,
                        entity_type=EntityType.PACKAGE,
                        label=f"{pkg_name}@{pkg_version}" if pkg_version else pkg_name,
                        attributes={
                            "version": pkg_version,
                            "ecosystem": ecosystem,
                            "purl": pkg_dict.get("purl", ""),
                            "is_direct": pkg_dict.get("is_direct", True),
                            "parent_package": pkg_dict.get("parent_package", ""),
                            "dependency_depth": pkg_dict.get("dependency_depth", 0),
                            "license": pkg_dict.get("license", ""),
                            "scorecard_score": pkg_dict.get("scorecard_score"),
                            "is_malicious": pkg_dict.get("is_malicious", False),
                            "stable_id": pkg_dict.get("stable_id", ""),
                        },
                        dimensions=NodeDimensions(ecosystem=ecosystem),
                        data_sources=[data_source_tag],
                    )
                )
                package_name_to_ids[pkg_name].append(pkg_id)
                normalized_pkg_name = normalize_package_name(pkg_name, ecosystem)
                if normalized_pkg_name != pkg_name:
                    package_name_to_ids[normalized_pkg_name].append(pkg_id)
                graph.add_edge(
                    UnifiedEdge(
                        source=srv_id,
                        target=pkg_id,
                        relationship=RelationshipType.DEPENDS_ON,
                        evidence=package_evidence,
                    )
                )
                pkg_key = _package_graph_key(pkg_name, pkg_version, ecosystem, pkg_dict.get("purl"))
                pkg_key_to_servers[pkg_key].append(srv_id)

                # ── Package-level vulnerabilities ──
                for vuln_dict in pkg_dict.get("vulnerabilities", []):
                    _add_vuln_node(graph, vuln_dict, pkg_id, data_source_tag, package_evidence)

            # ── Tools ──
            for tool_dict in srv_dict.get("tools", []):
                tool_name = tool_dict.get("name", "unknown")
                tool_id = f"tool:{srv_id}:{tool_name}"
                graph.add_node(
                    UnifiedNode(
                        id=tool_id,
                        entity_type=EntityType.TOOL,
                        label=tool_name,
                        attributes={
                            "description": tool_dict.get("description", ""),
                            "stable_id": tool_dict.get("stable_id", ""),
                            "fingerprint": tool_dict.get("fingerprint", ""),
                            "risk_score": tool_dict.get("risk_score", 0),
                            "schema_findings": tool_dict.get("schema_findings", []),
                            "server": srv_id,
                            "agent": agent_name,
                        },
                        data_sources=[data_source_tag],
                    )
                )
                graph.add_edge(
                    UnifiedEdge(
                        source=srv_id,
                        target=tool_id,
                        relationship=RelationshipType.PROVIDES_TOOL,
                    )
                )

            # ── Credentials (from env keys) ──
            env_keys = srv_dict.get("credential_env_vars", [])
            if not env_keys:
                env_dict = srv_dict.get("env", {})
                if isinstance(env_dict, dict):
                    env_keys = [k for k in env_dict if _is_credential_key(k)]
            for env_key in env_keys:
                cred_id = f"cred:{env_key}"
                graph.add_node(
                    UnifiedNode(
                        id=cred_id,
                        entity_type=EntityType.CREDENTIAL,
                        label=env_key,
                        attributes={"servers": [srv_id]},
                        data_sources=[data_source_tag],
                    )
                )
                graph.add_edge(
                    UnifiedEdge(
                        source=srv_id,
                        target=cred_id,
                        relationship=RelationshipType.EXPOSES_CRED,
                        weight=2.0,
                    )
                )
                cred_to_agents[env_key].append(agent_name)

    # ── Blast radius vulnerabilities ─────────────────────────────────
    for br_dict in blast_data:
        vuln_id_str = br_dict.get("vulnerability_id", "")
        if not vuln_id_str:
            continue
        severity = br_dict.get("severity", "").lower()
        pkg_name = br_dict.get("package_name", br_dict.get("package", "").split("@")[0])
        pkg_version = br_dict.get("package_version", "")
        ecosystem = br_dict.get("ecosystem", "")

        # Add/merge vuln node (add_node unions compliance_tags if node exists)
        vuln_node_id = f"vuln:{vuln_id_str}"
        graph.add_node(
            UnifiedNode(
                id=vuln_node_id,
                entity_type=EntityType.VULNERABILITY,
                label=vuln_id_str,
                severity=severity,
                risk_score=br_dict.get("risk_score", 0),
                attributes={
                    "cvss_score": br_dict.get("cvss_score"),
                    "epss_score": br_dict.get("epss_score"),
                    "is_kev": br_dict.get("is_kev", False),
                    "fixed_version": br_dict.get("fixed_version"),
                    "impact_category": br_dict.get("impact_category", ""),
                    "reachability": br_dict.get("reachability", ""),
                },
                compliance_tags=_collect_compliance_tags(br_dict),
                data_sources=[data_source_tag],
            )
        )

        # Link package → vulnerability
        if pkg_name:
            pkg_id = _package_node_id_from_parts(pkg_name, pkg_version, ecosystem, br_dict.get("package_purl") or br_dict.get("purl"))
            if graph.has_node(pkg_id):
                graph.add_edge(
                    UnifiedEdge(
                        source=pkg_id,
                        target=vuln_node_id,
                        relationship=RelationshipType.VULNERABLE_TO,
                        weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
                        evidence=_blast_radius_package_evidence(br_dict, data_source_tag),
                    )
                )

        # Link affected servers → vulnerability using indexed lookups instead
        # of an agent×server cross-product scan.
        for srv_id in _resolve_affected_server_ids(
            br_dict,
            pkg_name=pkg_name,
            pkg_version=pkg_version,
            ecosystem=ecosystem,
            pkg_key_to_servers=pkg_key_to_servers,
            server_name_to_agent_servers=server_name_to_agent_servers,
            agent_to_server_ids=agent_to_server_ids,
        ):
            graph.add_edge(
                UnifiedEdge(
                    source=srv_id,
                    target=vuln_node_id,
                    relationship=RelationshipType.VULNERABLE_TO,
                    weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
                    evidence=_blast_radius_package_evidence(br_dict, data_source_tag),
                )
            )

    # ── Shared server edges (agent ↔ agent) ──────────────────────────
    for srv_name, agent_names in server_to_agents.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            for i, a1 in enumerate(unique):
                for a2 in unique[i + 1 :]:
                    graph.add_edge(
                        UnifiedEdge(
                            source=f"agent:{a1}",
                            target=f"agent:{a2}",
                            relationship=RelationshipType.SHARES_SERVER,
                            direction="bidirectional",
                            weight=3.0,
                            evidence={"server": srv_name},
                        )
                    )

    # ── Shared credential edges (agent ↔ agent) ─────────────────────
    for cred_name, agent_names in cred_to_agents.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            for i, a1 in enumerate(unique):
                for a2 in unique[i + 1 :]:
                    graph.add_edge(
                        UnifiedEdge(
                            source=f"agent:{a1}",
                            target=f"agent:{a2}",
                            relationship=RelationshipType.SHARES_CRED,
                            direction="bidirectional",
                            weight=4.0,
                            evidence={"credential": cred_name},
                        )
                    )

    # ── Model provenance ─────────────────────────────────────────────
    for model_dict in report_json.get("model_provenance", []):
        model_name = model_dict.get("model_name", model_dict.get("name", "unknown"))
        model_id = f"model:{model_name}"
        graph.add_node(
            UnifiedNode(
                id=model_id,
                entity_type=EntityType.MODEL,
                label=model_name,
                attributes={
                    "framework": model_dict.get("framework", ""),
                    "source": model_dict.get("source", ""),
                    "hash": model_dict.get("hash", ""),
                    "verified": model_dict.get("verified", False),
                },
                data_sources=["model-provenance"],
            )
        )

    # ── Dataset cards ────────────────────────────────────────────────
    dataset_cards = report_json.get("dataset_cards")
    if isinstance(dataset_cards, dict):
        for dataset_dict in dataset_cards.get("datasets", []):
            dataset_name = dataset_dict.get("name") or dataset_dict.get("source_file") or "unknown-dataset"
            graph.add_node(
                UnifiedNode(
                    id=f"dataset:{dataset_name}",
                    entity_type=EntityType.DATASET,
                    label=dataset_name,
                    attributes={
                        "description": dataset_dict.get("description", ""),
                        "license": dataset_dict.get("license", ""),
                        "source_url": dataset_dict.get("source_url", ""),
                        "version": dataset_dict.get("version", ""),
                        "features": dataset_dict.get("features", []),
                        "splits": dataset_dict.get("splits", {}),
                        "size_bytes": dataset_dict.get("size_bytes", 0),
                        "source_file": dataset_dict.get("source_file", ""),
                        "languages": dataset_dict.get("languages", []),
                        "task_categories": dataset_dict.get("task_categories", []),
                        "security_flags": dataset_dict.get("security_flags", []),
                    },
                    compliance_tags=_flatten_compliance_tags(dataset_dict.get("compliance_tags")),
                    data_sources=["dataset-cards"],
                )
            )

    # ── Serving configs / containers ────────────────────────────────
    for serving_dict in report_json.get("serving_configs", []):
        container_image = serving_dict.get("container_image", "")
        if not container_image:
            continue
        container_id = f"container:{container_image}"
        graph.add_node(
            UnifiedNode(
                id=container_id,
                entity_type=EntityType.CONTAINER,
                label=serving_dict.get("name") or container_image,
                attributes={
                    "container_image": container_image,
                    "framework": serving_dict.get("framework", ""),
                    "source_file": serving_dict.get("source_file", ""),
                    "model_uri": serving_dict.get("model_uri", ""),
                    "endpoint_url": serving_dict.get("endpoint_url", ""),
                    "security_flags": serving_dict.get("security_flags", []),
                },
                dimensions=NodeDimensions(surface="container"),
                data_sources=["training-pipeline"],
            )
        )
        model_id = _resolve_model_id(graph, serving_dict.get("model_uri", ""))
        if model_id:
            graph.add_edge(
                UnifiedEdge(
                    source=container_id,
                    target=model_id,
                    relationship=RelationshipType.SERVES_MODEL,
                )
            )

    # ── CIS benchmark misconfigurations ──────────────────────────────
    for section_key, legacy_key, cloud_provider in (
        ("cis_benchmark", "cis_benchmark_data", ""),
        ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data", "snowflake"),
        ("azure_cis_benchmark", "azure_cis_benchmark_data", "azure"),
        ("gcp_cis_benchmark", "gcp_cis_benchmark_data", "gcp"),
        ("databricks_cis_benchmark", "databricks_cis_benchmark_data", "databricks"),
    ):
        cis_data = report_json.get(section_key) or report_json.get(legacy_key)
        if not cis_data:
            continue
        checks = cis_data.get("checks", [])
        for check in checks:
            if str(check.get("status", "")).upper() != "FAIL":
                continue
            check_id = check.get("check_id", "unknown")
            misconfig_id = f"misconfig:{section_key}:{check_id}"
            resource_ids = list(check.get("resource_ids", []))
            graph.add_node(
                UnifiedNode(
                    id=misconfig_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=check.get("title", check_id),
                    severity=check.get("severity", "medium").lower(),
                    attributes={
                        "check_id": check_id,
                        "cis_section": check.get("cis_section", ""),
                        "evidence": check.get("evidence", ""),
                        "recommendation": check.get("recommendation", ""),
                        "resource_ids": resource_ids,
                        "cloud_provider": cloud_provider,
                    },
                    compliance_tags=[f"CIS-{check_id}"],
                    data_sources=[section_key],
                    dimensions=NodeDimensions(cloud_provider=cloud_provider),
                )
            )
            for resource_id in sorted(set(resource_ids)):
                resource_node_id = f"cloud_resource:{cloud_provider or 'generic'}:{resource_id}"
                graph.add_node(
                    UnifiedNode(
                        id=resource_node_id,
                        entity_type=EntityType.CLOUD_RESOURCE,
                        label=resource_id,
                        attributes={
                            "resource_id": resource_id,
                            "cloud_provider": cloud_provider,
                            "source_section": section_key,
                        },
                        data_sources=[section_key],
                        dimensions=NodeDimensions(cloud_provider=cloud_provider),
                    )
                )
                graph.add_edge(
                    UnifiedEdge(
                        source=misconfig_id,
                        target=resource_node_id,
                        relationship=RelationshipType.AFFECTS,
                    )
                )

    # ── SAST findings as misconfiguration nodes ──────────────────────
    sast_data = report_json.get("sast") or report_json.get("sast_data")
    if sast_data:
        for finding in sast_data.get("findings", []):
            rule_id = finding.get("rule_id", "unknown")
            finding_path = finding.get("file_path") or finding.get("path", "")
            finding_line = finding.get("start_line") or finding.get("line", 0)
            cwe_ids = list(finding.get("cwe_ids", []))
            owasp_ids = list(finding.get("owasp_ids", []))
            sast_id = f"misconfig:sast:{rule_id}:{finding_path}:{finding_line}"
            graph.add_node(
                UnifiedNode(
                    id=sast_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=finding.get("message", rule_id or "SAST finding"),
                    severity=finding.get("severity", "medium").lower(),
                    attributes={
                        "rule_id": rule_id,
                        "path": finding_path,
                        "file_path": finding_path,
                        "line": finding_line,
                        "start_line": finding.get("start_line", finding_line),
                        "end_line": finding.get("end_line", finding_line),
                        "cwe_ids": cwe_ids,
                        "owasp_ids": owasp_ids,
                        "rule_url": finding.get("rule_url", ""),
                    },
                    compliance_tags=sorted(set(cwe_ids + owasp_ids)),
                    data_sources=["sast"],
                )
            )

    # ── IaC findings as misconfiguration nodes ───────────────────────
    iac_data = report_json.get("iac_findings") or report_json.get("iac_findings_data")
    if iac_data:
        for finding in iac_data.get("findings", []):
            rule_id = finding.get("rule_id", "unknown")
            finding_path = finding.get("file_path", "") or "unknown"
            finding_line = finding.get("line_number", 0) or 0
            category = str(finding.get("category", "iac") or "iac").lower()
            compliance = list(finding.get("compliance", []))
            attack_techniques = list(finding.get("attack_techniques", []))
            remediation = finding.get("remediation", "")
            iac_id = f"misconfig:iac:{rule_id}:{finding_path}:{finding_line}"
            target_id = f"iac_target:{category}:{finding_path}"

            graph.add_node(
                UnifiedNode(
                    id=iac_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=finding.get("title", rule_id or "IaC finding"),
                    severity=finding.get("severity", "medium").lower(),
                    attributes={
                        "rule_id": rule_id,
                        "file_path": finding_path,
                        "line_number": finding_line,
                        "category": category,
                        "message": finding.get("message", ""),
                        "remediation": remediation,
                    },
                    compliance_tags=sorted(set(compliance + attack_techniques)),
                    data_sources=sorted(set(["iac", category])),
                )
            )
            graph.add_node(
                UnifiedNode(
                    id=target_id,
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=finding_path,
                    attributes={
                        "file_path": finding_path,
                        "category": category,
                        "target_type": "iac_file",
                    },
                    data_sources=sorted(set(["iac", category])),
                )
            )
            graph.add_edge(
                UnifiedEdge(
                    source=iac_id,
                    target=target_id,
                    relationship=RelationshipType.AFFECTS,
                )
            )

    # ── Skill-audit findings as misconfiguration nodes ──────────────
    skill_audit = report_json.get("skill_audit")
    if skill_audit:
        for index, finding in enumerate(skill_audit.get("findings", []), start=1):
            category = str(finding.get("category", "skill_audit") or "skill_audit").lower()
            package_name = str(finding.get("package", "") or "").strip()
            server_name = str(finding.get("server", "") or "").strip()
            source_file = str(finding.get("source_file", "") or "").strip()
            finding_id = f"misconfig:skill_audit:{category}:{index}"
            graph.add_node(
                UnifiedNode(
                    id=finding_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=str(finding.get("title", "") or category or "Skill audit finding"),
                    severity=str(finding.get("severity", "medium") or "medium").lower(),
                    attributes={
                        "category": category,
                        "detail": finding.get("detail", ""),
                        "source_file": source_file,
                        "package": package_name,
                        "server": server_name,
                        "recommendation": finding.get("recommendation", ""),
                        "context": finding.get("context", ""),
                        "ai_analysis": finding.get("ai_analysis"),
                        "ai_adjusted_severity": finding.get("ai_adjusted_severity"),
                    },
                    compliance_tags=[f"skill_audit:{category}"],
                    data_sources=["skill-audit"],
                )
            )
            for target_id in _resolve_skill_audit_target_ids(
                finding,
                package_name_to_ids=package_name_to_ids,
                server_name_to_ids=server_name_to_ids,
                agent_name_to_ids=agent_name_to_ids,
                agent_config_path_to_id=agent_config_path_to_id,
            ):
                graph.add_edge(
                    UnifiedEdge(
                        source=finding_id,
                        target=target_id,
                        relationship=RelationshipType.AFFECTS,
                    )
                )

    # ── Framework-native static topology (CrewAI / LangGraph / AutoGen) ──
    ai_inventory = report_json.get("ai_inventory", {})
    if isinstance(ai_inventory, dict):
        _add_framework_topology(graph, ai_inventory.get("framework_agents", []), data_source_tag)

    # ── Cross-environment correlation (#1892 Phase 1: AWS Bedrock) ──
    _add_cross_env_correlation(graph, agents_data, data_source_tag)

    # ── Runtime session graph (dynamic edges) ──────────────────────
    runtime_graph = report_json.get("runtime_session_graph")
    if runtime_graph:
        for edge_dict in runtime_graph.get("edges", []):
            rel_str = edge_dict.get("interaction_type", edge_dict.get("relation", ""))
            rel_map = {
                "tool_call": RelationshipType.INVOKED,
                "invoked": RelationshipType.INVOKED,
                "resource_access": RelationshipType.ACCESSED,
                "accessed": RelationshipType.ACCESSED,
                "delegation": RelationshipType.DELEGATED_TO,
                "delegated_to": RelationshipType.DELEGATED_TO,
            }
            rel = rel_map.get(rel_str.lower())
            if not rel:
                continue
            src = edge_dict.get("source_node_id", edge_dict.get("source", ""))
            tgt = edge_dict.get("target_node_id", edge_dict.get("target", ""))
            if src and tgt:
                graph.add_edge(
                    UnifiedEdge(
                        source=src,
                        target=tgt,
                        relationship=rel,
                        evidence={
                            "timestamp": edge_dict.get("timestamp", ""),
                            "tool_capability": edge_dict.get("tool_capability", ""),
                            "risk_score": edge_dict.get("risk_score", 0),
                            "data_source": "runtime-proxy",
                        },
                    )
                )

    # ── Toxic combinations as TRIGGERS edges ─────────────────────────
    toxic_data = report_json.get("toxic_combinations")
    if toxic_data:
        for combo in toxic_data if isinstance(toxic_data, list) else toxic_data.get("combinations", []):
            combo_vulns = combo.get("vulnerability_ids", combo.get("vulns", []))
            combo_label = combo.get("name", combo.get("label", "toxic_combo"))
            toxic_node_id = f"toxic:{combo_label}"
            graph.add_node(
                UnifiedNode(
                    id=toxic_node_id,
                    entity_type=EntityType.MISCONFIGURATION,
                    label=combo_label,
                    risk_score=float(combo.get("risk_score", 0) or 0),
                    attributes={
                        "combo": combo_label,
                        "risk_score": combo.get("risk_score", 0),
                        "vulnerability_ids": combo_vulns,
                    },
                    data_sources=["toxic-combinations"],
                )
            )
            for vuln_id in combo_vulns:
                vuln_node_id = f"vuln:{vuln_id}"
                if graph.has_node(vuln_node_id):
                    graph.add_edge(
                        UnifiedEdge(
                            source=vuln_node_id,
                            target=toxic_node_id,
                            relationship=RelationshipType.TRIGGERS,
                            evidence={"combo": combo_label, "risk": combo.get("risk_score", 0)},
                        )
                    )

    # ── Enrich vulnerability nodes with blast radius stats ───────────
    for br_dict in blast_data:
        vuln_id_str = br_dict.get("vulnerability_id", "")
        vuln_node = graph.get_node(f"vuln:{vuln_id_str}") if vuln_id_str else None
        if vuln_node:
            vuln_node.attributes["affected_agent_count"] = len(br_dict.get("affected_agents", []))
            vuln_node.attributes["affected_server_count"] = len(br_dict.get("affected_servers", []))
            vuln_node.attributes["exposed_credential_count"] = len(br_dict.get("exposed_credentials", []))
            vuln_node.attributes["exposed_tool_count"] = len(br_dict.get("exposed_tools", []))
            vuln_node.attributes["reachability"] = br_dict.get("reachability", "")
            vuln_node.attributes["actionable"] = br_dict.get("actionable", False)

    if span is not None:
        span.set_attribute("agent_bom.graph.scan_id", sid)
        span.set_attribute("agent_bom.graph.tenant_id", tenant_id or "default")
        span.set_attribute("agent_bom.graph.agent_count", len(agents_data))
        span.set_attribute("agent_bom.graph.blast_radius_count", len(blast_data))
        span.set_attribute("agent_bom.graph.node_count", len(graph.nodes))
        span.set_attribute("agent_bom.graph.edge_count", len(graph.edges))
        span.end()
    return graph


def _add_vuln_node(
    graph: UnifiedGraph,
    vuln_dict: dict[str, Any],
    pkg_id: str,
    data_source: str,
    package_evidence: dict[str, Any] | None = None,
) -> None:
    """Add a vulnerability node and link it to its package."""
    vuln_id_str = vuln_dict.get("id", "")
    if not vuln_id_str:
        return
    severity = vuln_dict.get("severity", "").lower()
    vuln_node_id = f"vuln:{vuln_id_str}"

    graph.add_node(
        UnifiedNode(
            id=vuln_node_id,
            entity_type=EntityType.VULNERABILITY,
            label=vuln_id_str,
            severity=severity,
            attributes={
                "cvss_score": vuln_dict.get("cvss_score"),
                "epss_score": vuln_dict.get("epss_score"),
                "is_kev": vuln_dict.get("is_kev", False),
                "fixed_version": vuln_dict.get("fixed_version"),
                "cwe_ids": vuln_dict.get("cwe_ids", []),
            },
            data_sources=[data_source],
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=pkg_id,
            target=vuln_node_id,
            relationship=RelationshipType.VULNERABLE_TO,
            weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
            evidence=package_evidence or {"source": data_source},
        )
    )


def _normalize_server_name(raw: Any) -> str:
    """Return a comparable server name from string or object payloads."""
    if isinstance(raw, dict):
        return str(raw.get("name", "")).strip()
    name = getattr(raw, "name", raw)
    return str(name).strip()


def _resolve_affected_server_ids(
    br_dict: dict[str, Any],
    *,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    pkg_key_to_servers: dict[str, list[str]],
    server_name_to_agent_servers: dict[str, dict[str, str]],
    agent_to_server_ids: dict[str, set[str]],
) -> list[str]:
    """Resolve the concrete server node IDs touched by a blast-radius finding.

    Preference order:
    1. package-host servers from the inventory graph
    2. explicit affected server names
    3. explicit affected agent names

    Each additional hint narrows the candidate set instead of creating a
    synthetic agent×server cross-product.
    """
    candidate_ids: set[str] = set()
    if pkg_name:
        pkg_key = _package_graph_key(pkg_name, pkg_version, ecosystem, br_dict.get("package_purl") or br_dict.get("purl"))
        candidate_ids.update(pkg_key_to_servers.get(pkg_key, []))

    server_names = {name for name in (_normalize_server_name(server) for server in br_dict.get("affected_servers", [])) if name}
    if server_names:
        named_ids: set[str] = set()
        for server_name in server_names:
            named_ids.update(server_name_to_agent_servers.get(server_name, {}).values())
        candidate_ids = (candidate_ids & named_ids) if candidate_ids else named_ids

    agent_names = {str(agent).strip() for agent in br_dict.get("affected_agents", []) if str(agent).strip()}
    if agent_names:
        agent_ids: set[str] = set()
        for agent_name in agent_names:
            agent_ids.update(agent_to_server_ids.get(agent_name, set()))
        candidate_ids = (candidate_ids & agent_ids) if candidate_ids else agent_ids

    return sorted(candidate_ids)


def _package_graph_key(name: str, version: str, ecosystem: str, purl: str | None = None) -> str:
    return canonical_package_key(name, version, ecosystem, purl)


def _package_node_id(pkg_dict: dict[str, Any]) -> str:
    return _package_node_id_from_parts(
        str(pkg_dict.get("name", "unknown") or "unknown"),
        str(pkg_dict.get("version", "") or ""),
        str(pkg_dict.get("ecosystem", "") or ""),
        pkg_dict.get("purl"),
    )


def _package_node_id_from_parts(name: str, version: str, ecosystem: str, purl: str | None = None) -> str:
    return f"pkg:{_package_graph_key(name, version, ecosystem, purl)}"


def _package_evidence(pkg_dict: dict[str, Any], data_source_tag: str) -> dict[str, Any]:
    """Build bounded provenance evidence for package graph edges."""
    occurrences = pkg_dict.get("occurrences", [])
    if not isinstance(occurrences, list):
        occurrences = []
    normalized_occurrences: list[dict[str, Any]] = []
    for occurrence in occurrences[:10]:
        if not isinstance(occurrence, dict):
            continue
        item = {
            key: occurrence.get(key)
            for key in (
                "layer_index",
                "layer_id",
                "layer_path",
                "package_path",
                "created_by",
                "dockerfile_instruction",
                "source_file",
                "line",
                "parser",
            )
            if occurrence.get(key) not in (None, "")
        }
        if item:
            normalized_occurrences.append(item)

    evidence = {
        "source": data_source_tag,
        "package": pkg_dict.get("name", ""),
        "version": pkg_dict.get("version", ""),
        "ecosystem": pkg_dict.get("ecosystem", ""),
        "purl": pkg_dict.get("purl", ""),
        "stable_id": pkg_dict.get("stable_id", ""),
        "source_package": pkg_dict.get("source_package", ""),
        "version_source": pkg_dict.get("version_source", ""),
        "occurrence_count": pkg_dict.get("occurrence_count", len(occurrences)),
        "occurrences": normalized_occurrences,
    }
    introduced = pkg_dict.get("introduced_in_layer")
    if isinstance(introduced, dict):
        evidence["introduced_in_layer"] = {
            key: introduced.get(key)
            for key in ("layer_index", "layer_id", "layer_path", "package_path", "created_by", "dockerfile_instruction")
            if introduced.get(key) not in (None, "")
        }
    return {key: value for key, value in evidence.items() if value not in (None, "", [])}


def _blast_radius_package_evidence(br_dict: dict[str, Any], data_source_tag: str) -> dict[str, Any]:
    evidence = {
        "source": data_source_tag,
        "package": br_dict.get("package", ""),
        "package_name": br_dict.get("package_name", ""),
        "package_version": br_dict.get("package_version", ""),
        "package_stable_id": br_dict.get("package_stable_id", ""),
        "purl": br_dict.get("package_purl") or br_dict.get("purl", ""),
        "reachability": br_dict.get("reachability", ""),
    }
    return {key: value for key, value in evidence.items() if value not in (None, "", [])}


def _collect_compliance_tags(br_dict: dict[str, Any]) -> list[str]:
    """Collect all compliance tags from a blast radius dict."""
    tags: list[str] = []
    for key in (
        "owasp_tags",
        "atlas_tags",
        "attack_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
    ):
        tags.extend(br_dict.get(key, []))
    return sorted(set(tags))


def _add_agent_cloud_lineage(
    graph: UnifiedGraph,
    *,
    agent_id: str,
    agent_dict: dict[str, Any],
    agent_metadata: dict[str, Any],
    data_source: str,
) -> None:
    """Promote normalized cloud-origin metadata into explicit lineage nodes.

    Cloud providers already normalize runtime identity into ``agent.metadata``.
    The graph should carry that as inventory too, otherwise cloud-discovered
    agents remain disconnected from provider/runtime assets.
    """
    origin = agent_metadata.get("cloud_origin")
    if not isinstance(origin, dict):
        return

    provider = _clean_graph_part(origin.get("provider")) or _clean_graph_part(agent_dict.get("source")) or "cloud"
    service = _clean_graph_part(origin.get("service")) or "unknown-service"
    resource_type = _clean_graph_part(origin.get("resource_type")) or "resource"
    resource_id = _clean_graph_part(origin.get("resource_id")) or _clean_graph_part(origin.get("resource_name"))
    if not resource_id:
        return

    resource_name = _clean_graph_part(origin.get("resource_name")) or resource_id
    location = _clean_graph_part(origin.get("location"))
    cloud_provider_id = f"provider:{provider}"
    resource_node_id = f"cloud_resource:{provider}:{service}:{resource_type}:{resource_id}"
    data_sources = sorted({data_source, str(agent_dict.get("source") or "").strip(), f"cloud:{provider}"} - {""})

    graph.add_node(
        UnifiedNode(
            id=cloud_provider_id,
            entity_type=EntityType.PROVIDER,
            label=provider,
            attributes={"provider": provider, "source": "cloud_origin"},
            data_sources=data_sources,
        )
    )
    graph.add_node(
        UnifiedNode(
            id=resource_node_id,
            entity_type=EntityType.CLOUD_RESOURCE,
            label=resource_name,
            attributes={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
                "cloud_provider": provider,
                "cloud_service": service,
                "location": location,
                "scope": origin.get("scope", {}),
                "cloud_origin": origin,
                "cloud_state": agent_metadata.get("cloud_state"),
                "cloud_scope": agent_metadata.get("cloud_scope"),
                "cloud_timestamps": agent_metadata.get("cloud_timestamps"),
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface=service),
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=cloud_provider_id,
            target=resource_node_id,
            relationship=RelationshipType.HOSTS,
            evidence={"source": "cloud_origin", "provider": provider, "service": service},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=resource_node_id,
            target=agent_id,
            relationship=RelationshipType.HOSTS,
            evidence={"source": "cloud_origin", "resource_id": resource_id},
        )
    )

    principal = agent_metadata.get("cloud_principal")
    if not isinstance(principal, dict):
        return
    principal_id = _clean_graph_part(principal.get("principal_id")) or _clean_graph_part(principal.get("principal_name"))
    if not principal_id:
        return
    principal_name = _clean_graph_part(principal.get("principal_name")) or principal_id
    principal_node_id = f"service_account:{provider}:{principal_id}"
    graph.add_node(
        UnifiedNode(
            id=principal_node_id,
            entity_type=EntityType.SERVICE_ACCOUNT,
            label=principal_name,
            attributes={
                "principal_id": principal_id,
                "principal_name": principal_name,
                "principal_type": principal.get("principal_type", ""),
                "tenant_id": principal.get("tenant_id", ""),
                "source_field": principal.get("source_field", ""),
                "cloud_provider": provider,
                "cloud_service": service,
                "cloud_principal": principal,
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=principal_node_id,
            target=resource_node_id,
            relationship=RelationshipType.MANAGES,
            evidence={"source": "cloud_principal", "principal_type": principal.get("principal_type", "")},
        )
    )
    # Direct principal → agent edge so single-hop "which principals can
    # reach this agent?" queries don't have to traverse the intermediate
    # cloud_resource node. The intermediate edges (principal → resource,
    # resource → agent) above stay so the lineage is fully reconstructable.
    # `via` records that the relationship is mediated by a cloud_resource
    # so consumers can distinguish direct ownership from cloud-mediated
    # operation when they need to.
    graph.add_edge(
        UnifiedEdge(
            source=principal_node_id,
            target=agent_id,
            relationship=RelationshipType.MANAGES,
            evidence={
                "source": "cloud_principal",
                "principal_type": principal.get("principal_type", ""),
                "via": resource_node_id,
            },
        )
    )


def _add_cross_env_correlation(
    graph: UnifiedGraph,
    agents_data: Any,
    data_source: str,
) -> None:
    """Emit local↔cloud correlation edges across all configured providers.

    The strict-bar matcher in :mod:`agent_bom.cross_env_correlation` decides
    whether each candidate qualifies for ``CORRELATES_WITH`` (HIGH-confidence
    triplet match) or only ``POSSIBLY_CORRELATES_WITH`` (single-signal). Both
    relationships carry the matched signals and rationale so reviewers can see
    why the platform drew the line.
    """
    from agent_bom.cross_env_correlation import (
        CorrelationConfidence,
        correlate_cross_environment,
    )

    if not isinstance(agents_data, list):
        return
    result = correlate_cross_environment(agents_data)
    if not result.matches:
        return

    for match in result.matches:
        local_id = f"agent:{match.local_agent_name}"
        cloud_id = f"agent:{match.cloud_agent_name}"
        # Only wire edges between agents we already added as nodes — the
        # matcher operates over the report payload but the graph may have
        # filtered some agents out earlier.
        if not graph.get_node(local_id) or not graph.get_node(cloud_id):
            continue
        relationship = (
            RelationshipType.CORRELATES_WITH
            if match.confidence is CorrelationConfidence.HIGH
            else RelationshipType.POSSIBLY_CORRELATES_WITH
        )
        graph.add_edge(
            UnifiedEdge(
                source=local_id,
                target=cloud_id,
                relationship=relationship,
                evidence={
                    "data_source": data_source,
                    "confidence": match.confidence.value,
                    "matched_signals": list(match.matched_signals),
                    "cloud_provider": match.cloud_provider,
                    "cloud_service": match.cloud_service,
                    "cloud_account_id": match.cloud_account_id or "",
                    "cloud_region": match.cloud_region or "",
                    "cloud_model_id": match.cloud_model_id or "",
                    "rationale": match.rationale,
                },
            )
        )


def _add_framework_topology(graph: UnifiedGraph, framework_agents: Any, data_source: str) -> None:
    """Add static framework-native agent nodes and topology edges."""
    if not isinstance(framework_agents, list):
        return
    known_agent_ids: set[str] = set()
    for item in framework_agents:
        if not isinstance(item, dict):
            continue
        agent_id = str(item.get("stable_id") or "").strip()
        if not agent_id:
            continue
        known_agent_ids.add(agent_id)
        graph.add_node(
            UnifiedNode(
                id=agent_id,
                entity_type=EntityType.AGENT,
                label=str(item.get("name") or agent_id),
                attributes={
                    "agent_type": "framework-agent",
                    "framework": item.get("framework", ""),
                    "file_path": item.get("file_path", ""),
                    "line_number": item.get("line_number", 0),
                    "confidence": item.get("confidence", ""),
                    "model_refs": item.get("model_refs", []),
                    "credential_refs": item.get("credential_refs", []),
                    "capabilities": item.get("capabilities", []),
                    "dynamic_edges": item.get("dynamic_edges", False),
                },
                dimensions=NodeDimensions(agent_type="framework-agent", surface=str(item.get("framework", ""))),
                data_sources=[data_source, "source-ast"],
            )
        )

    for item in framework_agents:
        if not isinstance(item, dict):
            continue
        for edge in item.get("topology_edges", []):
            if not isinstance(edge, dict):
                continue
            source_id = str(edge.get("source_id") or "").strip()
            target_id = str(edge.get("target_id") or "").strip()
            if not source_id or not target_id:
                continue
            for node_id, node_name in ((source_id, edge.get("source_name")), (target_id, edge.get("target_name"))):
                if node_id in known_agent_ids or graph.has_node(node_id):
                    continue
                graph.add_node(
                    UnifiedNode(
                        id=node_id,
                        entity_type=EntityType.AGENT,
                        label=str(node_name or node_id),
                        attributes={
                            "agent_type": "framework-agent",
                            "framework": edge.get("framework", ""),
                            "synthetic_from_topology_edge": True,
                        },
                        dimensions=NodeDimensions(agent_type="framework-agent", surface=str(edge.get("framework", ""))),
                        data_sources=[data_source, "source-ast"],
                    )
                )
                known_agent_ids.add(node_id)
            try:
                relationship = RelationshipType(str(edge.get("relationship") or "delegated_to"))
            except ValueError:
                continue
            graph.add_edge(
                UnifiedEdge(
                    source=source_id,
                    target=target_id,
                    relationship=relationship,
                    evidence={
                        "source": "source-ast",
                        "framework": edge.get("framework", ""),
                        "file_path": edge.get("file_path", ""),
                        "line_number": edge.get("line_number", 0),
                        "confidence": edge.get("confidence", ""),
                        "evidence": edge.get("evidence", ""),
                    },
                )
            )


def _clean_graph_part(value: Any) -> str:
    return str(value or "").strip()


def _flatten_compliance_tags(raw: Any) -> list[str]:
    """Normalize arbitrary compliance-tag payloads into a simple list."""
    if not raw:
        return []
    if isinstance(raw, list):
        return sorted({str(tag) for tag in raw if tag})
    if isinstance(raw, dict):
        tags: set[str] = set()
        for value in raw.values():
            if isinstance(value, list):
                tags.update(str(tag) for tag in value if tag)
            elif value:
                tags.add(str(value))
        return sorted(tags)
    return [str(raw)]


def _resolve_model_id(graph: UnifiedGraph, model_uri: str) -> str:
    """Best-effort link from a serving config model URI to a known model node."""
    if not model_uri:
        return ""
    candidates = [part for part in model_uri.replace("://", "/").replace(":", "/").split("/") if part]
    for candidate in reversed(candidates):
        model_id = f"model:{candidate}"
        if graph.has_node(model_id):
            return model_id
    return ""


def _resolve_skill_audit_target_ids(
    finding: dict[str, Any],
    *,
    package_name_to_ids: dict[str, list[str]],
    server_name_to_ids: dict[str, list[str]],
    agent_name_to_ids: dict[str, list[str]],
    agent_config_path_to_id: dict[str, str],
) -> list[str]:
    """Resolve graph target IDs for a serialized skill-audit finding."""
    target_ids: set[str] = set()

    package_name = str(finding.get("package", "") or "").strip()
    if package_name:
        target_ids.update(package_name_to_ids.get(package_name, []))

    server_name = str(finding.get("server", "") or "").strip()
    if server_name:
        target_ids.update(server_name_to_ids.get(server_name, []))

    source_file = str(finding.get("source_file", "") or "").strip()
    if source_file:
        if source_file in agent_config_path_to_id:
            target_ids.add(agent_config_path_to_id[source_file])
        source_name = PurePath(source_file).name
        for config_path, agent_id in agent_config_path_to_id.items():
            if source_name and source_name == PurePath(config_path).name:
                target_ids.add(agent_id)

    if not target_ids and len(agent_name_to_ids) == 1:
        only_agent_ids = next(iter(agent_name_to_ids.values()))
        target_ids.update(only_agent_ids)

    return sorted(target_ids)
