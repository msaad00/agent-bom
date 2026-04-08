"""Unified graph builder from serialized AIBOM report data.

This ingests the JSON contract emitted by ``output.json_fmt.to_json()``
and builds the core inventory, finding, runtime, and compliance entities
used for current-state views, traversal, attack paths, and temporal diffs.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.severity import SEVERITY_RISK_SCORE
from agent_bom.graph.types import EntityType, RelationshipType

try:
    from agent_bom.constants import is_credential_key as _is_credential_key
except ImportError:  # pragma: no cover

    def _is_credential_key(name: str) -> bool:
        low = name.lower()
        return any(p in low for p in ("key", "token", "secret", "password", "auth"))


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
    sid = scan_id or report_json.get("scan_id", "")
    graph = UnifiedGraph(scan_id=sid, tenant_id=tenant_id)

    agents_data = report_json.get("agents", [])
    blast_data = report_json.get("blast_radius", [])
    scan_sources = report_json.get("scan_sources", [])
    data_source_tag = scan_sources[0] if scan_sources else "mcp-scan"

    # Track shared resources for lateral movement edges
    server_to_agents: dict[str, list[str]] = defaultdict(list)
    cred_to_agents: dict[str, list[str]] = defaultdict(list)
    # Track package→server links for vuln edges
    pkg_key_to_servers: dict[str, list[str]] = defaultdict(list)

    # ── Agents → Servers → Packages → Tools → Credentials ───────────
    for agent_dict in agents_data:
        agent_name = agent_dict.get("name", "unknown")
        agent_id = f"agent:{agent_name}"
        agent_type = agent_dict.get("type", "")
        provider_name = str(agent_dict.get("source") or "local").strip() or "local"
        provider_id = f"provider:{provider_name}"

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
                },
                dimensions=NodeDimensions(agent_type=agent_type),
                data_sources=[data_source_tag],
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=provider_id,
                target=agent_id,
                relationship=RelationshipType.HOSTS,
            )
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
            graph.add_edge(
                UnifiedEdge(
                    source=agent_id,
                    target=srv_id,
                    relationship=RelationshipType.USES,
                )
            )
            server_to_agents[srv_name].append(agent_name)

            # ── Packages ──
            for pkg_dict in srv_dict.get("packages", []):
                pkg_name = pkg_dict.get("name", "unknown")
                pkg_version = pkg_dict.get("version", "")
                ecosystem = pkg_dict.get("ecosystem", "")
                pkg_id = f"pkg:{pkg_name}:{ecosystem}:{pkg_version}"

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
                graph.add_edge(
                    UnifiedEdge(
                        source=srv_id,
                        target=pkg_id,
                        relationship=RelationshipType.DEPENDS_ON,
                    )
                )
                pkg_key = f"{ecosystem}:{pkg_name}:{pkg_version}"
                pkg_key_to_servers[pkg_key].append(srv_id)

                # ── Package-level vulnerabilities ──
                for vuln_dict in pkg_dict.get("vulnerabilities", []):
                    _add_vuln_node(graph, vuln_dict, pkg_id, data_source_tag)

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
            pkg_id = f"pkg:{pkg_name}:{ecosystem}:{pkg_version}"
            if graph.has_node(pkg_id):
                graph.add_edge(
                    UnifiedEdge(
                        source=pkg_id,
                        target=vuln_node_id,
                        relationship=RelationshipType.VULNERABLE_TO,
                        weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
                    )
                )

        # Link affected servers → vulnerability
        for agent_name in br_dict.get("affected_agents", []):
            for srv_name in br_dict.get("affected_servers", []):
                srv_id = f"server:{agent_name}:{srv_name}"
                if graph.has_node(srv_id):
                    graph.add_edge(
                        UnifiedEdge(
                            source=srv_id,
                            target=vuln_node_id,
                            relationship=RelationshipType.VULNERABLE_TO,
                            weight=SEVERITY_RISK_SCORE.get(severity, 1.0),
                            evidence={"package": br_dict.get("package", "")},
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

    return graph


def _add_vuln_node(
    graph: UnifiedGraph,
    vuln_dict: dict[str, Any],
    pkg_id: str,
    data_source: str,
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
        )
    )


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
