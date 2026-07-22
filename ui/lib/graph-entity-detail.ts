/**
 * Shared helpers for the investigation entity drawer — merge API node detail
 * into LineageNodeData and resolve rubric fields (semantic layer, next action).
 */

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import type { GraphNodeDetailResponse } from "@/lib/api-types";
import { GRAPH_NODE_KIND_META } from "@/lib/graph-schema";
import { LINEAGE_NODE_GRAPH_KIND } from "@/lib/graph-utils";

const SEMANTIC_LAYER_LABELS: Record<string, string> = {
  user: "User / application",
  identity: "Identity",
  orchestration: "Orchestration",
  mcp_server: "MCP / runtime",
  tool: "MCP / tool",
  package: "Package / supply chain",
  asset: "Model / data asset",
  infra: "Infrastructure",
  finding: "Finding / governance",
  gateway: "Gateway / runtime boundary",
};

export function semanticLayerForNodeType(nodeType: LineageNodeType): {
  key: string;
  label: string;
} {
  const kind = LINEAGE_NODE_GRAPH_KIND[nodeType];
  const meta = kind ? GRAPH_NODE_KIND_META[kind] : null;
  const key = meta?.layer ?? "asset";
  return { key, label: SEMANTIC_LAYER_LABELS[key] ?? key.replaceAll("_", " ") };
}

export function nodeIdFromLineageData(data: LineageNodeData): string | null {
  const raw = data.attributes?.node_id;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

export function evidenceTierLabel(data: LineageNodeData): string {
  const attr = data.attributes?.evidence_tier;
  if (typeof attr === "string" && attr.length > 0) return attr.replaceAll("_", " ");
  if (data.runtimeEvidenceTier) return data.runtimeEvidenceTier.replaceAll("_", " ");
  if (data.evidenceTier) return data.evidenceTier.replaceAll("_", " ");
  return "unspecified";
}

export function mergeGraphNodeDetail(
  base: LineageNodeData,
  detail: GraphNodeDetailResponse,
): LineageNodeData {
  const mergedAttributes = {
    ...(base.attributes ?? {}),
    ...(detail.node.attributes ?? {}),
    node_id: detail.node.id,
  };
  return {
    ...base,
    entityType: String(detail.node.entity_type),
    status: String(detail.node.status ?? base.status ?? ""),
    riskScore: detail.node.risk_score ?? base.riskScore,
    severity: detail.node.severity || base.severity,
    firstSeen: detail.node.first_seen || base.firstSeen,
    lastSeen: detail.node.last_seen || base.lastSeen,
    dataSources: detail.node.data_sources?.length
      ? detail.node.data_sources
      : base.dataSources,
    complianceTags: detail.node.compliance_tags?.length
      ? detail.node.compliance_tags
      : base.complianceTags,
    attributes: mergedAttributes,
    neighborCount: detail.neighbors.length,
    sourceCount: detail.sources.length,
    incomingEdgeCount: detail.edges_in.length,
    outgoingEdgeCount: detail.edges_out.length,
    impactCount: detail.impact.affected_count,
    maxImpactDepth: detail.impact.max_depth_reached,
    impactByType: detail.impact.affected_by_type,
  };
}

export type InvestigationNextAction = {
  label: string;
  href: string;
};

/** Prefer remediation, then findings for the CVE/label, then lineage pin. */
export function resolveInvestigationNextAction(
  data: LineageNodeData,
  options?: { scanId?: string | undefined; remediationHref?: string | undefined },
): InvestigationNextAction {
  if (options?.remediationHref) {
    return { label: "Open remediation", href: options.remediationHref };
  }
  const scanQs = options?.scanId ? `scan=${encodeURIComponent(options.scanId)}&` : "";
  if (data.nodeType === "vulnerability") {
    return {
      label: "Review finding",
      href: `/vulnerabilities?${scanQs}q=${encodeURIComponent(data.label)}`,
    };
  }
  if (data.nodeType === "package") {
    return {
      label: "Review package findings",
      href: `/vulnerabilities?${scanQs}package=${encodeURIComponent(data.label)}`,
    };
  }
  const nodeId = nodeIdFromLineageData(data);
  if (nodeId && options?.scanId) {
    return {
      label: "Inspect in lineage",
      href: `/graph?scan=${encodeURIComponent(options.scanId)}&root=${encodeURIComponent(nodeId)}`,
    };
  }
  return { label: "Open remediation queue", href: "/remediation" };
}
