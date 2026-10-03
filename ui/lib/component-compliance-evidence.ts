import { FINDING_ENTITY_TYPES, type UnifiedEdge, type UnifiedNode } from "@/lib/graph-schema";

/** Mappings are not assessments. Only explicit checks on an affected entity carry a result. */
export function componentControlEvidence(assetId: string, nodes: UnifiedNode[], edges: UnifiedEdge[]) {
  const adjacent = new Set(edges.flatMap(edge => edge.source === assetId ? [edge.target] : edge.target === assetId ? [edge.source] : []));
  return nodes.filter(node => node.id === assetId || (adjacent.has(node.id)
    && [...FINDING_ENTITY_TYPES].some(type => type === node.entity_type)))
    .flatMap(node => {
      const attrs = node.attributes ?? {};
      const affected = edges.some(edge => edge.source === node.id && edge.target === assetId && edge.relationship === "affects");
      const failed = node.entity_type === "misconfiguration" && affected && typeof attrs.check_id === "string"
        && attrs.evaluation_status === "fail" && ["resource", "account"].includes(String(attrs.evaluation_scope));
      return [...new Set(node.compliance_tags ?? [])].sort().map(tag => ({
        tag, node, status: failed ? "recorded_fail" as const : "not_evaluated" as const,
        scope: failed ? String(attrs.evaluation_scope) : "mapping_only",
      }));
    }).sort((a, b) => a.tag.localeCompare(b.tag) || a.node.id.localeCompare(b.node.id));
}
