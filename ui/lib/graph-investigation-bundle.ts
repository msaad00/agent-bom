import type { GraphIncidentPage } from "@/lib/api-types";
import { FINDING_ENTITY_TYPES } from "@/lib/graph-schema";

/** Export only the selected, generation-consistent relationship pages already read. */
export function buildGraphInvestigationBundle(scanId: string, nodeId: string, pages: GraphIncidentPage[], sourceUrl: string) {
  const generation = pages[0]?.snapshot_generation;
  if (!generation || !pages.length || pages.some(page => !page.found || page.scan_id !== scanId
    || page.node_id !== nodeId || page.direction !== "both" || page.snapshot_generation !== generation)) {
    throw new Error("Load consistent recorded relationships before exporting.");
  }
  const nodes = [...new Map(pages.flatMap(page => page.node ? [page.node, ...page.nodes] : page.nodes).map(node => [node.id, node])).values()];
  const edges = [...new Map(pages.flatMap(page => page.edges).map(edge => [JSON.stringify([edge.source, edge.target, edge.relationship]), edge])).values()];
  const nodeIds = new Set(nodes.map(node => node.id));
  const source = new URL(sourceUrl);
  const params = new URLSearchParams({ lens: "lineage", investigate: "1", scan: scanId, root: nodeId, node: nodeId });
  const findingId = source.searchParams.get("finding") || source.searchParams.get("related_finding");
  const findingScanId = findingId ? source.searchParams.get("finding_scan") || scanId : null;
  if (findingId) { params.set("finding", findingId); params.set("finding_scan", findingScanId!); }
  const returnUrl = new URL(`/security-graph?${params}`, source.origin);
  return {
    schema_version: "agent-bom.graph-investigation.v1",
    exported_at: new Date().toISOString(),
    selection: { scan_id: scanId, snapshot_generation: generation, node_id: nodeId,
      finding_node_ids: nodes.filter(node => [...FINDING_ENTITY_TYPES].some(type => type === node.entity_type)).map(node => node.id),
      finding_context: findingId ? { finding_id: findingId, scan_id: findingScanId } : null },
    return_url: returnUrl.href,
    scope: { kind: "loaded_incident_relationships", direction: "both", pages: pages.length,
      node_count: nodes.length, relationship_count: edges.length,
      more_relationships_available: Boolean(pages.at(-1)?.next_cursor),
      missing_endpoint_ids: [...new Set(edges.flatMap(edge => [edge.source, edge.target]).filter(id => !nodeIds.has(id)))],
      collection_coverage: "unknown" },
    sources: [...new Set(nodes.flatMap(node => node.data_sources ?? []))].sort(),
    nodes, relationships: edges,
    page_receipts: pages.map(page => ({ scan_id: page.scan_id, snapshot_generation: page.snapshot_generation,
      node_id: page.node_id, completeness: page.completeness, has_more: Boolean(page.next_cursor) })),
    limitations: [
      "This bundle contains loaded recorded relationships, not the complete snapshot or collection coverage.",
      "Recorded relationships do not establish execution, exploitation, or successful data access.",
      "This is an unsigned local export of API evidence, not independent attestation.",
      "The return link requires access to the original control plane and retained snapshot. A replaced snapshot may have a different generation.",
    ],
  };
}

export function downloadGraphInvestigation(bundle: ReturnType<typeof buildGraphInvestigationBundle>) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2) + "\n"], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "agent-bom-graph-investigation.json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
