import type { ExposurePath } from "@/lib/exposure-path";
import { INVESTIGATION_NODE_LIMIT } from "@/lib/graph-neighbor-expansion";

/** Export the selected bounded evidence, never fetch an entire estate. */
export function investigationExport(path: ExposurePath, scanId: string, route: string) {
  const [pathname, query = ""] = route.split("?", 2);
  const supplied = new URLSearchParams(query);
  const shared = new URLSearchParams();
  for (const key of ["scan", "lens", "selected_path", "path_view", "finding", "cve", "package", "agent", "node", "step", "question"]) {
    const value = supplied.get(key);
    if (value) shared.set(key, value);
  }
  const sharedRoute = `${pathname}${shared.size ? `?${shared}` : ""}`;
  const hops = path.hops.slice(0, INVESTIGATION_NODE_LIMIT);
  const ids = new Set(hops.map(hop => hop.id));
  const relationships = path.relationships.filter(rel => ids.has(rel.source) && ids.has(rel.target));
  const hopEvidence = path.hopEvidence?.filter(receipt => ids.has(receipt.source_node_id) && ids.has(receipt.target_node_id));
  return {
    schema_version: "investigation.export.v1",
    scope: { scan_id: scanId, route: sharedRoute, kind: scanId.startsWith("current-estate:") ? "current_estate_generation" : "retained_snapshot" },
    coverage: { exported_nodes: hops.length, supplied_nodes: path.hops.length, truncated: hops.length < path.hops.length, estate_complete: false },
    semantics: "Recorded permissions, observed activity and conditional impact are separate evidence. A connection does not establish exploitation or successful access.",
    path: { ...path, hops, nodeIds: hops.map(hop => hop.id), relationships, edgeIds: relationships.map(rel => rel.id), hopEvidence },
  };
}
