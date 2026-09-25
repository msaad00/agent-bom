import type { EnrichedVuln } from "@/lib/findings-view";

/**
 * Deep-link a finding into security-graph investigation using typed graph FKs
 * when present, falling back to CVE / package / agent query params.
 */
export function buildFindingInvestigationHref(
  vuln: Pick<
    EnrichedVuln,
    "id" | "node_id" | "finding_node_id" | "entity_type" | "packages" | "agents" | "finding_id" | "scan_id"
  >,
  options?: { scanId?: string | undefined },
): string {
  const params = new URLSearchParams({ lens: "attack-path" });
  const scanId = vuln.scan_id?.trim() || options?.scanId;
  if (scanId) params.set("scan", scanId);

  const nodeId = vuln.node_id?.trim();
  if (nodeId) params.set("node", nodeId);

  const findingNode = vuln.finding_node_id?.trim();
  if (findingNode && /^vuln:CVE-\d{4}-\d+/i.test(findingNode)) {
    params.set("cve", findingNode.slice("vuln:".length));
  } else if (/^CVE-\d{4}-\d+/i.test(vuln.id)) {
    params.set("cve", vuln.id);
  }

  const packageName = vuln.packages.find((name) => name && name !== "asset");
  if (packageName && (vuln.entity_type === "package" || !nodeId)) {
    params.set("package", packageName);
  }

  const agentName = vuln.agents[0];
  if (agentName) params.set("agent", agentName);

  if (vuln.finding_id) params.set("finding", vuln.finding_id);

  return `/security-graph?${params.toString()}`;
}

/** Exact asset context remains useful when no attack path links this occurrence. */
export function buildFindingAssetHref(focus: { nodeId: string; findingId: string; scanId?: string }): string {
  const params = new URLSearchParams({ lens: "lineage", investigate: "1", root: focus.nodeId, node: focus.nodeId });
  if (focus.scanId) params.set("scan", focus.scanId);
  if (focus.findingId) params.set("finding", focus.findingId);
  return `/security-graph?${params.toString()}`;
}
