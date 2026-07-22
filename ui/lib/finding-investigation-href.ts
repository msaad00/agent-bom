import type { EnrichedVuln } from "@/lib/findings-view";

/**
 * Deep-link a finding into security-graph investigation using typed graph FKs
 * when present, falling back to CVE / package / agent query params.
 */
export function buildFindingInvestigationHref(
  vuln: Pick<
    EnrichedVuln,
    "id" | "node_id" | "finding_node_id" | "entity_type" | "packages" | "agents" | "finding_id"
  >,
  options?: { scanId?: string | undefined },
): string {
  const params = new URLSearchParams();
  if (options?.scanId) params.set("scan", options.scanId);

  const nodeId = vuln.node_id?.trim();
  if (nodeId) params.set("node", nodeId);

  const findingNode = vuln.finding_node_id?.trim();
  if (findingNode?.startsWith("vuln:")) {
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

  const query = params.toString();
  return query ? `/security-graph?${query}` : "/security-graph";
}
