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

  if (vuln.finding_id) {
    params.set("finding", vuln.finding_id);
    if (scanId) params.set("finding_scan", scanId);
  }

  return `/security-graph?${params.toString()}`;
}

/** Exact asset context remains useful when no attack path links this occurrence. */
export function buildFindingAssetHref(focus: { nodeId: string; findingId: string; scanId?: string; findingScanId?: string }): string {
  const params = new URLSearchParams({ lens: "lineage", investigate: "1", root: focus.nodeId, node: focus.nodeId });
  if (focus.scanId) params.set("scan", focus.scanId);
  if (focus.findingId) {
    params.set("finding", focus.findingId);
    if (focus.findingScanId || focus.scanId) params.set("finding_scan", focus.findingScanId || focus.scanId!);
  }
  return `/security-graph?${params.toString()}`;
}

/** Keep return provenance distinct from the graph's currently selected snapshot. */
export function withFindingContext(href: string, context: { get(name: string): string | null }): string {
  const finding = context.get("finding");
  const related = context.get("related_finding");
  if (!finding && !related) return href;
  const [pathname, query = ""] = href.split("?", 2);
  const params = new URLSearchParams(query);
  if (finding) params.set("finding", finding);
  else if (related) params.set("related_finding", related);
  const sourceScan = context.get("finding_scan") || context.get("scan");
  if (sourceScan) params.set("finding_scan", sourceScan);
  return `${pathname}?${params}`;
}

export function buildFindingReturnHref(context: { get(name: string): string | null }): string | null {
  const finding = context.get("finding") || context.get("related_finding");
  if (!finding) return null;
  const params = new URLSearchParams({ finding });
  const sourceScan = context.get("finding_scan") || context.get("scan");
  if (sourceScan) {
    params.set("scan", sourceScan);
    // An explicit historical snapshot must not disappear behind the default time window.
    params.set("window", "0");
  }
  return `/findings?${params}`;
}
