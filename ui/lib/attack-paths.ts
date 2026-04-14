import { EntityType, type AttackPath, type UnifiedNode } from "./graph-schema";

export type AttackPathCardNode = {
  type: "cve" | "package" | "server" | "agent" | "credential";
  label: string;
  severity?: string;
};

export type AttackPathFocus = {
  cve?: string;
  packageName?: string;
  agentName?: string;
  scanId?: string;
};

export function attackPathKey(path: AttackPath): string {
  return `${path.source}::${path.target}::${path.hops.join("->")}`;
}

export function mapAttackPathNodeType(entityType: string): AttackPathCardNode["type"] | null {
  switch (entityType) {
    case EntityType.VULNERABILITY:
    case EntityType.MISCONFIGURATION:
      return "cve";
    case EntityType.PACKAGE:
      return "package";
    case EntityType.SERVER:
    case EntityType.CONTAINER:
    case EntityType.CLOUD_RESOURCE:
      return "server";
    case EntityType.AGENT:
    case EntityType.USER:
    case EntityType.GROUP:
    case EntityType.SERVICE_ACCOUNT:
      return "agent";
    case EntityType.CREDENTIAL:
      return "credential";
    default:
      return null;
  }
}

export function toAttackCardNodes(path: AttackPath, nodeById: Map<string, UnifiedNode>): AttackPathCardNode[] {
  const nodes: AttackPathCardNode[] = [];
  for (const hop of path.hops) {
    const node = nodeById.get(hop);
    if (!node) continue;
    const type = mapAttackPathNodeType(String(node.entity_type));
    if (!type) continue;
    nodes.push({
      type,
      label: node.label,
      severity: node.severity,
    });
  }
  return nodes;
}

export function buildSecurityGraphHref(focus: AttackPathFocus): string {
  const params = new URLSearchParams();
  if (focus.scanId) params.set("scan", focus.scanId);
  if (focus.cve) params.set("cve", focus.cve);
  if (focus.packageName) params.set("package", focus.packageName);
  if (focus.agentName) params.set("agent", focus.agentName);
  const query = params.toString();
  return query ? `/security-graph?${query}` : "/security-graph";
}

function normalizeLabel(value: string | undefined): string {
  return (value ?? "").trim().toLowerCase();
}

function pathNodeLabels(path: AttackPath, nodeById: Map<string, UnifiedNode>) {
  return path.hops
    .map((hop) => nodeById.get(hop))
    .filter((node): node is UnifiedNode => Boolean(node))
    .map((node) => ({
      label: normalizeLabel(node.label),
      type: mapAttackPathNodeType(String(node.entity_type)),
    }));
}

export function matchesAttackPathFocus(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
  focus: AttackPathFocus,
): boolean {
  const cve = normalizeLabel(focus.cve);
  const packageName = normalizeLabel(focus.packageName);
  const agentName = normalizeLabel(focus.agentName);
  if (!cve && !packageName && !agentName) return false;

  const labels = pathNodeLabels(path, nodeById);

  if (cve) {
    const inPathVulns = path.vuln_ids.some((id) => normalizeLabel(id) === cve);
    const inHopLabels = labels.some((node) => node.type === "cve" && node.label === cve);
    if (!inPathVulns && !inHopLabels) return false;
  }

  if (packageName && !labels.some((node) => node.type === "package" && node.label === packageName)) {
    return false;
  }

  if (agentName && !labels.some((node) => node.type === "agent" && node.label === agentName)) {
    return false;
  }

  return true;
}
