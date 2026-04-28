import { EntityType, type AttackPath, type UnifiedNode } from "./graph-schema";

export type AttackPathCardNode = {
  type: "cve" | "package" | "server" | "agent" | "credential";
  label: string;
  severity?: string | undefined;
};

export type AttackPathFocus = {
  cve?: string | undefined;
  packageName?: string | undefined;
  agentName?: string | undefined;
  scanId?: string | undefined;
};

export type AttackPathAction = {
  title: string;
  detail: string;
  href: string;
};

export type InteractionRiskLike = {
  pattern: string;
  agents: string[];
  risk_score: number;
  description: string;
  owasp_agentic_tag?: string | undefined;
};

export type InteractionRiskAction = {
  label: string;
  href: string;
};

export function attackPathKey(path: AttackPath): string {
  return `${path.source}::${path.target}::${path.hops.join("->")}`;
}

export function moveAttackPathSelection(
  attackPaths: AttackPath[],
  currentKey: string | null,
  direction: -1 | 1,
): string | null {
  if (attackPaths.length === 0) return null;
  if (!currentKey) return attackPathKey(attackPaths[0]!);

  const currentIndex = attackPaths.findIndex((path) => attackPathKey(path) === currentKey);
  if (currentIndex < 0) return attackPathKey(attackPaths[0]!);

  const nextIndex = (currentIndex + direction + attackPaths.length) % attackPaths.length;
  return attackPathKey(attackPaths[nextIndex]!);
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

export function attackPathSequenceLabels(path: AttackPath, nodeById: Map<string, UnifiedNode>): string[] {
  return path.hops
    .map((hop) => nodeById.get(hop))
    .filter((node): node is UnifiedNode => Boolean(node))
    .map((node) => node.label);
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
      rawLabel: node.label,
      label: normalizeLabel(node.label),
      type: mapAttackPathNodeType(String(node.entity_type)),
    }));
}

export function labelsForAttackPathType(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
  type: AttackPathCardNode["type"],
): string[] {
  const deduped = new Map<string, string>();
  for (const node of pathNodeLabels(path, nodeById)) {
    if (node.type !== type || deduped.has(node.label)) continue;
    deduped.set(node.label, node.rawLabel);
  }
  return Array.from(deduped.values());
}

export function recommendedAttackPathActions(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
): AttackPathAction[] {
  const actions: AttackPathAction[] = [];
  const leadingFinding = path.vuln_ids[0];
  const leadAgent = labelsForAttackPathType(path, nodeById, "agent")[0];

  if (leadingFinding) {
    actions.push({
      title: "Validate the lead finding",
      detail: "Open the primary CVE evidence first so the exploit chain has a confirmed root cause.",
      href: `/findings?cve=${encodeURIComponent(leadingFinding)}`,
    });
  }

  if (leadAgent) {
    actions.push({
      title: "Inspect the exposed agent",
      detail: "Review the first affected agent and confirm its connected servers, tools, and configuration trust boundary.",
      href: `/agents?name=${encodeURIComponent(leadAgent)}`,
    });
  }

  if (path.credential_exposure.length > 0) {
    actions.push({
      title: "Contain credential exposure",
      detail: "Rotate or scope exposed secrets before you widen blast radius by exploring deeper topology.",
      href: "/mesh",
    });
  } else if (path.tool_exposure.length > 0) {
    actions.push({
      title: "Review reachable tools",
      detail: "Check whether the reachable tools increase impact before choosing a fix sequence.",
      href: "/mesh",
    });
  }

  if (actions.length < 3) {
    actions.push({
      title: "Open full graph for neighbor context",
      detail: "Use the full graph when you need broader topology, additional paths, or related assets outside this shortlist.",
      href: "/graph",
    });
  }

  return actions.slice(0, 3);
}

export function summarizeInteractionRisks(risks: InteractionRiskLike[]) {
  const uniqueAgents = new Set(risks.flatMap((risk) => risk.agents));
  return {
    total: risks.length,
    uniqueAgents: uniqueAgents.size,
    highestRisk: risks.reduce((max, risk) => Math.max(max, risk.risk_score), 0),
  };
}

export function recommendedInteractionRiskActions(risk: InteractionRiskLike): InteractionRiskAction[] {
  const actions: InteractionRiskAction[] = [];

  if (risk.agents[0]) {
    actions.push({
      label: "Open lead agent",
      href: `/agents?name=${encodeURIComponent(risk.agents[0])}`,
    });
  }

  if (risk.owasp_agentic_tag) {
    actions.push({
      label: "Review tag evidence",
      href: `/compliance?q=${encodeURIComponent(risk.owasp_agentic_tag)}`,
    });
  } else {
    actions.push({
      label: "Inspect runtime controls",
      href: "/proxy",
    });
  }

  return actions.slice(0, 2);
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
