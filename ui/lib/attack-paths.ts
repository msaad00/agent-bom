import { EntityType, type AttackPath, type UnifiedNode } from "./graph-schema";
import {
  formatExposureEntityDisplay,
  formatExposureEntityTitle,
} from "@/lib/entity-display";
import {
  normalizeExposureSeverity,
  uniqueExposureValues,
  type ExposureEntityRef,
  type ExposureEntityRole,
  type ExposurePath,
  type ExposureRelationshipRef,
  exposureSeverityRank,
} from "./exposure-path";

export type AttackPathCardNode = {
  type: "cve" | "package" | "server" | "agent" | "credential" | "tool" | "data" | "identity" | "entity";
  label: string;
  severity?: string | undefined;
};

export interface RankedAttackPathRow<C> {
  path: AttackPath;
  card: C | undefined;
  rank: number;
  key: string;
}

export type AttackPathFocus = {
  cve?: string | undefined;
  packageName?: string | undefined;
  agentName?: string | undefined;
  scanId?: string | undefined;
};

export type GraphInvestigationRequest = {
  rootId: string;
  rootLabel?: string | undefined;
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

/**
 * Total mapping for chain rendering — unlike {@link mapAttackPathNodeType},
 * this never returns null. Every hop on a correlated exposure path must render
 * so the card shows the full `entry → … → sensitive data → finding` chain, not
 * a single surviving node. Data stores, tools, identities, and gateways are the
 * crown-jewel and blast-radius hops that made the older mapping collapse.
 */
export function mapAttackPathChainType(entityType: string): AttackPathCardNode["type"] {
  switch (entityType) {
    case EntityType.VULNERABILITY:
    case EntityType.MISCONFIGURATION:
      return "cve";
    case EntityType.PACKAGE:
      return "package";
    case EntityType.SERVER:
    case EntityType.CONTAINER:
    case EntityType.CLOUD_RESOURCE:
    case EntityType.API_GATEWAY:
    case EntityType.APPLICATION:
      return "server";
    case EntityType.AGENT:
      return "agent";
    case EntityType.USER:
    case EntityType.GROUP:
    case EntityType.SERVICE_ACCOUNT:
    case EntityType.SERVICE_PRINCIPAL:
    case EntityType.ROLE:
    case EntityType.FEDERATED_IDENTITY:
    case EntityType.MANAGED_IDENTITY:
    case EntityType.ACCOUNT:
      return "identity";
    case EntityType.CREDENTIAL:
    case EntityType.CREDENTIAL_REF:
      return "credential";
    case EntityType.TOOL:
    case EntityType.TOOL_CALL:
      return "tool";
    case EntityType.DATA_STORE:
    case EntityType.DATASET:
      return "data";
    default:
      return "entity";
  }
}

export function toAttackCardNodes(path: AttackPath, nodeById: Map<string, UnifiedNode>): AttackPathCardNode[] {
  const nodes: AttackPathCardNode[] = [];
  for (const hop of path.hops) {
    const node = nodeById.get(hop);
    if (!node) continue;
    const entityType = String(node.entity_type);
    nodes.push({
      type: mapAttackPathChainType(entityType),
      label: formatExposureEntityTitle(node.label, exposureRoleForEntityType(entityType), node.attributes ?? {}),
      severity: node.severity,
    });
  }
  return nodes;
}

const GENERIC_PATH_TITLE = /^exposure path\b/i;

/**
 * Prefer a descriptive backend title, but when the API falls back to the
 * generic "Exposure path" (a path with no finding id), synthesise a concrete
 * "entry → crown-jewel" title from the correlated chain endpoints so every card
 * reads differently and scannably.
 */
export function descriptiveAttackPathTitle(cardTitle: string | undefined, nodes: AttackPathCardNode[]): string {
  const trimmed = (cardTitle ?? "").trim();
  if (trimmed && !GENERIC_PATH_TITLE.test(trimmed)) return trimmed;
  const labels = nodes.map((node) => node.label.trim()).filter(Boolean);
  if (labels.length === 0) return trimmed || "Exposure path";
  const first = labels[0]!;
  const last = labels[labels.length - 1]!;
  if (labels.length === 1 || first === last) return first;
  return `${first} → ${last}`;
}

/**
 * Pair each sorted path with its fix-first card by position and stamp a rank
 * that equals the row's index in the sorted list. This is the single source of
 * truth for rank so duplicate ranks (#6 three times) — caused by looking rank up
 * through a lossy `source::target::hops` key that collides across distinct
 * paths — can never happen. The composite `key` is guaranteed unique per row.
 */
export function rankedAttackPathRows<C>(paths: AttackPath[], cards: readonly C[] = []): RankedAttackPathRow<C>[] {
  return paths.map((path, index) => ({
    path,
    card: cards[index],
    rank: index + 1,
    key: `${attackPathKey(path)}::${index}`,
  }));
}

export function exposureRoleForEntityType(entityType: string): ExposureEntityRole {
  switch (entityType) {
    case EntityType.VULNERABILITY:
    case EntityType.MISCONFIGURATION:
      return "finding";
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
    case EntityType.TOOL:
      return "tool";
    case EntityType.ENVIRONMENT:
      return "environment";
    default:
      return "unknown";
  }
}

function exposureRefFromUnifiedNode(node: UnifiedNode): ExposureEntityRef {
  const role = exposureRoleForEntityType(String(node.entity_type));
  const display = formatExposureEntityDisplay(node.label, role, node.attributes ?? {});
  return {
    id: node.id,
    label: display.title,
    subtitle: display.subtitle,
    role,
    severity: node.severity,
    riskScore: node.risk_score,
  };
}

function fallbackExposureRef(id: string, role: ExposureEntityRole): ExposureEntityRef {
  return {
    id,
    label: id,
    role,
  };
}

function highestNodeSeverity(hops: ExposureEntityRef[], fallback: string): string {
  return hops.reduce(
    (highest, hop) => (exposureSeverityRank(hop.severity) > exposureSeverityRank(highest) ? String(hop.severity) : highest),
    fallback,
  );
}

function parsePackageHopLabel(label: string): { packageName: string; packageVersion?: string } {
  const at = label.lastIndexOf("@");
  if (at > 0) {
    return { packageName: label.slice(0, at), packageVersion: label.slice(at + 1) };
  }
  return { packageName: label };
}

export function toExposurePathFromAttackPath(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
  options: { rank?: number | undefined; scanId?: string | undefined } = {},
): ExposurePath {
  const hops = path.hops.map((hop) => {
    const node = nodeById.get(hop);
    return node ? exposureRefFromUnifiedNode(node) : fallbackExposureRef(hop, "unknown");
  });
  const source = nodeById.get(path.source)
    ? exposureRefFromUnifiedNode(nodeById.get(path.source)!)
    : hops[0] ?? fallbackExposureRef(path.source, "unknown");
  const target = nodeById.get(path.target)
    ? exposureRefFromUnifiedNode(nodeById.get(path.target)!)
    : hops[hops.length - 1] ?? fallbackExposureRef(path.target, "unknown");
  const relationships: ExposureRelationshipRef[] = path.edges.map((edgeId, index) => ({
    id: edgeId,
    source: path.hops[index] ?? source.id,
    target: path.hops[index + 1] ?? target.id,
    relationship: edgeId.includes(":") ? edgeId.split(":")[0] ?? "related" : "related",
    direction: "directed",
    traversable: true,
  }));
  const packages = hops.filter((hop) => hop.role === "package");
  const servers = hops.filter((hop) => hop.role === "server");
  const affectedAgents = uniqueExposureValues(labelsForAttackPathType(path, nodeById, "agent"));
  const exposedCredentials = uniqueExposureValues(path.credential_exposure);
  const reachableTools = uniqueExposureValues(path.tool_exposure);

  return {
    id: attackPathKey(path),
    rank: options.rank,
    label: path.summary || `${source.label} -> ${target.label}`,
    summary: path.summary,
    riskScore: path.composite_risk,
    severity: normalizeExposureSeverity(highestNodeSeverity(hops, path.composite_risk >= 9 ? "critical" : "high")),
    source,
    target,
    hops,
    relationships,
    nodeIds: path.hops,
    edgeIds: path.edges,
    findings: uniqueExposureValues(path.vuln_ids),
    affectedAgents,
    affectedServers: uniqueExposureValues(servers.map((server) => server.label)),
    reachableTools,
    exposedCredentials,
    dependencyContext: {
      packageName: packages[0]
        ? parsePackageHopLabel(nodeById.get(packages[0].id)?.label ?? packages[0].label).packageName
        : undefined,
      packageVersion: packages[0]
        ? parsePackageHopLabel(nodeById.get(packages[0].id)?.label ?? packages[0].label).packageVersion
        : undefined,
      serverName: servers[0]
        ? nodeById.get(servers[0].id)?.label ?? servers[0].label
        : undefined,
    },
    evidence: {
      isKev: hops.some((hop) => String(hop.label).toLowerCase().includes("kev")),
      source: "graph_attack_path",
    },
    provenance: {
      source: "graph_attack_path",
      scanId: options.scanId,
    },
  };
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

export function buildFindingsHref(focus: Pick<AttackPathFocus, "cve" | "scanId">): string {
  const params = new URLSearchParams();
  if (focus.scanId) params.set("scan", focus.scanId);
  if (focus.cve) params.set("cve", focus.cve);
  const query = params.toString();
  return query ? `/findings?${query}` : "/findings";
}

export function buildGraphInvestigationHref(
  request: GraphInvestigationRequest & Pick<AttackPathFocus, "scanId" | "agentName">,
): string {
  const params = new URLSearchParams();
  if (request.scanId) params.set("scan", request.scanId);
  if (request.agentName) params.set("agent", request.agentName);
  params.set("investigate", "1");
  params.set("root", request.rootId);
  if (request.rootLabel && request.rootLabel !== request.rootId) {
    params.set("q", request.rootLabel);
  }
  return `/graph?${params.toString()}`;
}

export function decodeGraphInvestigationParams(
  params: URLSearchParams | { get(name: string): string | null },
): GraphInvestigationRequest | null {
  const rootId = params.get("root") || params.get("root_id") || params.get("node");
  if (!rootId) return null;

  const investigate = params.get("investigate");
  if (investigate && investigate !== "1" && investigate !== "true") return null;

  return {
    rootId,
    rootLabel: params.get("q") || params.get("label") || undefined,
  };
}

function normalizeLabel(value: string | undefined): string {
  return (value ?? "").trim().toLowerCase();
}

function pathNodeLabels(path: AttackPath, nodeById: Map<string, UnifiedNode>) {
  return path.hops
    .map((hop) => nodeById.get(hop))
    .filter((node): node is UnifiedNode => Boolean(node))
    .map((node) => {
      const type = mapAttackPathNodeType(String(node.entity_type));
      const role: ExposureEntityRole =
        type === "cve"
          ? "finding"
          : type === "credential"
            ? "credential"
            : type === "package"
              ? "package"
              : type === "server"
                ? "server"
                : type === "agent"
                  ? "agent"
                  : "unknown";
      const display = formatExposureEntityDisplay(node.label, role, node.attributes ?? {});
      return {
        rawLabel: node.label,
        label: normalizeLabel(node.label),
        friendlyLabel: display.title,
        type,
      };
    });
}

export function labelsForAttackPathType(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
  type: AttackPathCardNode["type"],
): string[] {
  const deduped = new Map<string, string>();
  for (const node of pathNodeLabels(path, nodeById)) {
    if (node.type !== type || deduped.has(node.label)) continue;
    deduped.set(node.label, node.friendlyLabel);
  }
  return Array.from(deduped.values());
}

export function investigationRootForAttackPath(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
  focus: AttackPathFocus = {},
): UnifiedNode | null {
  const cve = normalizeLabel(focus.cve);
  const packageName = normalizeLabel(focus.packageName);
  const agentName = normalizeLabel(focus.agentName);
  const typedHops = path.hops
    .map((hop) => nodeById.get(hop))
    .filter((node): node is UnifiedNode => Boolean(node))
    .map((node) => ({
      node,
      label: normalizeLabel(node.label),
      type: mapAttackPathNodeType(String(node.entity_type)),
    }));

  if (cve) {
    const focusedCve = typedHops.find(
      (hop) => hop.type === "cve" && (hop.label === cve || path.vuln_ids.some((id) => normalizeLabel(id) === cve)),
    );
    if (focusedCve) return focusedCve.node;
  }

  if (packageName) {
    const focusedPackage = typedHops.find((hop) => hop.type === "package" && hop.label === packageName);
    if (focusedPackage) return focusedPackage.node;
  }

  if (agentName) {
    const focusedAgent = typedHops.find((hop) => hop.type === "agent" && hop.label === agentName);
    if (focusedAgent) return focusedAgent.node;
  }

  return nodeById.get(path.source) ?? typedHops[0]?.node ?? null;
}

export function recommendedAttackPathActions(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
  focus: Pick<AttackPathFocus, "scanId"> = {},
): AttackPathAction[] {
  const actions: AttackPathAction[] = [];
  const leadingFinding = path.vuln_ids[0];
  const leadAgent = labelsForAttackPathType(path, nodeById, "agent")[0];

  if (leadingFinding) {
    actions.push({
      title: "Validate the lead finding",
      detail: "Open the primary CVE evidence first so the exploit chain has a confirmed root cause.",
      href: buildFindingsHref({ scanId: focus.scanId, cve: leadingFinding }),
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
      href: "/runtime?tab=proxy",
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
