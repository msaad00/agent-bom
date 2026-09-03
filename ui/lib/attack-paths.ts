import { EntityType, type AttackPath, type UnifiedNode } from "./graph-schema";
import type { UnifiedGraphResponse } from "./api-types";
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
  /** Estate / vuln UnifiedNode id from Finding.node_id / finding_node_id. */
  nodeId?: string | undefined;
  /** Stable Finding.id when stamped on the path or query string. */
  findingId?: string | undefined;
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

function pathNodeIdsForTypes(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
  entityTypes: ReadonlySet<string>,
): string[] {
  return [...new Set(
    path.hops.filter((hop) => {
      const node = nodeById.get(hop);
      return node ? entityTypes.has(String(node.entity_type)) : false;
    }),
  )].sort();
}

/** Stable presentation key without mutating or collapsing stored path rows. */
export function attackPathPresentationKey(
  path: AttackPath,
  nodeById: Map<string, UnifiedNode>,
): string {
  const findingNodeLabels = path.hops.flatMap((hop) => {
    const node = nodeById.get(hop);
    if (!node || ![EntityType.VULNERABILITY, EntityType.MISCONFIGURATION].includes(node.entity_type as EntityType)) {
      return [];
    }
    return [node.label.trim().toLowerCase()];
  });
  const advisoryLabels = path.vuln_ids.map((value) => value.trim().toLowerCase()).filter(Boolean);
  const findings = [...new Set(advisoryLabels.length ? advisoryLabels : findingNodeLabels)].sort();
  const agents = pathNodeIdsForTypes(
    path,
    nodeById,
    new Set([EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT]),
  );
  const packages = pathNodeIdsForTypes(path, nodeById, new Set([EntityType.PACKAGE]));
  const assets = pathNodeIdsForTypes(
    path,
    nodeById,
    new Set([EntityType.SERVER, EntityType.CONTAINER, EntityType.CLOUD_RESOURCE]),
  );
  return JSON.stringify({
    finding: findings.length ? findings : path.finding_ids?.length ? [...path.finding_ids].sort() : [path.target],
    agent: agents.length ? agents : [path.source],
    package: packages,
    asset: assets,
  });
}

export function dedupeAttackPathsForPresentation(
  paths: AttackPath[],
  nodeById: Map<string, UnifiedNode>,
): AttackPath[] {
  const seen = new Set<string>();
  return paths.filter((path) => {
    const key = attackPathPresentationKey(path, nodeById);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
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

/** Compact semantic chain for a ranked row before the analyst opens its DAG. */
export function attackPathRoleChain(path: AttackPath, nodeById: Map<string, UnifiedNode>): string {
  const roles: string[] = [];
  for (const node of toAttackCardNodes(path, nodeById)) {
    const role = node.type === "cve" ? "finding" : node.type;
    if (roles[roles.length - 1] !== role) roles.push(role);
  }
  return roles.join(" → ");
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
 * Pair each sorted path with the fix-first card derived from the same path and
 * stamp a rank that equals the row's index in the sorted list. Matching by path
 * identity prevents independently filtered or ordered API responses from
 * cross-pollinating a card title with another path's hop and agent counters.
 * The composite `key` remains unique when structurally identical paths repeat.
 */
export function rankedAttackPathRows<C extends { attack_path: AttackPath }>(
  paths: AttackPath[],
  cards: readonly C[] = [],
): RankedAttackPathRow<C>[] {
  const cardsByPath = new Map<string, C[]>();
  for (const card of cards) {
    const key = attackPathKey(card.attack_path);
    const matchingCards = cardsByPath.get(key) ?? [];
    matchingCards.push(card);
    cardsByPath.set(key, matchingCards);
  }

  return paths.map((path, index) => ({
    path,
    card: cardsByPath.get(attackPathKey(path))?.shift(),
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
  const attributes = node.attributes ?? {};
  let display = formatExposureEntityDisplay(node.label, role, attributes);
  let kindLabel: string | undefined;
  if (node.entity_type === EntityType.CONTAINER) {
    const [title, digest] = node.label.split("@", 2);
    display = {
      title: title || node.label,
      subtitle: digest ? `Digest ${digest}` : "Container image",
    };
    kindLabel = "Container";
  } else if (node.entity_type === EntityType.DATA_STORE || node.entity_type === EntityType.DATASET) {
    const sensitivity = typeof attributes.data_sensitivity === "string"
      ? attributes.data_sensitivity.replaceAll("_", " ")
      : "Sensitive";
    display = {
      title: node.label,
      subtitle: `${sensitivity.charAt(0).toUpperCase()}${sensitivity.slice(1)} data asset`,
    };
    kindLabel = "Data asset";
  } else if (node.entity_type === EntityType.CLOUD_RESOURCE || node.entity_type === EntityType.RESOURCE) {
    display = { title: node.label, subtitle: "Cloud resource" };
    kindLabel = "Cloud resource";
  } else if (
    node.entity_type === EntityType.SERVICE_ACCOUNT ||
    node.entity_type === EntityType.SERVICE_PRINCIPAL ||
    node.entity_type === EntityType.MANAGED_IDENTITY ||
    node.entity_type === EntityType.USER ||
    node.entity_type === EntityType.GROUP ||
    node.entity_type === EntityType.ROLE
  ) {
    display = { title: node.label, subtitle: "Workload identity" };
    kindLabel = "Identity";
  } else if (node.entity_type === EntityType.AGENT && node.id.startsWith("workload:")) {
    display = { title: node.label, subtitle: "Application workload" };
    kindLabel = "Workload";
  } else if (
    node.entity_type === EntityType.SERVER &&
    (node.id.startsWith("service:") || attributes.internet_exposed === true)
  ) {
    display = {
      title: node.label,
      subtitle: attributes.internet_exposed === true ? "Internet-exposed service" : "Application service",
    };
    kindLabel = "Service";
  }
  return {
    id: node.id,
    label: display.title,
    subtitle: display.subtitle,
    kindLabel,
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
  const relationships: ExposureRelationshipRef[] = path.hops.slice(0, -1).map((sourceId, index) => {
    const targetId = path.hops[index + 1] ?? target.id;
    const receipt = path.hop_evidence?.find(
      (candidate) => candidate.source_node_id === sourceId && candidate.target_node_id === targetId,
    );
    const edgeValue = path.edges[index]?.trim();
    // Persisted attack paths store relationship labels in `edges`; a few
    // legacy fixtures store opaque `edge:*` identifiers instead. Never render
    // an opaque identifier as if it described traversal semantics.
    const edgeRelationship = edgeValue && !edgeValue.startsWith("edge:") ? edgeValue : undefined;
    return {
      id: `${sourceId}->${targetId}`,
      source: sourceId,
      target: targetId,
      relationship: receipt?.relationship || edgeRelationship || "related",
      direction: receipt?.direction === "bidirectional" ? "bidirectional" : "directed",
      traversable: receipt?.traversable ?? true,
      confidence: receipt?.confidence,
      evidenceCount: receipt?.source_snapshot_ids.length,
    };
  });
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

/**
 * Preserve server-ranked remediation metadata while presenting every hop with
 * the canonical graph node kind. The API exposure contract intentionally uses
 * broad roles for visual styling (for example container -> server), so the
 * graph taxonomy remains the source of truth for the operator-facing label.
 */
export function withCanonicalExposurePresentation(
  path: ExposurePath,
  nodeById: Map<string, UnifiedNode>,
): ExposurePath {
  const hops = path.hops.map((hop) => {
    const node = nodeById.get(hop.id);
    return node ? exposureRefFromUnifiedNode(node) : hop;
  });
  const hopById = new Map(hops.map((hop) => [hop.id, hop]));
  const sourceNode = nodeById.get(path.source.id);
  const targetNode = nodeById.get(path.target.id);

  return {
    ...path,
    hops,
    source: sourceNode
      ? exposureRefFromUnifiedNode(sourceNode)
      : hopById.get(path.source.id) ?? path.source,
    target: targetNode
      ? exposureRefFromUnifiedNode(targetNode)
      : hopById.get(path.target.id) ?? path.target,
  };
}

export function attackPathSequenceLabels(path: AttackPath, nodeById: Map<string, UnifiedNode>): string[] {
  return path.hops
    .map((hop) => nodeById.get(hop))
    .filter((node): node is UnifiedNode => Boolean(node))
    .map((node) => node.label);
}

export function buildSecurityGraphHref(focus: AttackPathFocus): string {
  const params = new URLSearchParams({ lens: "attack-path" });
  if (focus.scanId) params.set("scan", focus.scanId);
  if (focus.nodeId) params.set("node", focus.nodeId);
  if (focus.findingId) params.set("finding", focus.findingId);
  if (focus.cve) params.set("cve", focus.cve);
  if (focus.packageName) params.set("package", focus.packageName);
  if (focus.agentName) params.set("agent", focus.agentName);
  return `/security-graph?${params.toString()}`;
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
  params.set("lens", "lineage");
  return `/security-graph?${params.toString()}`;
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
      href: "/security-graph?lens=mesh",
    });
  } else if (path.tool_exposure.length > 0) {
    actions.push({
      title: "Review reachable tools",
      detail: "Check whether the reachable tools increase impact before choosing a fix sequence.",
      href: "/security-graph?lens=mesh",
    });
  }

  if (actions.length < 3) {
    actions.push({
      title: "Open full graph for neighbor context",
      detail: "Use the full graph when you need broader topology, additional paths, or related assets outside this shortlist.",
      href: "/security-graph?lens=lineage",
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
  const nodeId = (focus.nodeId || "").trim();
  const findingId = (focus.findingId || "").trim();
  if (!cve && !packageName && !agentName && !nodeId && !findingId) return false;

  const labels = pathNodeLabels(path, nodeById);

  if (nodeId && !path.hops.includes(nodeId)) {
    return false;
  }

  if (findingId) {
    const pathFindingIds = Array.isArray(path.finding_ids) ? path.finding_ids : [];
    const inFindingIds = pathFindingIds.some((id) => id === findingId);
    const inVulnIds = path.vuln_ids.some((id) => id === findingId);
    if (!inFindingIds && !inVulnIds) return false;
  }

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

/**
 * Append a later `/v1/graph/attack-paths` page onto an already-loaded response.
 * Dedupes nodes/edges/paths so "Show more" can follow `pagination.has_more`
 * without resetting the investigation canvas.
 */
export function mergeAttackPathGraphPages(
  current: UnifiedGraphResponse,
  next: UnifiedGraphResponse,
): UnifiedGraphResponse {
  const nodeIds = new Set(current.nodes.map((node) => node.id));
  const edgeIds = new Set(current.edges.map((edge) => edge.id));
  const pathKeys = new Set(current.attack_paths.map((path) => attackPathKey(path)));

  const mergedPaths = [
    ...current.attack_paths,
    ...next.attack_paths.filter((path) => !pathKeys.has(attackPathKey(path))),
  ];
  return {
    ...current,
    ...next,
    nodes: [...current.nodes, ...next.nodes.filter((node) => !nodeIds.has(node.id))],
    edges: [...current.edges, ...next.edges.filter((edge) => !edgeIds.has(edge.id))],
    attack_paths: mergedPaths,
    pagination: next.pagination,
    stats: {
      ...current.stats,
      ...next.stats,
      attack_path_count: next.pagination.total,
    },
  };
}

export interface GraphPathQueueCounts {
  snapshotTotal: number;
  materializedPaths: number;
  derivedPaths: number;
  returnedRows: number;
  renderedRows: number;
  truncated: boolean;
}

/** Reconcile snapshot, transfer, and presentation counts without conflating them. */
export function graphPathQueueCounts(
  graph: UnifiedGraphResponse | null | undefined,
  renderedRows: number,
): GraphPathQueueCounts {
  const metadata = graph?.count_metadata;
  const snapshotTotal = metadata?.snapshot_total ?? graph?.pagination?.total ?? 0;
  const source = metadata?.source;
  return {
    snapshotTotal,
    materializedPaths:
      metadata?.materialized_paths ?? (source === "persisted_graph_paths" ? snapshotTotal : 0),
    derivedPaths:
      metadata?.derived_paths ?? (source === "derived_graph_paths" ? snapshotTotal : 0),
    returnedRows: graph?.attack_paths.length ?? 0,
    renderedRows: Math.max(0, renderedRows),
    truncated: Boolean(graph?.completeness?.truncated ?? graph?.pagination?.has_more),
  };
}
