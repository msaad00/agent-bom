import {
  Package,
  Server,
  Bot,
  Cloud,
  KeyRound,
  Container,
  FileCode,
  type LucideIcon,
} from "lucide-react";

import type { UnifiedGraphResponse } from "@/lib/api";
import type { PageLane } from "@/lib/page-lanes";
import { severityRank } from "@/lib/severity";

/**
 * Asset Inventory reads exclusively from the canonical context graph
 * (`GET /v1/graph`, exposed as `api.getGraph`). Every asset row and every
 * correlation number below is derived from real graph nodes + edges — nothing
 * is fabricated. Coverage is therefore exactly whatever the platform has
 * actually discovered for the tenant; a kind with no nodes renders an honest
 * empty state rather than placeholder data.
 */

export type AssetKindId =
  | "packages"
  | "servers"
  | "agents"
  | "cloud"
  | "identities"
  | "containers"
  | "code";

export interface AssetKindConfig {
  id: AssetKindId;
  /** Plural display label, e.g. "Packages". */
  label: string;
  /** Singular, e.g. "package". */
  singular: string;
  /** One-line description of what this page lists. */
  description: string;
  /** Canonical graph entity_type values that roll up into this kind. */
  entityTypes: string[];
  /** Page lane used for the header chrome / accent. */
  lane: PageLane;
  /** Header for the primary (name) column. */
  primaryColumn: string;
  /**
   * Honest, per-kind coverage note. Surfaced verbatim so users understand what
   * the platform can and cannot see for this asset type.
   */
  coverageNote: string;
  icon: LucideIcon;
}

/**
 * The shipped asset-type matrix. Ordered highest-value first. Each kind maps to
 * one or more canonical `entity_type`s so the graph's own taxonomy stays the
 * single source of truth.
 */
export const ASSET_KINDS: readonly AssetKindConfig[] = [
  {
    id: "packages",
    label: "Packages",
    singular: "package",
    description:
      "Open-source dependencies discovered across your agents, images, and repositories (SBOM / SCA).",
    entityTypes: ["package"],
    lane: "command",
    primaryColumn: "Package",
    coverageNote:
      "Sourced from SBOM/SCA discovery. Versions and ecosystems come from lockfiles, manifests, and image layers.",
    icon: Package,
  },
  {
    id: "servers",
    label: "MCP servers",
    singular: "MCP server",
    description:
      "Model Context Protocol servers your agents connect to, with transport, tools, and correlated findings.",
    entityTypes: ["server"],
    lane: "ai-estate",
    primaryColumn: "Server",
    coverageNote:
      "Sourced from local discovery, runtime observation, and gateway registration. Reference-only catalog servers live under MCP Catalog.",
    icon: Server,
  },
  {
    id: "agents",
    label: "AI agents",
    singular: "agent",
    description:
      "AI agents and clients discovered in the estate, correlated to the servers, credentials, and findings they touch.",
    entityTypes: ["agent"],
    lane: "ai-estate",
    primaryColumn: "Agent",
    coverageNote:
      "Sourced from local agent configs, the fleet control plane, and runtime traces. See Agent BOM for the full manifest view.",
    icon: Bot,
  },
  {
    id: "cloud",
    label: "Cloud resources",
    singular: "cloud resource",
    description:
      "Compute, storage, databases, and network resources from connected cloud accounts (CSPM inventory).",
    entityTypes: ["cloud_resource", "resource", "data_store", "api_gateway"],
    lane: "cloud-data",
    primaryColumn: "Resource",
    coverageNote:
      "Read-only cloud inventory. Coverage depends on which accounts are connected and which inventory scopes are enabled per provider.",
    icon: Cloud,
  },
  {
    id: "identities",
    label: "Identities & credentials",
    singular: "identity",
    description:
      "Human and non-human identities, credentials, roles, and access policies (NHI) linked to your estate.",
    entityTypes: [
      "credential",
      "credential_ref",
      "user",
      "role",
      "service_account",
      "service_principal",
      "managed_identity",
      "federated_identity",
      "group",
      "policy",
      "access_grant",
      "access_policy",
    ],
    lane: "cloud-data",
    primaryColumn: "Identity",
    coverageNote:
      "Credential references never include secret values. NHI coverage depends on connected identity providers (Okta, Entra) and cloud accounts.",
    icon: KeyRound,
  },
  {
    id: "containers",
    label: "Container images",
    singular: "container image",
    description:
      "Container images scanned for vulnerable layers and packages, correlated to the agents that run them.",
    entityTypes: ["container"],
    lane: "command",
    primaryColumn: "Image",
    coverageNote:
      "Sourced from image scans. Coverage is limited to images that have been scanned or observed running.",
    icon: Container,
  },
  {
    id: "code",
    label: "Code & repositories",
    singular: "code asset",
    description:
      "Applications, source modules, config files, and CI jobs from scanned repositories (SAST / IaC surface).",
    entityTypes: [
      "application",
      "source_file",
      "code_module",
      "config_file",
      "external_import",
      "directory",
      "ci_job",
    ],
    lane: "command",
    primaryColumn: "Asset",
    coverageNote:
      "Sourced from repository and project scans. Depth depends on which repos were scanned and whether SAST/IaC analysis ran.",
    icon: FileCode,
  },
];

export const ASSET_KIND_BY_ID: Record<AssetKindId, AssetKindConfig> =
  Object.fromEntries(ASSET_KINDS.map((kind) => [kind.id, kind])) as Record<
    AssetKindId,
    AssetKindConfig
  >;

/** Entity types that represent findings (used for correlation, never listed as assets). */
export const FINDING_ENTITY_TYPES: ReadonlySet<string> = new Set([
  "vulnerability",
  "misconfiguration",
  "drift_incident",
]);

const ENTITY_TYPE_TO_KIND: Map<string, AssetKindId> = new Map(
  ASSET_KINDS.flatMap((kind) =>
    kind.entityTypes.map((entityType) => [entityType, kind.id] as const),
  ),
);

/** Map a canonical graph entity_type to its asset-kind bucket, if any. */
export function assetKindForEntityType(
  entityType: string | undefined | null,
): AssetKindId | null {
  if (!entityType) return null;
  return ENTITY_TYPE_TO_KIND.get(entityType.toLowerCase()) ?? null;
}

type GraphNode = UnifiedGraphResponse["nodes"][number];
type GraphEdge = UnifiedGraphResponse["edges"][number];

export interface AssetRow {
  id: string;
  kind: AssetKindId;
  entityType: string;
  label: string;
  /** The asset node's own posture severity, lowercased. */
  severity: string;
  severityRank: number;
  riskScore: number;
  status: string;
  ecosystem: string | undefined;
  provider: string | undefined;
  environment: string | undefined;
  version: string | undefined;
  dataSources: string[];
  /** Correlated findings — direct finding neighbors in the graph. */
  findingCount: number;
  criticalCount: number;
  highCount: number;
  /** Highest severity among correlated findings, lowercased ("none" when zero). */
  topFindingSeverity: string;
  firstSeen: string | undefined;
  lastSeen: string | undefined;
  attributes: Record<string, unknown>;
  complianceTags: string[];
  /** Graph ids of the correlated finding nodes (for drill-down links). */
  findingIds: string[];
}

export interface InventoryModel {
  rowsByKind: Record<AssetKindId, AssetRow[]>;
  /** True per-kind totals from graph stats (may exceed loaded rows). */
  totalsByKind: Record<AssetKindId, number>;
  /** Rows actually loaded into the model for this page. */
  loadedByKind: Record<AssetKindId, number>;
  scanId: string;
  createdAt: string;
}

function attrString(node: GraphNode, key: string): string | undefined {
  const value = node.attributes?.[key];
  if (typeof value === "string" && value.trim()) return value.trim();
  return undefined;
}

function nodeDimension(node: GraphNode, key: string): string | undefined {
  const dims = node.dimensions as unknown as Record<string, unknown> | undefined;
  const value = dims?.[key];
  if (typeof value === "string" && value.trim()) return value.trim();
  return undefined;
}

function emptyRecord(): Record<AssetKindId, AssetRow[]> {
  return {
    packages: [],
    servers: [],
    agents: [],
    cloud: [],
    identities: [],
    containers: [],
    code: [],
  };
}

function emptyCounts(): Record<AssetKindId, number> {
  return {
    packages: 0,
    servers: 0,
    agents: 0,
    cloud: 0,
    identities: 0,
    containers: 0,
    code: 0,
  };
}

/**
 * Build the inventory model from a unified graph response. Buckets non-finding
 * nodes by asset kind and correlates each to its direct finding neighbors.
 */
export function buildInventory(graph: UnifiedGraphResponse): InventoryModel {
  const nodesById = new Map<string, GraphNode>();
  for (const node of graph.nodes) {
    nodesById.set(node.id, node);
  }

  const findingNeighbors = new Map<string, GraphNode[]>();
  const edges: GraphEdge[] = graph.edges ?? [];
  for (const edge of edges) {
    const source = nodesById.get(edge.source);
    const target = nodesById.get(edge.target);
    if (!source || !target) continue;
    const sourceIsFinding = FINDING_ENTITY_TYPES.has(source.entity_type.toLowerCase());
    const targetIsFinding = FINDING_ENTITY_TYPES.has(target.entity_type.toLowerCase());
    // Only correlate finding <-> asset edges (exactly one endpoint a finding).
    if (sourceIsFinding === targetIsFinding) continue;
    const finding = sourceIsFinding ? source : target;
    const asset = sourceIsFinding ? target : source;
    const bucket = findingNeighbors.get(asset.id) ?? [];
    bucket.push(finding);
    findingNeighbors.set(asset.id, bucket);
  }

  const rowsByKind = emptyRecord();
  for (const node of graph.nodes) {
    const entityType = node.entity_type.toLowerCase();
    const kind = assetKindForEntityType(entityType);
    if (!kind) continue;

    const findings = findingNeighbors.get(node.id) ?? [];
    const seenFinding = new Set<string>();
    let criticalCount = 0;
    let highCount = 0;
    let topRank = -1;
    let topSeverity = "none";
    const findingIds: string[] = [];
    for (const finding of findings) {
      if (seenFinding.has(finding.id)) continue;
      seenFinding.add(finding.id);
      findingIds.push(finding.id);
      const sev = (finding.severity ?? "none").toLowerCase();
      if (sev === "critical") criticalCount += 1;
      else if (sev === "high") highCount += 1;
      const rank = severityRank(sev);
      if (rank > topRank) {
        topRank = rank;
        topSeverity = sev;
      }
    }

    const severity = (node.severity ?? "none").toLowerCase();
    rowsByKind[kind].push({
      id: node.id,
      kind,
      entityType,
      label: node.label || node.id,
      severity,
      severityRank: severityRank(severity),
      riskScore: typeof node.risk_score === "number" ? node.risk_score : 0,
      status: node.status ?? "unknown",
      ecosystem: nodeDimension(node, "ecosystem") ?? attrString(node, "ecosystem"),
      provider:
        nodeDimension(node, "cloud_provider") ?? attrString(node, "cloud_provider") ?? attrString(node, "provider"),
      environment: nodeDimension(node, "environment") ?? attrString(node, "environment"),
      version: attrString(node, "version"),
      dataSources: Array.isArray(node.data_sources) ? node.data_sources : [],
      findingCount: seenFinding.size,
      criticalCount,
      highCount,
      topFindingSeverity: topSeverity,
      firstSeen: node.first_seen || undefined,
      lastSeen: node.last_seen || undefined,
      attributes: node.attributes ?? {},
      complianceTags: Array.isArray(node.compliance_tags) ? node.compliance_tags : [],
      findingIds,
    });
  }

  const nodeTypes = graph.stats?.node_types ?? {};
  const totalsByKind = emptyCounts();
  const loadedByKind = emptyCounts();
  for (const kind of ASSET_KINDS) {
    let total = 0;
    for (const entityType of kind.entityTypes) {
      total += nodeTypes[entityType] ?? 0;
    }
    const loaded = rowsByKind[kind.id].length;
    loadedByKind[kind.id] = loaded;
    // Stats are graph-wide; if they are missing or lower than what we loaded,
    // fall back to the honest loaded count so we never under-report.
    totalsByKind[kind.id] = Math.max(total, loaded);
  }

  return {
    rowsByKind,
    totalsByKind,
    loadedByKind,
    scanId: graph.scan_id,
    createdAt: graph.created_at,
  };
}

export interface AssetFilter {
  query?: string | undefined;
  /** Minimum asset severity, e.g. "high"; "all" keeps everything. */
  severity?: string | undefined;
  dataSource?: string | undefined;
  /** When true, keep only rows that have at least one correlated finding. */
  withFindingsOnly?: boolean | undefined;
}

/** Apply the inventory filter toolbar selections to a row set. */
export function filterAssetRows(rows: AssetRow[], filter: AssetFilter): AssetRow[] {
  const query = filter.query?.trim().toLowerCase() ?? "";
  const severity = filter.severity && filter.severity !== "all" ? filter.severity : undefined;
  const dataSource = filter.dataSource && filter.dataSource !== "all" ? filter.dataSource : undefined;
  return rows.filter((row) => {
    if (severity && row.severityRank < severityRank(severity)) return false;
    if (dataSource && !row.dataSources.includes(dataSource)) return false;
    if (filter.withFindingsOnly && row.findingCount === 0) return false;
    if (query) {
      const haystack = [
        row.label,
        row.entityType,
        row.ecosystem ?? "",
        row.provider ?? "",
        row.environment ?? "",
        row.version ?? "",
        ...row.dataSources,
      ]
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
}

/** Distinct data sources present in a row set, sorted for a filter dropdown. */
export function dataSourceOptions(rows: AssetRow[]): string[] {
  const seen = new Set<string>();
  for (const row of rows) {
    for (const source of row.dataSources) {
      if (source) seen.add(source);
    }
  }
  return Array.from(seen).sort((a, b) => a.localeCompare(b));
}

export type AssetSortKey = "label" | "severity" | "findings" | "risk";

/** Stable sort a row set by a column. */
export function sortAssetRows(
  rows: AssetRow[],
  key: AssetSortKey,
  direction: "asc" | "desc",
): AssetRow[] {
  const factor = direction === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    let diff = 0;
    if (key === "label") diff = a.label.localeCompare(b.label);
    else if (key === "severity") diff = a.severityRank - b.severityRank || a.findingCount - b.findingCount;
    else if (key === "findings")
      diff = a.findingCount - b.findingCount || a.criticalCount - b.criticalCount;
    else diff = a.riskScore - b.riskScore;
    if (diff === 0) diff = a.label.localeCompare(b.label);
    return diff * factor;
  });
}

export interface KindSummary {
  criticalAssets: number;
  highAssets: number;
  withFindings: number;
  totalFindings: number;
}

/** Roll a row set up into the KPI numbers shown on the strip. */
export function summarizeRows(rows: AssetRow[]): KindSummary {
  let criticalAssets = 0;
  let highAssets = 0;
  let withFindings = 0;
  let totalFindings = 0;
  for (const row of rows) {
    if (row.severity === "critical") criticalAssets += 1;
    else if (row.severity === "high") highAssets += 1;
    if (row.findingCount > 0) withFindings += 1;
    totalFindings += row.findingCount;
  }
  return { criticalAssets, highAssets, withFindings, totalFindings };
}
