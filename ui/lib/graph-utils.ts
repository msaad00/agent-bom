/**
 * Shared React Flow graph utilities — DRY constants for Controls, MiniMap, and
 * Background styling used across all graph views (Lineage, Mesh, Context, Attack Flow).
 */

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";

// ─── Shared Styling Constants ────────────────────────────────────────────────

export const CONTROLS_CLASS =
  "!bg-zinc-900/90 !border-zinc-700 !rounded-lg !backdrop-blur-sm [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300 [&>button:hover]:!bg-zinc-700";

export const MINIMAP_CLASS = "!bg-zinc-900/90 !border-zinc-700 !rounded-lg !backdrop-blur-sm";
export const MINIMAP_BG = "#09090b";
export const MINIMAP_MASK = "rgba(24,24,27,0.82)";

export const BACKGROUND_COLOR = "#1c1c1e";
export const BACKGROUND_GAP = 24;

// ─── MiniMap Node Color Map ──────────────────────────────────────────────────

export const NODE_COLOR_MAP: Record<LineageNodeType, string> = {
  provider: "#71717a",
  agent: "#10b981",
  server: "#3b82f6",
  sharedServer: "#22d3ee",
  package: "#52525b",
  vulnerability: "#ef4444",
  misconfiguration: "#f97316",
  credential: "#f59e0b",
  tool: "#a855f7",
  model: "#8b5cf6",
  dataset: "#06b6d4",
  container: "#6366f1",
  cloudResource: "#0ea5e9",
  user: "#34d399",
  group: "#d946ef",
  serviceAccount: "#fbbf24",
  environment: "#14b8a6",
  fleet: "#22d3ee",
  cluster: "#38bdf8",
};

export function minimapNodeColor(n: { data: Record<string, unknown> }): string {
  const d = n.data as LineageNodeData;
  return NODE_COLOR_MAP[d.nodeType] ?? "#52525b";
}

// ─── Attack Flow Node Colors ─────────────────────────────────────────────────

export const ATTACK_FLOW_MINIMAP_COLORS: Record<string, string> = {
  cve: "#ef4444",
  package: "#52525b",
  server: "#3b82f6",
  agent: "#10b981",
  credential: "#eab308",
  tool: "#a855f7",
};

// ─── Edge Styling — Turbo Flow Pattern ───────────────────────────────────────

export const EDGE_COLORS = {
  agentToServer: "#10b981",
  serverToPackage: "#3b82f6",
  packageToVuln: "#ef4444",
  serverToCredential: "#f59e0b",
  serverToTool: "#a855f7",
  sharedServer: "#22d3ee",
  sharedCredential: "#f97316",
  lateralPath: "#f97316",
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
} as const;

// ─── Legend Items ─────────────────────────────────────────────────────────────

export interface LegendItem {
  label: string;
  color: string;
  dashed?: boolean | undefined;
  kind?: "node" | "edge" | undefined;
  lineStyle?: "solid" | "dashed" | undefined;
  shape?: "dot" | "square" | "diamond" | "pill" | undefined;
}

const NODE_TYPE_LEGEND_ORDER: LineageNodeType[] = [
  "provider",
  "agent",
  "sharedServer",
  "server",
  "package",
  "model",
  "dataset",
  "container",
  "cloudResource",
  "environment",
  "fleet",
  "cluster",
  "user",
  "group",
  "serviceAccount",
  "vulnerability",
  "misconfiguration",
  "credential",
  "tool",
];

const NODE_TYPE_LEGEND_ITEMS: Record<LineageNodeType, LegendItem> = {
  provider: { label: "Provider", color: "#71717a", kind: "node", shape: "dot" },
  agent: { label: "Agent", color: "#10b981", kind: "node", shape: "dot" },
  sharedServer: { label: "Shared", color: "#22d3ee", kind: "node", shape: "square" },
  server: { label: "Server", color: "#3b82f6", kind: "node", shape: "square" },
  package: { label: "Package", color: "#52525b", kind: "node", shape: "pill" },
  model: { label: "Model", color: "#8b5cf6", kind: "node", shape: "pill" },
  dataset: { label: "Dataset", color: "#06b6d4", kind: "node", shape: "pill" },
  container: { label: "Container", color: "#6366f1", kind: "node", shape: "square" },
  cloudResource: { label: "Cloud", color: "#0ea5e9", kind: "node", shape: "square" },
  environment: { label: "Env", color: "#14b8a6", kind: "node", shape: "square" },
  fleet: { label: "Fleet", color: "#22d3ee", kind: "node", shape: "square" },
  cluster: { label: "Cluster", color: "#38bdf8", kind: "node", shape: "square" },
  user: { label: "User", color: "#34d399", kind: "node", shape: "dot" },
  group: { label: "Group", color: "#d946ef", kind: "node", shape: "pill" },
  serviceAccount: { label: "Svc", color: "#fbbf24", kind: "node", shape: "dot" },
  vulnerability: { label: "Vuln", color: "#ef4444", kind: "node", shape: "diamond" },
  misconfiguration: { label: "Config", color: "#f97316", kind: "node", shape: "diamond" },
  credential: { label: "Cred", color: "#f59e0b", kind: "node", shape: "dot" },
  tool: { label: "Tool", color: "#a855f7", kind: "node", shape: "pill" },
};

const RELATIONSHIP_LEGEND_ORDER = [
  "uses",
  "depends_on",
  "provides_tool",
  "exposes_cred",
  "reaches_tool",
  "vulnerable_to",
  "shares_server",
  "shares_cred",
  "lateral_path",
  "invoked",
  "accessed",
] as const;

const RELATIONSHIP_LEGEND_ITEMS: Record<(typeof RELATIONSHIP_LEGEND_ORDER)[number], LegendItem> = {
  uses: { label: "Uses", color: EDGE_COLORS.agentToServer, kind: "edge", lineStyle: "solid" },
  depends_on: { label: "Depends On", color: EDGE_COLORS.serverToPackage, kind: "edge", lineStyle: "solid" },
  provides_tool: { label: "Provides Tool", color: EDGE_COLORS.serverToTool, kind: "edge", lineStyle: "solid" },
  exposes_cred: { label: "Exposes Cred", color: EDGE_COLORS.serverToCredential, kind: "edge", lineStyle: "dashed", dashed: true },
  reaches_tool: { label: "Credential Reaches Tool", color: "#fbbf24", kind: "edge", lineStyle: "dashed", dashed: true },
  vulnerable_to: { label: "Vulnerable To", color: EDGE_COLORS.packageToVuln, kind: "edge", lineStyle: "solid" },
  shares_server: { label: "Shares Server", color: EDGE_COLORS.sharedServer, kind: "edge", lineStyle: "dashed", dashed: true },
  shares_cred: { label: "Shares Cred", color: EDGE_COLORS.sharedCredential, kind: "edge", lineStyle: "dashed", dashed: true },
  lateral_path: { label: "Lateral Path", color: EDGE_COLORS.lateralPath, kind: "edge", lineStyle: "dashed", dashed: true },
  invoked: { label: "Runtime Invoke", color: EDGE_COLORS.agentToServer, kind: "edge", lineStyle: "dashed", dashed: true },
  accessed: { label: "Runtime Access", color: EDGE_COLORS.serverToPackage, kind: "edge", lineStyle: "dashed", dashed: true },
};

function isLineageNodeType(value: unknown): value is LineageNodeType {
  return typeof value === "string" && value in NODE_TYPE_LEGEND_ITEMS;
}

export function legendItemsForVisibleNodes(
  nodes: Array<{ data?: unknown }>,
  extras: LegendItem[] = [],
): LegendItem[] {
  const visibleTypes = new Set<LineageNodeType>();
  for (const node of nodes) {
    const nodeType = (node.data as Partial<LineageNodeData> | undefined)?.nodeType;
    if (isLineageNodeType(nodeType)) {
      visibleTypes.add(nodeType);
    }
  }

  const items = NODE_TYPE_LEGEND_ORDER
    .filter((nodeType) => visibleTypes.has(nodeType))
    .map((nodeType) => NODE_TYPE_LEGEND_ITEMS[nodeType]);

  for (const extra of extras) {
    if (!items.some((item) => item.label === extra.label)) {
      items.push(extra);
    }
  }

  return items;
}

export function relationshipLegendItemsForVisibleEdges(edges: Array<{ data?: unknown }>): LegendItem[] {
  const visibleRelationships = new Set<string>();
  for (const edge of edges) {
    const relationship = (edge.data as { relationship?: unknown } | undefined)?.relationship;
    if (typeof relationship === "string" && relationship in RELATIONSHIP_LEGEND_ITEMS) {
      visibleRelationships.add(relationship);
    }
  }

  return RELATIONSHIP_LEGEND_ORDER
    .filter((relationship) => visibleRelationships.has(relationship))
    .map((relationship) => RELATIONSHIP_LEGEND_ITEMS[relationship]);
}

export function legendItemsForVisibleGraph(
  nodes: Array<{ data?: unknown }>,
  edges: Array<{ data?: unknown }>,
  extras: LegendItem[] = [],
): LegendItem[] {
  return legendItemsForVisibleNodes(nodes, [
    ...relationshipLegendItemsForVisibleEdges(edges),
    ...extras,
  ]);
}

export const STANDARD_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", kind: "node", shape: "dot" },
  { label: "Server", color: "#3b82f6", kind: "node", shape: "square" },
  { label: "Package", color: "#52525b", kind: "node", shape: "pill" },
  { label: "CVE", color: "#ef4444", kind: "node", shape: "diamond" },
  { label: "Cred", color: "#f59e0b", kind: "node", shape: "dot" },
  { label: "Tool", color: "#a855f7", kind: "node", shape: "pill" },
];

export const MESH_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", kind: "node", shape: "dot" },
  { label: "Shared", color: "#22d3ee", kind: "node", shape: "square" },
  { label: "Server", color: "#3b82f6", kind: "node", shape: "square" },
  { label: "Package", color: "#52525b", kind: "node", shape: "pill" },
  { label: "Vuln", color: "#ef4444", kind: "node", shape: "diamond" },
  { label: "Cred", color: "#f59e0b", kind: "node", shape: "dot" },
  { label: "Tool", color: "#a855f7", kind: "node", shape: "pill" },
];

export const CONTEXT_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", kind: "node", shape: "dot" },
  { label: "Shared", color: "#22d3ee", kind: "node", shape: "square" },
  { label: "Cred", color: "#f59e0b", kind: "node", shape: "dot" },
  { label: "Tool", color: "#a855f7", kind: "node", shape: "pill" },
  { label: "Vuln", color: "#ef4444", kind: "node", shape: "diamond" },
  { label: "Lateral", color: "#f97316", kind: "edge", dashed: true, lineStyle: "dashed", shape: "diamond" },
];
