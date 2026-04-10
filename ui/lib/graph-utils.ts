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
  dashed?: boolean;
  shape?: "dot" | "square" | "diamond" | "pill";
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
  provider: { label: "Provider", color: "#71717a", shape: "dot" },
  agent: { label: "Agent", color: "#10b981", shape: "dot" },
  sharedServer: { label: "Shared", color: "#22d3ee", shape: "square" },
  server: { label: "Server", color: "#3b82f6", shape: "square" },
  package: { label: "Package", color: "#52525b", shape: "pill" },
  model: { label: "Model", color: "#8b5cf6", shape: "pill" },
  dataset: { label: "Dataset", color: "#06b6d4", shape: "pill" },
  container: { label: "Container", color: "#6366f1", shape: "square" },
  cloudResource: { label: "Cloud", color: "#0ea5e9", shape: "square" },
  environment: { label: "Env", color: "#14b8a6", shape: "square" },
  fleet: { label: "Fleet", color: "#22d3ee", shape: "square" },
  cluster: { label: "Cluster", color: "#38bdf8", shape: "square" },
  user: { label: "User", color: "#34d399", shape: "dot" },
  group: { label: "Group", color: "#d946ef", shape: "pill" },
  serviceAccount: { label: "Svc", color: "#fbbf24", shape: "dot" },
  vulnerability: { label: "Vuln", color: "#ef4444", shape: "diamond" },
  misconfiguration: { label: "Config", color: "#f97316", shape: "diamond" },
  credential: { label: "Cred", color: "#f59e0b", shape: "dot" },
  tool: { label: "Tool", color: "#a855f7", shape: "pill" },
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

export const STANDARD_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", shape: "dot" },
  { label: "Server", color: "#3b82f6", shape: "square" },
  { label: "Package", color: "#52525b", shape: "pill" },
  { label: "CVE", color: "#ef4444", shape: "diamond" },
  { label: "Cred", color: "#f59e0b", shape: "dot" },
  { label: "Tool", color: "#a855f7", shape: "pill" },
];

export const MESH_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", shape: "dot" },
  { label: "Shared", color: "#22d3ee", shape: "square" },
  { label: "Server", color: "#3b82f6", shape: "square" },
  { label: "Package", color: "#52525b", shape: "pill" },
  { label: "Vuln", color: "#ef4444", shape: "diamond" },
  { label: "Cred", color: "#f59e0b", shape: "dot" },
  { label: "Tool", color: "#a855f7", shape: "pill" },
];

export const CONTEXT_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", shape: "dot" },
  { label: "Shared", color: "#22d3ee", shape: "square" },
  { label: "Cred", color: "#f59e0b", shape: "dot" },
  { label: "Tool", color: "#a855f7", shape: "pill" },
  { label: "Vuln", color: "#ef4444", shape: "diamond" },
  { label: "Lateral", color: "#f97316", dashed: true, shape: "diamond" },
];
