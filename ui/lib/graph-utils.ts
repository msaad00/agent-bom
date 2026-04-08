/**
 * Shared React Flow graph utilities — DRY constants for Controls, MiniMap, and
 * Background styling used across all graph views (Lineage, Mesh, Context, Attack Flow).
 */

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";

// ─── Shared Styling Constants ────────────────────────────────────────────────

export const CONTROLS_CLASS =
  "!bg-zinc-900/90 !border-zinc-700 !rounded-lg !backdrop-blur-sm [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300 [&>button:hover]:!bg-zinc-700";

export const MINIMAP_CLASS = "!bg-zinc-900/90 !border-zinc-700 !rounded-lg !backdrop-blur-sm";

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
}

export const STANDARD_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981" },
  { label: "Server", color: "#3b82f6" },
  { label: "Package", color: "#52525b" },
  { label: "CVE", color: "#ef4444" },
  { label: "Cred", color: "#f59e0b" },
  { label: "Tool", color: "#a855f7" },
];

export const MESH_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981" },
  { label: "Shared", color: "#22d3ee" },
  { label: "Server", color: "#3b82f6" },
  { label: "Package", color: "#52525b" },
  { label: "Vuln", color: "#ef4444" },
  { label: "Cred", color: "#f59e0b" },
  { label: "Tool", color: "#a855f7" },
];

export const CONTEXT_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981" },
  { label: "Shared", color: "#22d3ee" },
  { label: "Cred", color: "#f59e0b" },
  { label: "Tool", color: "#a855f7" },
  { label: "Vuln", color: "#ef4444" },
  { label: "Lateral", color: "#f97316", dashed: true },
];
