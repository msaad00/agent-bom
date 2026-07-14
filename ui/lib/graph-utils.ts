/**
 * Shared React Flow graph utilities — DRY constants for Controls, MiniMap, and
 * Background styling used across all graph views (Lineage, Mesh, Context, Attack Flow).
 */

import type {
  LineageNodeData,
  LineageNodeType,
} from "@/components/lineage-nodes";
import type { Edge } from "@xyflow/react";
import {
  GRAPH_EDGE_KIND_META,
  GRAPH_NODE_KIND_META,
  type GraphEdgeKindKey,
  type GraphNodeKindKey,
} from "@/lib/graph-schema";
import type { GraphChangeKind, GraphDiffResponse } from "@/lib/api-types";

// ─── Shared Styling Constants ────────────────────────────────────────────────

export const CONTROLS_CLASS =
  "!bg-[var(--surface)]/90 !border-[var(--border-subtle)] !rounded-lg !backdrop-blur-sm [&>button]:!bg-[var(--surface-elevated)] [&>button]:!border-[var(--border-subtle)] [&>button]:!text-[var(--text-secondary)] [&>button:hover]:!bg-[var(--surface-muted)]";

export const MINIMAP_CLASS =
  "!bg-[var(--surface)]/90 !border-[var(--border-subtle)] !rounded-lg !backdrop-blur-sm";
// React Flow forwards `bgColor` into an inline CSS custom property that its
// stylesheet resolves with `var()`, so a token reference here follows the
// light/dark toggle without any runtime JS (was a hardcoded near-black #09090b
// that rendered as a black panel on the light canvas).
export const MINIMAP_BG = "var(--surface)";
export const MINIMAP_MASK = "rgba(24,24,27,0.82)";

// Dot-grid tint. #1c1c1e sat one step off the page background, so the canvas
// read flat/dark; a lighter neutral makes the grid legible on both the dark
// surface and the light-theme canvas, giving the graph perceptible depth.
export const BACKGROUND_COLOR = "#3f4453";
export const BACKGROUND_GAP = 24;

const SHARED_SERVER_COLOR = "#22d3ee";

export const LINEAGE_NODE_GRAPH_KIND: Record<
  LineageNodeType,
  GraphNodeKindKey | null
> = {
  provider: "provider",
  agent: "agent",
  server: "server",
  sharedServer: "server",
  package: "package",
  vulnerability: "vulnerability",
  misconfiguration: "misconfiguration",
  credential: "credential",
  tool: "tool",
  model: "model",
  framework: "framework",
  dataset: "dataset",
  container: "container",
  cloudResource: "cloud_resource",
  org: "org",
  account: "account",
  user: "user",
  group: "group",
  role: "role",
  policy: "policy",
  serviceAccount: "service_account",
  servicePrincipal: "service_principal",
  federatedIdentity: "federated_identity",
  environment: "environment",
  fleet: "fleet",
  cluster: "cluster",
  managedIdentity: "managed_identity",
  accessGrant: "access_grant",
  accessPolicy: "access_policy",
  driftIncident: "drift_incident",
  dataStore: "data_store",
  directory: "directory",
  sourceFile: "source_file",
  configFile: "config_file",
};

function generatedMetaForNodeType(nodeType: LineageNodeType) {
  const kind = LINEAGE_NODE_GRAPH_KIND[nodeType];
  return kind ? GRAPH_NODE_KIND_META[kind] : null;
}

const UI_NODE_LEGEND_OVERRIDES: Partial<
  Record<LineageNodeType, Pick<LegendItem, "label" | "color" | "shape">>
> = {
  managedIdentity: {
    label: "Managed Identity",
    color: "#0891b2",
    shape: "dot",
  },
  accessGrant: { label: "Access Grant", color: "#ca8a04", shape: "diamond" },
  accessPolicy: { label: "Access Policy", color: "#a16207", shape: "diamond" },
  driftIncident: {
    label: "Drift Incident",
    color: "#fb923c",
    shape: "diamond",
  },
  dataStore: { label: "Data Store", color: "#0284c7", shape: "square" },
};

// ─── MiniMap Node Color Map ──────────────────────────────────────────────────

export const NODE_COLOR_MAP: Record<LineageNodeType, string> =
  Object.fromEntries(
    (Object.keys(LINEAGE_NODE_GRAPH_KIND) as LineageNodeType[]).map(
      (nodeType) => [
        nodeType,
        nodeType === "sharedServer"
          ? SHARED_SERVER_COLOR
          : (generatedMetaForNodeType(nodeType)?.color ?? "#52525b"),
      ],
    ),
  ) as Record<LineageNodeType, string>;

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
  layer?: string | undefined;
  description?: string | undefined;
  dashed?: boolean | undefined;
  kind?: "node" | "edge" | undefined;
  lineStyle?: "solid" | "dashed" | undefined;
  shape?: "dot" | "square" | "diamond" | "pill" | undefined;
  // Entity type drives the legend glyph from the same ENTITY_ICONS map the
  // node renderers use, so a legend row and its node always show one icon.
  nodeType?: LineageNodeType | undefined;
}

function legendShapeForGraphShape(shape: string): LegendItem["shape"] {
  switch (shape) {
    case "circle":
      return "dot";
    case "diamond":
    case "triangle":
      return "diamond";
    case "square":
      return "square";
    default:
      return "pill";
  }
}

const NODE_TYPE_LEGEND_ORDER: LineageNodeType[] = [
  "provider",
  "agent",
  "sharedServer",
  "server",
  "package",
  "directory",
  "configFile",
  "sourceFile",
  "model",
  "dataset",
  "container",
  "cloudResource",
  "dataStore",
  "environment",
  "fleet",
  "cluster",
  "org",
  "account",
  "user",
  "group",
  "role",
  "policy",
  "serviceAccount",
  "servicePrincipal",
  "federatedIdentity",
  "managedIdentity",
  "accessGrant",
  "accessPolicy",
  "vulnerability",
  "misconfiguration",
  "driftIncident",
  "credential",
  "tool",
];

export function legendItemForNodeType(nodeType: LineageNodeType): LegendItem {
  if (nodeType === "sharedServer") {
    return {
      label: "Shared Server",
      color: SHARED_SERVER_COLOR,
      layer: GRAPH_NODE_KIND_META.server.layer,
      kind: "node",
      shape: "square",
      nodeType: "sharedServer",
    };
  }

  const meta = generatedMetaForNodeType(nodeType);
  const override = UI_NODE_LEGEND_OVERRIDES[nodeType];
  return {
    label: override?.label ?? meta?.label ?? nodeType,
    color: override?.color ?? meta?.color ?? "#52525b",
    layer: meta?.layer,
    kind: "node",
    shape:
      override?.shape ?? (meta ? legendShapeForGraphShape(meta.shape) : "pill"),
    nodeType,
  };
}

const NODE_TYPE_LEGEND_ITEMS: Record<LineageNodeType, LegendItem> =
  Object.fromEntries(
    NODE_TYPE_LEGEND_ORDER.map((nodeType) => [
      nodeType,
      legendItemForNodeType(nodeType),
    ]),
  ) as Record<LineageNodeType, LegendItem>;

const RELATIONSHIP_LEGEND_ORDER = [
  "hosts",
  "uses",
  "depends_on",
  "provides_tool",
  "exposes_cred",
  "reaches_tool",
  "serves_model",
  "contains",
  "vulnerable_to",
  "affects",
  "exploitable_via",
  "remediates",
  "triggers",
  "shares_server",
  "shares_cred",
  "lateral_path",
  "authenticates_as",
  "scoped_to",
  "governs",
  "exhibits_drift",
  "assumes",
  "trusts",
  "attached",
  "inherits",
  "can_access",
  "cross_account_trust",
  "exposed_to",
  "stores",
  "has_permission",
  "invoked",
  "called",
  "accessed",
  "used_credential",
  "delegated_to",
] as const;

const DASHED_LEGEND_RELATIONSHIPS = new Set<string>([
  "exposes_cred",
  "reaches_tool",
  "shares_server",
  "shares_cred",
  "lateral_path",
  "exploitable_via",
  "exposed_to",
  "has_permission",
  "invoked",
  "called",
  "accessed",
  "used_credential",
  "delegated_to",
]);

const RELATIONSHIP_LABEL_OVERRIDES: Record<string, string> = {
  exposes_cred: "Exposes Credential",
  reaches_tool: "Credential Reaches Tool",
  vulnerable_to: "Has CVE",
  exploitable_via: "Exploitable Via",
  shares_cred: "Shares Credential",
  lateral_path: "Lateral Movement",
  authenticates_as: "Authenticates As",
  scoped_to: "Scoped To",
  exhibits_drift: "Exhibits Drift",
  can_access: "Can Access",
  cross_account_trust: "Cross-account Trust",
  exposed_to: "Exposed To",
  has_permission: "Has Permission",
  used_credential: "Used Credential",
  delegated_to: "Delegated To",
};

const RELATIONSHIP_DESCRIPTION_OVERRIDES: Record<string, string> = {
  exposes_cred:
    "Static evidence that a server can surface a credential or secret reference.",
  reaches_tool:
    "Credential or identity can reach a tool-capable execution boundary.",
  vulnerable_to: "Package or component is linked to a vulnerability finding.",
  exploitable_via:
    "Finding has a reachable exploit path through agent, MCP, tool, or identity context.",
  shares_server:
    "Multiple agents share an MCP server, creating a lateral movement choke point.",
  shares_cred: "Multiple agents or servers share credential material.",
  lateral_path:
    "Ranked traversal chain that connects source, tool/credential, and impacted target.",
  authenticates_as:
    "Agent can operate as a managed identity or service principal.",
  scoped_to:
    "Access grant is constrained to a resource, tool, or environment scope.",
  governs:
    "Policy or control applies to the connected identity, tool, or environment.",
  exhibits_drift:
    "Observed behavior or posture differs from expected governance state.",
  exposed_to: "Internet, account, or environment exposure reaches this asset.",
  stores: "Asset stores or indexes data that may be reachable from the path.",
  has_permission:
    "Identity has an effective permission on the connected resource.",
  invoked: "Runtime evidence that an agent invoked a server or tool.",
  called: "Runtime evidence of a concrete tool call.",
  accessed: "Runtime evidence that a tool or call accessed an asset.",
  used_credential: "Runtime evidence that credential material was used.",
  delegated_to:
    "Runtime delegation from one actor or tool boundary to another.",
};

function fallbackRelationshipLabel(relationship: string): string {
  return relationship
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function relationshipLegendItem(relationship: string): LegendItem {
  const meta = GRAPH_EDGE_KIND_META[relationship as GraphEdgeKindKey];
  const dashed = DASHED_LEGEND_RELATIONSHIPS.has(relationship);
  return {
    label:
      RELATIONSHIP_LABEL_OVERRIDES[relationship] ??
      meta?.label ??
      fallbackRelationshipLabel(relationship),
    color: meta?.color ?? "#52525b",
    layer: meta?.category,
    description: RELATIONSHIP_DESCRIPTION_OVERRIDES[relationship],
    kind: "edge",
    dashed,
    lineStyle: dashed ? "dashed" : "solid",
  };
}

const RELATIONSHIP_LEGEND_ITEMS: Record<
  (typeof RELATIONSHIP_LEGEND_ORDER)[number],
  LegendItem
> = Object.fromEntries(
  RELATIONSHIP_LEGEND_ORDER.map((relationship) => [
    relationship,
    relationshipLegendItem(relationship),
  ]),
) as Record<(typeof RELATIONSHIP_LEGEND_ORDER)[number], LegendItem>;

function isLineageNodeType(value: unknown): value is LineageNodeType {
  return typeof value === "string" && value in NODE_TYPE_LEGEND_ITEMS;
}

export function legendItemsForVisibleNodes(
  nodes: Array<{ data?: unknown }>,
  extras: LegendItem[] = [],
): LegendItem[] {
  const visibleTypes = new Set<LineageNodeType>();
  for (const node of nodes) {
    const nodeType = (node.data as Partial<LineageNodeData> | undefined)
      ?.nodeType;
    if (isLineageNodeType(nodeType)) {
      visibleTypes.add(nodeType);
    }
  }

  const items = NODE_TYPE_LEGEND_ORDER.filter((nodeType) =>
    visibleTypes.has(nodeType),
  ).map((nodeType) => NODE_TYPE_LEGEND_ITEMS[nodeType]);

  for (const extra of extras) {
    if (!items.some((item) => item.label === extra.label)) {
      items.push(extra);
    }
  }

  return items;
}

export function relationshipLegendItemsForVisibleEdges(
  edges: Array<{ data?: unknown }>,
): LegendItem[] {
  const visibleRelationships = new Set<string>();
  for (const edge of edges) {
    const relationship = (edge.data as { relationship?: unknown } | undefined)
      ?.relationship;
    if (
      typeof relationship === "string" &&
      relationship in RELATIONSHIP_LEGEND_ITEMS
    ) {
      visibleRelationships.add(relationship);
    }
  }

  return RELATIONSHIP_LEGEND_ORDER.filter((relationship) =>
    visibleRelationships.has(relationship),
  ).map((relationship) => RELATIONSHIP_LEGEND_ITEMS[relationship]);
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

const HIGH_SIGNAL_RELATIONSHIPS = new Set([
  "vulnerable_to",
  "exposes_cred",
  "shares_cred",
  "lateral_path",
  "exploitable_via",
  "accessed",
  "invoked",
]);

function numericStrokeWidth(edge: Edge, fallback = 1.4): number {
  const width = edge.style?.strokeWidth;
  return typeof width === "number" && Number.isFinite(width) ? width : fallback;
}

function edgeRelationship(edge: Edge): string {
  const relationship = (edge.data as { relationship?: unknown } | undefined)
    ?.relationship;
  return typeof relationship === "string" ? relationship : "";
}

export function readableGraphEdges(
  edges: Edge[],
  activeNodeIds?: Set<string> | null,
  options: {
    baseOpacity?: number;
    highSignalOpacity?: number;
    inactiveOpacity?: number;
    activeOpacity?: number;
    quietAnimation?: boolean;
    captureMode?: boolean;
  } = {},
): Edge[] {
  const {
    baseOpacity = 0.42,
    highSignalOpacity = 0.64,
    inactiveOpacity = 0.08,
    activeOpacity = 0.96,
    quietAnimation = true,
    captureMode = false,
  } = options;

  return edges.map((edge): Edge => {
    const relationship = edgeRelationship(edge);
    const highSignal = HIGH_SIGNAL_RELATIONSHIPS.has(relationship);
    const active = activeNodeIds
      ? activeNodeIds.has(edge.source) && activeNodeIds.has(edge.target)
      : false;
    const captureBaseOpacity = captureMode
      ? Math.max(baseOpacity, 0.42)
      : baseOpacity;
    const captureHighSignalOpacity = captureMode
      ? Math.max(highSignalOpacity, 0.68)
      : highSignalOpacity;
    const captureInactiveOpacity = captureMode
      ? Math.max(inactiveOpacity, 0.18)
      : inactiveOpacity;
    const opacity = activeNodeIds
      ? active
        ? activeOpacity
        : captureInactiveOpacity
      : highSignal
        ? captureHighSignalOpacity
        : captureBaseOpacity;
    const width = numericStrokeWidth(edge);

    return {
      ...edge,
      animated: captureMode
        ? false
        : quietAnimation
          ? Boolean(activeNodeIds && active && edge.animated)
          : Boolean(edge.animated),
      style: {
        ...edge.style,
        opacity,
        strokeWidth: active
          ? Math.max(width, captureMode ? 3 : 2.6)
          : captureMode
            ? Math.max(Math.min(width, highSignal ? 2.2 : 1.6), 1.25)
            : Math.max(Math.min(width, highSignal ? 2 : 1.5), 1),
      },
    };
  });
}

export const MESH_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", kind: "node", shape: "dot" },
  { label: "Shared", color: "#22d3ee", kind: "node", shape: "square" },
  { label: "Server", color: "#3b82f6", kind: "node", shape: "square" },
  { label: "Package", color: "#52525b", kind: "node", shape: "pill" },
  { label: "Vuln", color: "#ef4444", kind: "node", shape: "diamond" },
  { label: "Cred", color: "#f59e0b", kind: "node", shape: "dot" },
  { label: "Tool", color: "#a855f7", kind: "node", shape: "pill" },
];

// ─── Drift lens — snapshot change-kind helpers (#3192) ───────────────────────
//
// The graph diff API (/v1/graph/diff) classifies every node/edge between two
// snapshots as new / removed / changed. These helpers turn that response into
// a lookup the graph client can paint onto the rollup-default rendered graph
// without re-implementing the diff. Anything the diff does not mention is
// treated as `unchanged` (the stable estate).

export type ChangeKind = GraphChangeKind;

export interface ChangeKindMeta {
  label: string;
  color: string;
  description: string;
  ringClass: string;
}

export const CHANGE_KIND_ORDER: ChangeKind[] = [
  "new",
  "changed",
  "removed",
  "unchanged",
];

export const CHANGE_KIND_META: Record<ChangeKind, ChangeKindMeta> = {
  new: {
    label: "New",
    color: "#10b981",
    description: "Asset appeared since the compared snapshot.",
    ringClass: "drift-ring-new",
  },
  changed: {
    label: "Changed",
    color: "#f59e0b",
    description: "Asset persisted but its posture or metadata drifted.",
    ringClass: "drift-ring-changed",
  },
  removed: {
    label: "Removed",
    color: "#f43f5e",
    description: "Asset disappeared since the compared snapshot.",
    ringClass: "drift-ring-removed",
  },
  unchanged: {
    label: "Unchanged",
    color: "#52525b",
    description: "Asset is stable across both snapshots.",
    ringClass: "",
  },
};

export function edgeChangeKey(
  source: string,
  target: string,
  relationship: string,
): string {
  return `${source}|${target}|${relationship}`;
}

export interface DriftIndex {
  nodeKind: Map<string, ChangeKind>;
  edgeKind: Map<string, ChangeKind>;
  counts: Record<ChangeKind, number>;
  /** True when the diff surfaced at least one changed node or edge. */
  hasChanges: boolean;
  attributeDeltas: Map<string, import("@/lib/api-types").GraphAttributeDelta[]>;
}

const EMPTY_DRIFT_COUNTS = (): Record<ChangeKind, number> => ({
  new: 0,
  changed: 0,
  removed: 0,
  unchanged: 0,
});

export function buildDriftIndex(
  diff: GraphDiffResponse | null | undefined,
): DriftIndex {
  const nodeKind = new Map<string, ChangeKind>();
  const edgeKind = new Map<string, ChangeKind>();
  const counts = EMPTY_DRIFT_COUNTS();

  const index = diff?.change_kind_index;
  if (index) {
    for (const [id, kind] of Object.entries(index.nodes)) {
      nodeKind.set(id, kind);
      counts[kind] += 1;
    }
    for (const [key, kind] of Object.entries(index.edges)) {
      edgeKind.set(key, kind);
    }
  }

  const attributeDeltas = new Map<string, import("@/lib/api-types").GraphAttributeDelta[]>();
  if (diff?.attribute_deltas) {
    for (const [nodeId, deltas] of Object.entries(diff.attribute_deltas)) {
      if (deltas.length > 0) attributeDeltas.set(nodeId, deltas);
    }
  }

  return {
    nodeKind,
    edgeKind,
    counts,
    hasChanges: nodeKind.size > 0 || edgeKind.size > 0,
    attributeDeltas,
  };
}

export function driftAttributeSummaries(
  index: DriftIndex,
): string[] {
  const seen = new Set<string>();
  for (const deltas of index.attributeDeltas.values()) {
    for (const delta of deltas) {
      if (delta.summary) seen.add(delta.summary);
    }
  }
  return [...seen];
}

export function changeKindForNode(id: string, index: DriftIndex): ChangeKind {
  return index.nodeKind.get(id) ?? "unchanged";
}

export function changeKindForEdge(
  source: string,
  target: string,
  relationship: string,
  index: DriftIndex,
): ChangeKind {
  return (
    index.edgeKind.get(edgeChangeKey(source, target, relationship)) ??
    "unchanged"
  );
}

/** Legend rows for the drift lens, optionally annotated with live counts. */
export function driftLegendItems(
  counts?: Partial<Record<ChangeKind, number>>,
): LegendItem[] {
  return CHANGE_KIND_ORDER.map((kind) => {
    const meta = CHANGE_KIND_META[kind];
    const count = counts?.[kind];
    return {
      label: count !== undefined ? `${meta.label} · ${count}` : meta.label,
      color: meta.color,
      description: meta.description,
      kind: "node",
      shape: "dot",
    };
  });
}

export const CONTEXT_LEGEND: LegendItem[] = [
  { label: "Agent", color: "#10b981", kind: "node", shape: "dot" },
  { label: "Shared", color: "#22d3ee", kind: "node", shape: "square" },
  { label: "Cred", color: "#f59e0b", kind: "node", shape: "dot" },
  { label: "Tool", color: "#a855f7", kind: "node", shape: "pill" },
  { label: "Vuln", color: "#ef4444", kind: "node", shape: "diamond" },
  {
    label: "Lateral",
    color: "#f97316",
    kind: "edge",
    dashed: true,
    lineStyle: "dashed",
    shape: "diamond",
  },
];
