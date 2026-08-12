/**
 * Text equivalent of a canvas-rendered graph.
 *
 * Past the large-graph thresholds `/graph` swaps React Flow — whose nodes and
 * edges are real DOM with real labels — for the 2D canvas or the sigma/WebGL
 * stage. Both paint pixels, so assistive technology is left with the widget's
 * name and nothing about what is in it. This builds the same graph as text:
 * a census by node type and relationship, the most significant nodes, and the
 * connections between them.
 *
 * Counts are derived from the drawn model, never re-invented, and every
 * truncation is stated rather than applied silently — the overview is already
 * budgeted, and a text equivalent that implies it shows everything would be
 * less honest than the canvas it replaces.
 */

import type {
  LargeGraphEdge,
  LargeGraphNode,
  LargeGraphOverviewModel,
  LargeGraphOverviewSummary,
} from "@/lib/large-graph-overview";

export interface GraphTextRow {
  id: string;
  label: string;
  nodeType: string;
  severity: string;
  connections: number;
}

export interface GraphTextAlternativeModel {
  headline: string;
  nodeTypes: Array<{ nodeType: string; count: number }>;
  relationships: Array<{ relationship: string; count: number }>;
  rows: GraphTextRow[];
  rowsNote: string;
  connections: string[];
  connectionsNote: string;
}

export interface GraphTextAlternativeOptions {
  /** Nodes listed individually. Bounded so the hidden DOM stays cheap. */
  maxRows?: number | undefined;
  /** Connection sentences listed individually. */
  maxConnections?: number | undefined;
}

const DEFAULT_MAX_ROWS = 40;
const DEFAULT_MAX_CONNECTIONS = 30;

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

function severityRank(severity: string | undefined): number {
  const index = SEVERITY_ORDER.indexOf(
    String(severity ?? "").toLowerCase() as (typeof SEVERITY_ORDER)[number],
  );
  return index === -1 ? -1 : SEVERITY_ORDER.length - index;
}

function severityLabel(severity: string | undefined): string {
  const normalized = String(severity ?? "").toLowerCase();
  return SEVERITY_ORDER.includes(normalized as (typeof SEVERITY_ORDER)[number])
    ? normalized
    : "unrated";
}

/** `exposes_cred` reads as "exposes cred" when spoken aloud. */
function spoken(relationship: string): string {
  return relationship.replace(/[_-]+/g, " ").trim();
}

function census<T>(items: T[], key: (item: T) => string) {
  const counts = new Map<string, number>();
  for (const item of items) {
    const value = key(item);
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([value, count]) => ({ value, count }));
}

function connectionDegrees(edges: LargeGraphEdge[]): Map<string, number> {
  const degrees = new Map<string, number>();
  for (const edge of edges) {
    degrees.set(edge.source, (degrees.get(edge.source) ?? 0) + 1);
    degrees.set(edge.target, (degrees.get(edge.target) ?? 0) + 1);
  }
  return degrees;
}

export function buildGraphTextAlternative(
  model: LargeGraphOverviewModel,
  summary: LargeGraphOverviewSummary,
  options: GraphTextAlternativeOptions = {},
): GraphTextAlternativeModel {
  const maxRows = options.maxRows ?? DEFAULT_MAX_ROWS;
  const maxConnections = options.maxConnections ?? DEFAULT_MAX_CONNECTIONS;

  const visibleNodes = model.nodes.filter((node) => !node.hidden);
  const visibleEdges = model.edges.filter(
    (edge) => !edge.hidden && model.nodeById.has(edge.source) && model.nodeById.has(edge.target),
  );
  const degrees = connectionDegrees(visibleEdges);

  const ranked = [...visibleNodes].sort((left, right) => {
    const bySeverity = severityRank(right.severity) - severityRank(left.severity);
    if (bySeverity !== 0) return bySeverity;
    const byDegree = (degrees.get(right.id) ?? 0) - (degrees.get(left.id) ?? 0);
    if (byDegree !== 0) return byDegree;
    return left.label.localeCompare(right.label) || left.id.localeCompare(right.id);
  });

  const rows: GraphTextRow[] = ranked.slice(0, maxRows).map((node) => ({
    id: node.id,
    label: node.label,
    nodeType: node.nodeType,
    severity: severityLabel(node.severity),
    connections: degrees.get(node.id) ?? 0,
  }));

  const label = (id: string): string => model.nodeById.get(id)?.label ?? id;
  const rankedEdges = [...visibleEdges].sort((left, right) => {
    const byDegree =
      (degrees.get(right.source) ?? 0) + (degrees.get(right.target) ?? 0) -
      ((degrees.get(left.source) ?? 0) + (degrees.get(left.target) ?? 0));
    if (byDegree !== 0) return byDegree;
    return left.id.localeCompare(right.id);
  });
  const connections = rankedEdges
    .slice(0, maxConnections)
    .map((edge) => `${label(edge.source)} ${spoken(edge.relationship)} ${label(edge.target)}`);

  const drawn = `${model.nodes.length.toLocaleString()} nodes and ${model.edges.length.toLocaleString()} relationships`;
  const scope = `${summary.nodes.toLocaleString()} nodes and ${summary.edges.toLocaleString()} relationships`;
  const headline =
    summary.nodes === model.nodes.length && summary.edges === model.edges.length
      ? `Graph of ${scope}. ${summary.findings.toLocaleString()} findings, of which ${summary.criticalFindings.toLocaleString()} critical; ${summary.credentials.toLocaleString()} credentials and ${summary.tools.toLocaleString()} tools.`
      : `Graph of ${scope} in scope. The overview draws the highest-signal ${drawn}; ${model.omittedNodeCount.toLocaleString()} nodes and ${model.omittedEdgeCount.toLocaleString()} relationships are omitted from it. ${summary.findings.toLocaleString()} findings, of which ${summary.criticalFindings.toLocaleString()} critical; ${summary.credentials.toLocaleString()} credentials and ${summary.tools.toLocaleString()} tools.`;

  return {
    headline,
    nodeTypes: census(visibleNodes, (node: LargeGraphNode) => node.nodeType).map(
      ({ value, count }) => ({ nodeType: value, count }),
    ),
    relationships: census(visibleEdges, (edge: LargeGraphEdge) => edge.relationship).map(
      ({ value, count }) => ({ relationship: value, count }),
    ),
    rows,
    rowsNote: `Listing ${rows.length.toLocaleString()} of ${visibleNodes.length.toLocaleString()} drawn nodes, highest severity and most connected first.`,
    connections,
    connectionsNote: `Listing ${connections.length.toLocaleString()} of ${visibleEdges.length.toLocaleString()} drawn relationships, busiest first.`,
  };
}
