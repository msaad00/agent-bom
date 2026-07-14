import type { ExposurePath } from "@/lib/exposure-path";
import { GRAPH_ROLE_STYLE } from "@/lib/exposure-path-graph-style";

// Node sizing. Few nodes render at the full design size (never larger — a
// 2-node path must not balloon into two canvas-filling boxes). As the path
// grows the boxes shrink toward a readable floor so the whole board stays
// compact and no single node dominates the viewport.
export const MAX_NODE_WIDTH = 188;
export const MIN_NODE_WIDTH = 148;
export const MAX_NODE_HEIGHT = 76;
export const MIN_NODE_HEIGHT = 62;

const MARGIN_X = 28;
const MARGIN_Y = 30;
const COLUMN_GAP = 132;
const ROW_GAP_EXTRA = 40; // vertical clear channel between wrapped rows
const MAX_COLUMNS = 4;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * Node box size for a path of `count` hops. Interpolates from the full design
 * size (<= 3 nodes) down to a readable floor (>= 9 nodes) so denser paths scale
 * down instead of overflowing. Monotonically non-increasing in `count`.
 */
export function nodeSizeForCount(count: number): { width: number; height: number } {
  const t = clamp((count - 3) / 6, 0, 1);
  return {
    width: Math.round(MAX_NODE_WIDTH - t * (MAX_NODE_WIDTH - MIN_NODE_WIDTH)),
    height: Math.round(MAX_NODE_HEIGHT - t * (MAX_NODE_HEIGHT - MIN_NODE_HEIGHT)),
  };
}

/** Characters per label line, scaled so text stays readable as nodes shrink. */
export function labelCharsForWidth(nodeWidth: number): number {
  return Math.max(12, Math.floor((nodeWidth - 28) / 8));
}

export type PathGraphNode = ExposurePath["hops"][number] & {
  x: number;
  y: number;
};

export interface PathGraphEdge {
  id: string;
  path: string;
  stroke: string;
  label: string;
  labelX: number;
  labelY: number;
}

export interface PathGraphLayout {
  width: number;
  height: number;
  /**
   * Natural (1x) CSS pixel width of the board. The SVG is capped at this width
   * so a small graph renders compact and centred rather than being stretched to
   * fill the canvas; larger boards still shrink-to-fit via `width: 100%`.
   */
  fitWidth: number;
  nodeWidth: number;
  nodeHeight: number;
  labelChars: number;
  nodes: PathGraphNode[];
  edges: PathGraphEdge[];
  relationshipLabels: { id: string; text: string; x: number; y: number; width: number }[];
}

export function buildPathGraphLayout(path: ExposurePath): PathGraphLayout {
  const count = path.hops.length;
  const { width: nodeWidth, height: nodeHeight } = nodeSizeForCount(count);
  const columns = Math.min(MAX_COLUMNS, Math.max(1, count));
  const pitchX = nodeWidth + COLUMN_GAP;
  const rowGap = nodeHeight + ROW_GAP_EXTRA;

  const nodes: PathGraphNode[] = path.hops.map((hop, index) => {
    const row = Math.floor(index / columns);
    const col = index % columns;
    // Boustrophedon rows so a wrapped path reads left-to-right, then back.
    const visualCol = row % 2 === 0 ? col : columns - 1 - col;
    return {
      ...hop,
      x: MARGIN_X + visualCol * pitchX,
      y: MARGIN_Y + row * rowGap,
    };
  });

  // Auto-fit: the viewBox is the tight bounding box of every node plus a uniform
  // margin, so the rendered graph always frames its own content — a 1-hop path
  // is compact, a many-hop path scales down to fit, nothing overflows.
  const maxX = nodes.reduce((acc, node) => Math.max(acc, node.x + nodeWidth), nodeWidth);
  const maxY = nodes.reduce((acc, node) => Math.max(acc, node.y + nodeHeight), nodeHeight);
  const width = maxX + MARGIN_X;
  const height = maxY + MARGIN_Y;

  const edges: PathGraphEdge[] = nodes.slice(0, -1).map((source, index) => {
    const target = nodes[index + 1]!;
    const relationship = relationshipForPathStep(path, source.id, target.id, index);
    const startX = source.x + nodeWidth;
    const startY = source.y + nodeHeight / 2;
    const endX = target.x;
    const endY = target.y + nodeHeight / 2;
    const sameRow = Math.abs(startY - endY) < 10;
    const control = sameRow ? Math.max(40, Math.abs(endX - startX) / 2) : 56;
    const pathD = sameRow
      ? `M ${startX} ${startY} C ${startX + control} ${startY}, ${endX - control} ${endY}, ${endX} ${endY}`
      : `M ${source.x + nodeWidth / 2} ${source.y + nodeHeight} C ${source.x + nodeWidth / 2} ${source.y + nodeHeight + control}, ${target.x + nodeWidth / 2} ${target.y - control}, ${target.x + nodeWidth / 2} ${target.y}`;
    const style = GRAPH_ROLE_STYLE[target.role] ?? GRAPH_ROLE_STYLE.unknown;
    return {
      id: `${source.id}->${target.id}`,
      path: pathD,
      stroke: style.stroke,
      label: truncateGraphText(relationship, 16),
      labelX: sameRow ? (startX + endX) / 2 : source.x + nodeWidth / 2,
      labelY: sameRow ? startY : (source.y + nodeHeight + target.y) / 2,
    };
  });

  const relationshipLabels = edges.map((edge) => ({
    id: `${edge.id}:label`,
    text: edge.label,
    x: edge.labelX,
    y: edge.labelY,
    width: Math.max(50, Math.round(edge.label.length * 6.6 + 22)),
  }));

  return {
    width,
    height,
    fitWidth: width,
    nodeWidth,
    nodeHeight,
    labelChars: labelCharsForWidth(nodeWidth),
    nodes,
    edges,
    relationshipLabels,
  };
}

function relationshipForPathStep(path: ExposurePath, source: string, target: string, index: number): string {
  const byEndpoints = path.relationships.find(
    (relationship) => relationship.source === source && relationship.target === target,
  );
  const raw = byEndpoints?.relationship ?? path.relationships[index]?.relationship ?? "reaches";
  return humanizeRelationship(raw);
}

export function humanizeRelationship(value: string): string {
  return value
    .replace(/[_:]+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function truncateGraphText(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, Math.max(1, maxLength - 1))}…` : value;
}

export function wrapGraphText(value: string, maxLineLength: number, maxLines: number): string[] {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLineLength) return [normalized];

  const lines: string[] = [];
  let remaining = normalized;
  while (remaining.length > 0 && lines.length < maxLines) {
    const isLastLine = lines.length === maxLines - 1;
    if (remaining.length <= maxLineLength) {
      lines.push(remaining);
      break;
    }
    if (isLastLine) {
      lines.push(truncateGraphText(remaining, maxLineLength));
      break;
    }

    const window = remaining.slice(0, maxLineLength + 1);
    const breakpoints = [" ", "-", "_", "/", ":", "@", "."].map((character) => window.lastIndexOf(character));
    const breakpoint = Math.max(...breakpoints);
    const cut = breakpoint >= Math.floor(maxLineLength * 0.45) ? breakpoint + 1 : maxLineLength;
    lines.push(remaining.slice(0, cut).trim());
    remaining = remaining.slice(cut).trim();
  }

  return lines.length > 0 ? lines : [truncateGraphText(normalized, maxLineLength)];
}
