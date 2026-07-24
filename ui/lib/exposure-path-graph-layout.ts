import type { ExposureEntityRef, ExposureEntityRole, ExposurePath } from "@/lib/exposure-path";
import { GRAPH_ROLE_STYLE } from "@/lib/exposure-path-graph-style";

// Node sizing. Few nodes render at the full design size (never larger — a
// 2-node path must not balloon into two canvas-filling boxes). As the path
// grows the boxes shrink toward a readable floor so the whole board stays
// compact and no single node dominates the viewport.
export const MAX_NODE_WIDTH = 188;
export const MIN_NODE_WIDTH = 148;
export const MAX_NODE_HEIGHT = 92;
export const MIN_NODE_HEIGHT = 82;

const MARGIN_X = 28;
const MARGIN_Y = 30;
const COLUMN_GAP = 132;
// Path view is always a single horizontal kill-chain. Multi-row wrap made long
// paths look like a broken DAG (vertical connector + orphan stubs on narrow
// boards). Long chains collapse their middle instead — see `shouldCollapsePath`.

/**
 * Drawable board width at the widest desktop the app shell allows. The shell
 * caps content at `max-w-[1400px]` with `lg:px-8` (1400 - 2 x 32 = 1336 CSS px);
 * the command-center card spends 44px on `sm:p-5 sm:pl-6` and the board wrapper
 * another 24px on its `p-1` + `p-2` insets, leaving 1268px of board.
 */
export const FIT_REFERENCE_WIDTH = 1268;

/**
 * Smallest uniform down-scale the board may take before its text stops being
 * readable. The smallest text that carries meaning is the 11px relationship
 * label (the 9px role chip is redundant with node colour and the hover title),
 * and 10px is the smallest label size the design system ships — so 10/11 ≈ 0.9.
 */
export const MIN_READABLE_SCALE = 0.9;

/**
 * Widest natural board that still fits `FIT_REFERENCE_WIDTH` without pushing
 * text under `MIN_READABLE_SCALE`. Naively shrink-to-fitting an 11-hop board
 * (3004px) into the reference width is a 0.42 scale — ~5px hop labels — so
 * anything wider collapses its middle instead of scaling into illegibility.
 *
 * The budget is keyed to the reference width, not to the live container: the
 * board is rendered `width: 100%` with `max-width: fitWidth`, so a container
 * narrower than the reference (the exposure-path lens renders the card in a
 * ~740px master-detail column at 1440px) scales the board further down. That
 * still shows every visible hop where the previous fixed-width board clipped
 * them, and the List view stays the readable alternative in narrow columns.
 */
export const MAX_READABLE_BOARD_WIDTH = Math.floor(FIT_REFERENCE_WIDTH / MIN_READABLE_SCALE);

/** Synthetic node that stands in for the hops a collapsed board hides. */
export const COLLAPSED_HOPS_NODE_ID = "exposure-path:collapsed-hops";

/** Pinned entry hop + one summary node + pinned end hop. */
const COLLAPSED_NODE_COUNT = 3;

/** Hidden-hop kinds, most security-significant first. */
const HIDDEN_HOP_KIND_ORDER: ExposureEntityRole[] = [
  "credential",
  "tool",
  "finding",
  "package",
  "server",
  "agent",
  "environment",
  "cluster",
  "unknown",
];

const HIDDEN_HOP_KIND_LABEL: Record<ExposureEntityRole, [string, string]> = {
  credential: ["credential", "credentials"],
  tool: ["tool", "tools"],
  finding: ["finding", "findings"],
  package: ["package", "packages"],
  server: ["server", "servers"],
  agent: ["agent", "agents"],
  environment: ["environment", "environments"],
  cluster: ["cluster", "clusters"],
  unknown: ["entity", "entities"],
};

/** Kinds named on the summary node — two keeps the label inside one node box. */
const MAX_SUMMARY_KINDS = 2;

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

/** CSS-pixel width a single-row board of `hopCount` nodes needs at 1x. */
export function naturalBoardWidth(hopCount: number): number {
  if (hopCount <= 0) return MARGIN_X * 2;
  const { width } = nodeSizeForCount(hopCount);
  return MARGIN_X * 2 + hopCount * width + (hopCount - 1) * COLUMN_GAP;
}

/**
 * True when the chain is too wide to render whole at a readable scale. Collapsed
 * boards pin the entry and end hops and summarise the middle, so the security
 * payoff is named in the first frame instead of scrolling off it.
 */
export function shouldCollapsePath(hopCount: number): boolean {
  return hopCount > COLLAPSED_NODE_COUNT && naturalBoardWidth(hopCount) > MAX_READABLE_BOARD_WIDTH;
}

/**
 * Name what a collapsed middle hides, most security-significant kind first, so
 * the summary reads "3 credentials · 3 tools" rather than an opaque "+9 more".
 */
export function summarizeHiddenHops(hops: ExposureEntityRef[]): string {
  const counts = new Map<ExposureEntityRole, number>();
  for (const hop of hops) {
    const role = HIDDEN_HOP_KIND_LABEL[hop.role] ? hop.role : "unknown";
    counts.set(role, (counts.get(role) ?? 0) + 1);
  }
  return HIDDEN_HOP_KIND_ORDER.filter((role) => counts.has(role))
    .slice(0, MAX_SUMMARY_KINDS)
    .map((role) => {
      const count = counts.get(role) ?? 0;
      const [singular, plural] = HIDDEN_HOP_KIND_LABEL[role];
      return `${count} ${count === 1 ? singular : plural}`;
    })
    .join(" · ");
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
  /** Hops in the path, including any the collapsed board stands in for. */
  totalHopCount: number;
  /** True when the middle of the chain was replaced by the summary node. */
  collapsed: boolean;
  /** Hops the summary node stands in for; 0 when the whole chain is laid out. */
  hiddenHopCount: number;
  /** Kinds the summary node names, e.g. `3 credentials · 3 tools`. */
  hiddenHopSummary: string;
}

export interface BuildPathGraphLayoutOptions {
  /**
   * Lay out every hop at 1x and let the canvas scroll horizontally. Default
   * (`false`) collapses chains wider than `MAX_READABLE_BOARD_WIDTH`.
   */
  expanded?: boolean | undefined;
}

export function buildPathGraphLayout(
  path: ExposurePath,
  options: BuildPathGraphLayoutOptions = {},
): PathGraphLayout {
  const totalHopCount = path.hops.length;
  const collapsed = options.expanded !== true && shouldCollapsePath(totalHopCount);
  const hiddenHops = collapsed ? path.hops.slice(1, -1) : [];
  const hiddenHopSummary = summarizeHiddenHops(hiddenHops);
  const visibleHops: ExposureEntityRef[] = collapsed
    ? [
        path.hops[0]!,
        {
          id: COLLAPSED_HOPS_NODE_ID,
          label: `+${hiddenHops.length} hops hidden`,
          subtitle: hiddenHopSummary,
          role: "unknown",
        },
        path.hops[totalHopCount - 1]!,
      ]
    : path.hops;

  const count = visibleHops.length;
  const { width: nodeWidth, height: nodeHeight } = nodeSizeForCount(count);
  const pitchX = nodeWidth + COLUMN_GAP;

  // Single left-to-right row: hop N always sits to the right of hop N-1. A prior
  // 4-column wrap (and an earlier boustrophedon snake) made long demo paths look
  // disconnected — vertical wrap edges and ports that no longer matched the
  // visual order. Horizontal scroll keeps the kill-chain readable instead.
  const nodes: PathGraphNode[] = visibleHops.map((hop, index) => ({
    ...hop,
    x: MARGIN_X + index * pitchX,
    y: MARGIN_Y,
  }));

  // Auto-fit: the viewBox is the tight bounding box of every node plus a uniform
  // margin, so the rendered graph always frames its own content — a 1-hop path
  // is compact; a many-hop path grows horizontally and the canvas scrolls.
  const maxX = nodes.reduce((acc, node) => Math.max(acc, node.x + nodeWidth), nodeWidth);
  const maxY = nodes.reduce((acc, node) => Math.max(acc, node.y + nodeHeight), nodeHeight);
  const width = maxX + MARGIN_X;
  const height = maxY + MARGIN_Y;

  const edges: PathGraphEdge[] = nodes.slice(0, -1).map((source, index) => {
    const target = nodes[index + 1]!;
    const relationship = relationshipForPathStep(path, source.id, target.id, index);
    const control = Math.max(40, Math.abs(target.x - source.x) / 2);
    const startX = source.x + nodeWidth;
    const endX = target.x;
    const midY = source.y + nodeHeight / 2;
    const pathD = `M ${startX} ${midY} C ${startX + control} ${midY}, ${endX - control} ${midY}, ${endX} ${midY}`;
    const style = GRAPH_ROLE_STYLE[target.role] ?? GRAPH_ROLE_STYLE.unknown;
    return {
      id: `${source.id}->${target.id}`,
      path: pathD,
      stroke: style.stroke,
      label: truncateGraphText(relationship, 16),
      labelX: (startX + endX) / 2,
      labelY: midY,
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
    totalHopCount,
    collapsed,
    hiddenHopCount: hiddenHops.length,
    hiddenHopSummary,
  };
}

function relationshipForPathStep(path: ExposurePath, source: string, target: string, index: number): string {
  // An elided span asserts nothing about the relationships it hides.
  if (source === COLLAPSED_HOPS_NODE_ID || target === COLLAPSED_HOPS_NODE_ID) return "…";
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
  return value.length > maxLength ? `${value.slice(0, Math.max(1, maxLength - 1)).trimEnd()}…` : value;
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
    // Prefer a short whole-word line to splitting an entity name. Graph nodes
    // are labels, not prose; preserving identifiers is more important than
    // making both rows the same visual width.
    // Reject separators near the start (`a/very-long`): a one-character first
    // line is harder to scan than a clean split.
    const cut = breakpoint > 3 ? breakpoint + 1 : maxLineLength;
    lines.push(remaining.slice(0, cut).trim());
    remaining = remaining.slice(cut).trim();
  }

  return lines.length > 0 ? lines : [truncateGraphText(normalized, maxLineLength)];
}
