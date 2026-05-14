import {
  LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
  LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
} from "@/lib/large-graph-overview";

export type GraphRendererKind = "react-flow" | "large-overview" | "webgl";

export interface GraphRendererDecisionInput {
  nodeCount: number;
  edgeCount: number;
  captureMode?: boolean | undefined;
  selectedAttackPath?: boolean | undefined;
  reachabilityActive?: boolean | undefined;
  graphOnlyFindings?: boolean | undefined;
  webglEnabled?: boolean | undefined;
}

export interface GraphRendererDecision {
  kind: GraphRendererKind;
  reason: string;
  interactive: boolean;
  supportsInvestigation: boolean;
}

export function decideGraphRenderer({
  nodeCount,
  edgeCount,
  captureMode = false,
  selectedAttackPath = false,
  reachabilityActive = false,
  graphOnlyFindings = false,
  webglEnabled = false,
}: GraphRendererDecisionInput): GraphRendererDecision {
  if (captureMode) {
    return {
      kind: "react-flow",
      reason: "capture-mode",
      interactive: true,
      supportsInvestigation: true,
    };
  }
  if (selectedAttackPath) {
    return {
      kind: "react-flow",
      reason: "attack-path-focus",
      interactive: true,
      supportsInvestigation: true,
    };
  }
  if (reachabilityActive) {
    return {
      kind: "react-flow",
      reason: "reachability-drill-in",
      interactive: true,
      supportsInvestigation: true,
    };
  }
  if (graphOnlyFindings) {
    return {
      kind: "react-flow",
      reason: "findings-only-fallback",
      interactive: true,
      supportsInvestigation: true,
    };
  }

  const broadGraph =
    nodeCount >= LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD ||
    edgeCount >= LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD;
  if (broadGraph && webglEnabled) {
    return {
      kind: "webgl",
      reason: "large-graph-webgl-enabled",
      interactive: true,
      supportsInvestigation: false,
    };
  }
  if (broadGraph) {
    return {
      kind: "large-overview",
      reason: "large-graph-overview-threshold",
      interactive: true,
      supportsInvestigation: false,
    };
  }

  return {
    kind: "react-flow",
    reason: "focused-interactive-graph",
    interactive: true,
    supportsInvestigation: true,
  };
}
