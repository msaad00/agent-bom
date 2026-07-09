"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  Background,
  Controls,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AlertTriangle, Layers, Loader2, Radar, Route, ShieldAlert } from "lucide-react";

import { AttackPathCard } from "@/components/attack-path-card";
import { GraphEvaluationSummary } from "@/components/graph-evaluation-summary";
import {
  GraphEvidenceExportButton,
  GraphLegend,
  FullscreenButton,
} from "@/components/graph-chrome";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { LargeGraphOverview } from "@/components/large-graph-overview";
import { LineageDetailPanel } from "@/components/lineage-detail";
import {
  GraphEmptyState,
  GraphFindingsFallback,
  GraphPanelSkeleton,
  GraphRefreshOverlay,
} from "@/components/graph-state-panels";
import {
  FilterPanel,
  ASSET_DRIFT_GRAPH_SCOPE_PARAM,
  DEFAULT_FILTERS,
  createAssetLifecycleDriftGraphFilters,
  createExpandedGraphFilters,
  createFocusedGraphFilters,
  createImmediateGraphFilters,
  graphScopeLabelForFilters,
  graphScopePresetForFilters,
  type FilterState,
} from "@/components/lineage-filter";
import {
  lineageNodeTypesAdaptive,
  type LineageNodeData,
  type LineageNodeType,
} from "@/components/lineage-nodes";
import { useGraphLayout } from "@/lib/use-graph-layout";
import { effectiveLodBandForGraph, useLodBand } from "@/lib/lod-renderer";
import {
  aggregateSiblings,
  EXPANDED_AGGREGATION_THRESHOLD,
  FOCUSED_AGGREGATION_THRESHOLD,
  isClusterPillNode,
} from "@/lib/sibling-aggregator";
import {
  EntityType,
  RelationshipType,
  type UnifiedNode,
} from "@/lib/graph-schema";
import {
  attackPathKey,
  decodeGraphInvestigationParams,
  toAttackCardNodes,
  type GraphInvestigationRequest,
} from "@/lib/attack-paths";
import {
  BACKGROUND_COLOR,
  BACKGROUND_GAP,
  buildDriftIndex,
  driftAttributeSummaries,
  changeKindForEdge,
  changeKindForNode,
  CHANGE_KIND_META,
  CONTROLS_CLASS,
  legendItemsForVisibleGraph,
  MINIMAP_BG,
  MINIMAP_CLASS,
  MINIMAP_MASK,
  minimapNodeColor,
  readableGraphEdges,
  type ChangeKind,
} from "@/lib/graph-utils";
import {
  graphFitViewOptions,
  shouldShowGraphMiniMap,
} from "@/lib/graph-viewport";
import {
  prettifyReachabilityType,
  summarizeReachability,
  type ReachabilitySummary,
} from "@/lib/graph-reachability";
import { evaluateGraphUx } from "@/lib/graph-ux-evaluation";
import {
  api,
  type GraphDiffResponse,
  type GraphEdgeChangesResponse,
  type GraphNodeDetailResponse,
  type GraphQueryResponse,
  type GraphSnapshot,
  type UnifiedGraphResponse,
} from "@/lib/api";
import type { GraphRollupResponse } from "@/lib/api-types";
import { buildRollupFlowGraph } from "@/lib/graph-rollup-view";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import {
  LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
  LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
} from "@/lib/large-graph-overview";
import { decideGraphRenderer } from "@/lib/graph-renderer-switch";
import {
  graphRollupEligible,
  parseGraphRollupUrlPreference,
  parseRollupNodeParam,
  rollupViewHasContainers,
} from "@/lib/graph-rollup-default";
import {
  applyFilters,
  decodeFiltersFromParams,
  driftFilterPasses,
  encodeFiltersToParams,
  evidenceLensPasses,
  isCriticalChange,
  type DriftLensFilter,
  type EvidenceLensFilter,
} from "@/lib/filter-algebra";
import { useCaptureMode } from "@/lib/use-capture-mode";

const GraphDriftLegend = dynamic(
  () =>
    import("@/components/graph-drift-legend").then(
      (mod) => mod.GraphDriftLegend,
    ),
  { ssr: false },
);

const GraphEvidenceLegend = dynamic(
  () =>
    import("@/components/graph-evidence-legend").then(
      (mod) => mod.GraphEvidenceLegend,
    ),
  { ssr: false },
);

const GraphEdgeChangesPanel = dynamic(
  () =>
    import("@/components/graph-edge-changes-panel").then(
      (mod) => mod.GraphEdgeChangesPanel,
    ),
  { ssr: false },
);

const SigmaGraphOverview = dynamic(
  () =>
    import("@/components/sigma-graph-overview").then(
      (mod) => mod.SigmaGraphOverview,
    ),
  {
    ssr: false,
    loading: () => (
      <GraphPanelSkeleton
        title="Loading WebGL graph"
        detail="Preparing the Sigma renderer for the broad graph overview."
      />
    ),
  },
);

function PulseStyles() {
  return (
    <style jsx global>{`
      @keyframes pulse-critical {
        0%,
        100% {
          box-shadow: 0 0 6px rgba(239, 68, 68, 0.35);
        }
        50% {
          box-shadow: 0 0 12px rgba(239, 68, 68, 0.55);
        }
      }
      .node-critical-pulse {
        animation: none;
        box-shadow: 0 0 6px rgba(239, 68, 68, 0.28);
      }
      /* Stagger so a graph with many critical nodes does NOT strobe in
         sync — when ten or twenty nodes pulse together at the same
         phase the page reads as a flickering page-wide flash. The
         animation-delay buckets desync neighbours visually. */
      .node-critical-pulse:nth-child(3n) {
        animation-delay: -0.4s;
      }
      .node-critical-pulse:nth-child(3n + 1) {
        animation-delay: -1.2s;
      }
      .node-critical-pulse:nth-child(3n + 2) {
        animation-delay: -2s;
      }
      @media (prefers-reduced-motion: reduce) {
        .node-critical-pulse {
          animation: none;
          box-shadow: 0 0 6px rgba(239, 68, 68, 0.5);
        }
      }

      /* Focus-mode (#2257). Hovering or pinning a node fires CSS classes
         on the React Flow node wrapper so non-connected nodes fade out
         and the focused node gets a sky-blue glow. The transition is
         short enough to feel responsive but long enough to read as a
         deliberate dim, not a flicker. */
      .lineage-node-dim {
        opacity: 0.15;
        transition: opacity 0.2s ease;
      }
      .lineage-node-focus {
        box-shadow: 0 0 16px rgba(56, 189, 248, 0.6);
        transition: box-shadow 0.15s ease;
        z-index: 5;
      }

      /* Sibling-aggregation cluster pill pulses subtly to suggest
         "click me to expand". Honors prefers-reduced-motion. */
      @keyframes cluster-pill-pulse {
        0%,
        100% {
          box-shadow: 0 0 6px rgba(56, 189, 248, 0.35);
        }
        50% {
          box-shadow: 0 0 14px rgba(56, 189, 248, 0.65);
        }
      }
      .cluster-pill-pulse {
        animation: none;
        box-shadow: 0 0 8px rgba(56, 189, 248, 0.32);
      }
      @media (prefers-reduced-motion: reduce) {
        .cluster-pill-pulse {
          animation: none;
          box-shadow: 0 0 8px rgba(56, 189, 248, 0.45);
        }
      }
    `}</style>
  );
}

const FOCUS_NEIGHBORHOOD_DEPTH = 2;
const FOCUS_NEIGHBORHOOD_NODE_LIMIT = 80;

function getLocalNeighborhoodIds(
  nodeId: string,
  edges: Edge[],
  maxDepth = FOCUS_NEIGHBORHOOD_DEPTH,
  maxNodes = FOCUS_NEIGHBORHOOD_NODE_LIMIT,
): Set<string> {
  const adjacency = new Map<string, Set<string>>();
  for (const edge of edges) {
    addNeighbor(adjacency, edge.source, edge.target);
    addNeighbor(adjacency, edge.target, edge.source);
  }

  const visited = new Set<string>([nodeId]);
  const queue = [{ id: nodeId, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (current.depth >= maxDepth) continue;
    for (const neighbor of adjacency.get(current.id) ?? []) {
      if (visited.has(neighbor)) continue;
      visited.add(neighbor);
      if (visited.size >= maxNodes) return visited;
      queue.push({ id: neighbor, depth: current.depth + 1 });
    }
  }

  return visited;
}

function addNeighbor(
  map: Map<string, Set<string>>,
  source: string,
  target: string,
): void {
  const existing = map.get(source);
  if (existing) {
    existing.add(target);
  } else {
    map.set(source, new Set([target]));
  }
}

const LAYER_ENTITY_TYPES: Array<[LineageNodeType, EntityType]> = [
  ["provider", EntityType.PROVIDER],
  ["agent", EntityType.AGENT],
  ["user", EntityType.USER],
  ["group", EntityType.GROUP],
  ["serviceAccount", EntityType.SERVICE_ACCOUNT],
  ["environment", EntityType.ENVIRONMENT],
  ["fleet", EntityType.FLEET],
  ["cluster", EntityType.CLUSTER],
  ["server", EntityType.SERVER],
  ["package", EntityType.PACKAGE],
  ["model", EntityType.MODEL],
  ["dataset", EntityType.DATASET],
  ["container", EntityType.CONTAINER],
  ["cloudResource", EntityType.CLOUD_RESOURCE],
  ["vulnerability", EntityType.VULNERABILITY],
  ["misconfiguration", EntityType.MISCONFIGURATION],
  ["credential", EntityType.CREDENTIAL],
  ["tool", EntityType.TOOL],
  ["managedIdentity", EntityType.MANAGED_IDENTITY],
  ["accessGrant", EntityType.ACCESS_GRANT],
  ["accessPolicy", EntityType.ACCESS_POLICY],
  ["driftIncident", EntityType.DRIFT_INCIDENT],
  ["dataStore", EntityType.DATA_STORE],
  ["directory", EntityType.DIRECTORY],
  ["sourceFile", EntityType.SOURCE_FILE],
  ["configFile", EntityType.CONFIG_FILE],
];

const RELATIONSHIP_SCOPE_MAP: Record<
  FilterState["relationshipScope"],
  RelationshipType[] | undefined
> = {
  all: undefined,
  inventory: [
    RelationshipType.HOSTS,
    RelationshipType.USES,
    RelationshipType.DEPENDS_ON,
    RelationshipType.PROVIDES_TOOL,
    RelationshipType.EXPOSES_CRED,
    RelationshipType.REACHES_TOOL,
    RelationshipType.SERVES_MODEL,
    RelationshipType.CONTAINS,
  ],
  attack: [
    RelationshipType.AFFECTS,
    RelationshipType.VULNERABLE_TO,
    RelationshipType.EXPLOITABLE_VIA,
    RelationshipType.REMEDIATES,
    RelationshipType.TRIGGERS,
    RelationshipType.SHARES_SERVER,
    RelationshipType.SHARES_CRED,
    RelationshipType.LATERAL_PATH,
    RelationshipType.EXPLOITABLE_VIA,
    RelationshipType.EXPOSED_TO,
    RelationshipType.HAS_PERMISSION,
  ],
  runtime: [
    RelationshipType.INVOKED,
    RelationshipType.ACCESSED,
    RelationshipType.CALLED,
    RelationshipType.USED_CREDENTIAL,
    RelationshipType.DELEGATED_TO,
  ],
  governance: [
    RelationshipType.MANAGES,
    RelationshipType.OWNS,
    RelationshipType.PART_OF,
    RelationshipType.MEMBER_OF,
    RelationshipType.AUTHENTICATES_AS,
    RelationshipType.SCOPED_TO,
    RelationshipType.GOVERNS,
    RelationshipType.EXHIBITS_DRIFT,
    RelationshipType.ASSUMES,
    RelationshipType.TRUSTS,
    RelationshipType.ATTACHED,
    RelationshipType.INHERITS,
    RelationshipType.CAN_ACCESS,
    RelationshipType.CROSS_ACCOUNT_TRUST,
    RelationshipType.STORES,
    RelationshipType.HAS_PERMISSION,
  ],
};

function entityTypesForLayers(filters: FilterState): EntityType[] {
  return LAYER_ENTITY_TYPES.filter(([layer]) => filters.layers[layer]).map(
    ([, entityType]) => entityType,
  );
}

function emptyGraphResponse(scanId: string): UnifiedGraphResponse {
  return {
    scan_id: scanId,
    tenant_id: "",
    created_at: "",
    nodes: [],
    edges: [],
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: 0,
      total_edges: 0,
      node_types: {},
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
    pagination: {
      total: 0,
      offset: 0,
      limit: 0,
      has_more: false,
    },
  };
}

function lineageTypeForEntity(entityType: string): LineageNodeType {
  return (
    LAYER_ENTITY_TYPES.find(([, current]) => current === entityType)?.[0] ??
    "server"
  );
}

function stringAttribute(
  attributes: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = attributes?.[key];
  return typeof value === "string" ? value : undefined;
}

function versionProvenanceAttribute(
  attributes: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = attributes?.version_provenance;
  if (!value || typeof value !== "object" || Array.isArray(value))
    return undefined;
  const nested = (value as Record<string, unknown>)[key];
  return typeof nested === "string" ? nested : undefined;
}

function buildFallbackNodeData(node: UnifiedNode): LineageNodeData {
  const attributes = { ...(node.attributes ?? {}), node_id: node.id };
  return {
    label: node.label,
    nodeType: lineageTypeForEntity(String(node.entity_type)),
    entityType: String(node.entity_type),
    status: String(node.status ?? ""),
    riskScore: node.risk_score,
    severity: node.severity,
    firstSeen: node.first_seen,
    lastSeen: node.last_seen,
    dataSources: node.data_sources ?? [],
    complianceTags: node.compliance_tags ?? [],
    attributes,
    description:
      stringAttribute(attributes, "description") ||
      stringAttribute(attributes, "recommendation") ||
      stringAttribute(attributes, "framework") ||
      stringAttribute(attributes, "source"),
    version:
      stringAttribute(attributes, "version") ||
      stringAttribute(attributes, "hash"),
    ecosystem: stringAttribute(attributes, "ecosystem"),
    versionSource:
      versionProvenanceAttribute(attributes, "version_source") ||
      stringAttribute(attributes, "version_source"),
    versionConfidence:
      versionProvenanceAttribute(attributes, "confidence") ||
      stringAttribute(attributes, "version_confidence"),
    command:
      stringAttribute(attributes, "command") ||
      stringAttribute(attributes, "transport") ||
      stringAttribute(attributes, "url"),
    agentType: stringAttribute(attributes, "agent_type"),
    agentStatus: stringAttribute(attributes, "status"),
  };
}

function mergeNodeDetail(
  base: LineageNodeData,
  detail: GraphNodeDetailResponse,
): LineageNodeData {
  const mergedAttributes = {
    ...(base.attributes ?? {}),
    ...(detail.node.attributes ?? {}),
    node_id: detail.node.id,
  };
  return {
    ...base,
    entityType: String(detail.node.entity_type),
    status: String(detail.node.status ?? base.status ?? ""),
    riskScore: detail.node.risk_score ?? base.riskScore,
    severity: detail.node.severity || base.severity,
    firstSeen: detail.node.first_seen || base.firstSeen,
    lastSeen: detail.node.last_seen || base.lastSeen,
    dataSources: detail.node.data_sources?.length
      ? detail.node.data_sources
      : base.dataSources,
    complianceTags: detail.node.compliance_tags?.length
      ? detail.node.compliance_tags
      : base.complianceTags,
    attributes: mergedAttributes,
    neighborCount: detail.neighbors.length,
    sourceCount: detail.sources.length,
    incomingEdgeCount: detail.edges_in.length,
    outgoingEdgeCount: detail.edges_out.length,
    impactCount: detail.impact.affected_count,
    maxImpactDepth: detail.impact.max_depth_reached,
    impactByType: detail.impact.affected_by_type,
    description:
      base.description ||
      stringAttribute(mergedAttributes, "description") ||
      stringAttribute(mergedAttributes, "recommendation") ||
      stringAttribute(mergedAttributes, "framework") ||
      stringAttribute(mergedAttributes, "source"),
    version:
      base.version ||
      stringAttribute(mergedAttributes, "version") ||
      stringAttribute(mergedAttributes, "hash"),
    ecosystem: base.ecosystem || stringAttribute(mergedAttributes, "ecosystem"),
    versionSource:
      base.versionSource ||
      versionProvenanceAttribute(mergedAttributes, "version_source") ||
      stringAttribute(mergedAttributes, "version_source"),
    versionConfidence:
      base.versionConfidence ||
      versionProvenanceAttribute(mergedAttributes, "confidence") ||
      stringAttribute(mergedAttributes, "version_confidence"),
    command:
      base.command ||
      stringAttribute(mergedAttributes, "command") ||
      stringAttribute(mergedAttributes, "transport") ||
      stringAttribute(mergedAttributes, "url"),
    agentType:
      base.agentType || stringAttribute(mergedAttributes, "agent_type"),
    agentStatus:
      base.agentStatus || stringAttribute(mergedAttributes, "status"),
  };
}

function buildPathEdgeKeys(hops: string[]): Set<string> {
  const keys = new Set<string>();
  for (let index = 0; index < hops.length - 1; index += 1) {
    const source = hops[index];
    const target = hops[index + 1];
    keys.add(`${source}=>${target}`);
    keys.add(`${target}=>${source}`);
  }
  return keys;
}

function graphErrorState(message: string): {
  title: string;
  detail: string;
  suggestions: string[];
} {
  const lowered = message.toLowerCase();
  if (
    lowered.includes("budget") ||
    lowered.includes("limit") ||
    lowered.includes("too large")
  ) {
    return {
      title: "Graph query budget reached",
      detail: message,
      suggestions: [
        "Reduce depth or page size before retrying.",
        "Switch back to Relevant paths for operator triage.",
        "Narrow the graph by agent, severity, or relationship scope.",
      ],
    };
  }
  if (lowered.includes("timeout") || lowered.includes("timed out")) {
    return {
      title: "Graph query timed out",
      detail: message,
      suggestions: [
        "Retry with a smaller page size.",
        "Reduce max depth for the current graph window.",
        "Use search or selectors before expanding topology.",
      ],
    };
  }
  if (
    lowered.includes("permission") ||
    lowered.includes("tenant") ||
    lowered.includes("forbidden") ||
    lowered.includes("unauthorized")
  ) {
    return {
      title: "Graph is unavailable for this tenant or session",
      detail: message,
      suggestions: [
        "Confirm the selected tenant has access to this snapshot.",
        "Refresh the session before retrying.",
        "Use a snapshot generated by the current tenant.",
      ],
    };
  }
  return {
    title: "Graph query failed",
    detail: message,
    suggestions: [
      "Retry the request.",
      "Reduce the graph scope if the snapshot is large.",
      "Check API logs for the rejected query.",
    ],
  };
}

type InvestigationMode = {
  rootId: string;
  rootLabel: string;
  truncated: boolean;
  nodeCount: number;
  edgeCount: number;
};

function queryResponseToGraphResponse(
  response: GraphQueryResponse,
): UnifiedGraphResponse {
  return {
    scan_id: response.scan_id,
    tenant_id: response.tenant_id,
    created_at: response.created_at,
    nodes: response.nodes,
    edges: response.edges,
    attack_paths: response.attack_paths,
    interaction_risks: response.interaction_risks,
    stats: response.stats,
    pagination: {
      total: response.nodes.length,
      offset: 0,
      limit: response.nodes.length,
      has_more: false,
    },
  };
}

/**
 * Wrapper — supplies the xyflow store at the page root so `useLodBand`
 * (#2257) can read `viewport.zoom` from anywhere inside the page, not
 * just from a child of `<ReactFlow>`. Without the explicit provider the
 * page would have to thread the LOD band through props or duplicate
 * `<ReactFlow>` ancestry.
 */
/**
 * Blast-radius overlay state (audit/#3192). Populated from `/v1/graph/impact`
 * (reverse-BFS "what depends on this node"), it drives an on-canvas highlight of
 * every impacted node + edge so operators can see the real downstream cost of a
 * finding instead of only a count in the side panel.
 */
type BlastRadiusState = {
  rootId: string;
  rootLabel: string;
  nodeIds: Set<string>;
  countsByType: Record<string, number>;
  affectedCount: number;
  maxDepthReached: number;
};

type RollupBreadcrumb = {
  id: string;
  label: string;
};

export default function GraphPageClient() {
  return (
    <ReactFlowProvider>
      <GraphPageInner />
    </ReactFlowProvider>
  );
}

function GraphPageInner() {
  const reactFlow = useReactFlow();
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [graphData, setGraphData] = useState<UnifiedGraphResponse | null>(null);
  const [pageOffset, setPageOffset] = useState(0);
  const [loadingSnapshots, setLoadingSnapshots] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [graphDiff, setGraphDiff] = useState<GraphDiffResponse | null>(null);
  const [edgeChanges, setEdgeChanges] = useState<GraphEdgeChangesResponse | null>(
    null,
  );
  const [loadingEdgeChanges, setLoadingEdgeChanges] = useState(false);
  const [edgeChangesError, setEdgeChangesError] = useState<string | null>(null);
  const [driftLensActive, setDriftLensActive] = useState(false);
  const [driftFilter, setDriftFilter] = useState<DriftLensFilter>("all");
  const [evidenceLensActive, setEvidenceLensActive] = useState(false);
  const [evidenceFilter, setEvidenceFilter] =
    useState<EvidenceLensFilter>("all");
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(
    null,
  );
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedAttackPathKey, setSelectedAttackPathKey] = useState<
    string | null
  >(null);
  const [autoPathDismissed, setAutoPathDismissed] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UnifiedNode[]>([]);
  const [searching, setSearching] = useState(false);
  const [investigationMode, setInvestigationMode] =
    useState<InvestigationMode | null>(null);
  const [reachabilitySummary, setReachabilitySummary] =
    useState<ReachabilitySummary | null>(null);
  const loadingReachability = false;
  const [reachabilityError, setReachabilityError] = useState<string | null>(
    null,
  );
  const [blastRadius, setBlastRadius] = useState<BlastRadiusState | null>(null);
  const [loadingBlast, setLoadingBlast] = useState(false);
  const [blastError, setBlastError] = useState<string | null>(null);
  const [rollupView, setRollupView] = useState<GraphRollupResponse | null>(null);
  const [rollupStack, setRollupStack] = useState<RollupBreadcrumb[]>(() => {
    if (typeof window === "undefined") return [];
    const nodeId = parseRollupNodeParam(new URLSearchParams(window.location.search));
    return nodeId ? [{ id: nodeId, label: nodeId }] : [];
  });
  const [rollupDismissed, setRollupDismissed] = useState(
    () =>
      typeof window !== "undefined" &&
      parseGraphRollupUrlPreference(
        new URLSearchParams(window.location.search),
      ) === "off",
  );
  const [loadingRollup, setLoadingRollup] = useState(false);
  const [rollupError, setRollupError] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [pinnedFocusId, setPinnedFocusId] = useState<string | null>(null);
  const [expandedClusterIds, setExpandedClusterIds] = useState<Set<string>>(
    () => new Set(),
  );
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Seed filters from URL on first render so /graph?agent=...&severity=high
  // reproduces the exact view in another tab.
  const [filters, setFilters] = useState<FilterState>(() => {
    if (typeof window === "undefined") return DEFAULT_FILTERS;
    const params = new URLSearchParams(window.location.search);
    const baseline =
      params.get("scope") === ASSET_DRIFT_GRAPH_SCOPE_PARAM
        ? createAssetLifecycleDriftGraphFilters(params.get("agent"))
        : DEFAULT_FILTERS;
    return { ...baseline, ...decodeFiltersFromParams(params) };
  });
  const [initializedFocus, setInitializedFocus] = useState(false);
  // Track whether we've already seeded filters from the URL so the
  // auto-focus effect that picks the first agent doesn't clobber an
  // explicit ?agent= param on initial load.
  const seededFromUrlRef = useRef<boolean>(
    typeof window !== "undefined" &&
      new URLSearchParams(window.location.search).toString().length > 0,
  );
  const requestedScanIdRef = useRef<string>(
    typeof window !== "undefined"
      ? new URLSearchParams(window.location.search).get("scan") ||
          new URLSearchParams(window.location.search).get("scan_id") ||
          ""
      : "",
  );
  const requestedInvestigationRef = useRef<GraphInvestigationRequest | null>(
    typeof window !== "undefined"
      ? decodeGraphInvestigationParams(
          new URLSearchParams(window.location.search),
        )
      : null,
  );
  const rollupPreferenceRef = useRef(
    typeof window !== "undefined"
      ? parseGraphRollupUrlPreference(
          new URLSearchParams(window.location.search),
        )
      : ("default" as const),
  );
  const firstScanSelectionRef = useRef(true);
  // Last URL the filter→URL sync effect wrote, used to break an infinite
  // router.replace loop (see the sync effect below for the full rationale).
  const lastSyncedUrlRef = useRef<string | null>(null);
  const captureMode = useCaptureMode();

  useEffect(() => {
    setLoadingSnapshots(true);
    api
      .getGraphSnapshots(40)
      .then((items) => {
        setSnapshots(items);
        if (items.length > 0) {
          setSelectedScanId((current) => {
            if (current) return current;
            const requested = requestedScanIdRef.current;
            if (requested && items.some((item) => item.scan_id === requested)) {
              return requested;
            }
            return items[0]!.scan_id;
          });
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoadingSnapshots(false));
  }, []);

  const serverEntityTypes = useMemo(
    () => entityTypesForLayers(filters),
    [filters],
  );

  const serverRelationships = useMemo(
    () => RELATIONSHIP_SCOPE_MAP[filters.relationshipScope],
    [filters.relationshipScope],
  );

  const serverFilterKey = useMemo(
    () =>
      JSON.stringify({
        scanId: selectedScanId,
        entityTypes: serverEntityTypes,
        relationships: serverRelationships,
        runtimeMode: filters.runtimeMode,
        maxDepth: filters.maxDepth,
        severity: filters.severity,
        pageSize: filters.pageSize,
      }),
    [selectedScanId, serverEntityTypes, serverRelationships, filters],
  );

  useEffect(() => {
    setPageOffset(0);
    setExpandedClusterIds(new Set());
    setPinnedFocusId(null);
    setHoveredNodeId(null);
    setAutoPathDismissed(false);
    setReachabilitySummary(null);
    setReachabilityError(null);
  }, [serverFilterKey]);

  useEffect(() => {
    setSearchResults([]);
    setSearchQuery("");
    setSelectedAttackPathKey(null);
    setAutoPathDismissed(false);
    setInvestigationMode(null);
    setReachabilitySummary(null);
    setReachabilityError(null);
    setRollupView(null);
    setRollupStack([]);
    setRollupDismissed(false);
    setRollupError(null);
    if (firstScanSelectionRef.current) {
      firstScanSelectionRef.current = false;
      if (seededFromUrlRef.current) {
        setInitializedFocus(true);
        return;
      }
    }
    setFilters(DEFAULT_FILTERS);
    setInitializedFocus(false);
  }, [selectedScanId]);

  useEffect(() => {
    if (!selectedScanId) {
      setGraphData(null);
      return;
    }

    if (investigationMode || requestedInvestigationRef.current) return;

    if (serverEntityTypes.length === 0) {
      setGraphData(emptyGraphResponse(selectedScanId));
      setSelectedNode(null);
      setError(null);
      return;
    }

    let cancelled = false;
    setLoadingGraph(true);
    setSelectedNode(null);
    api
      .getGraph({
        scanId: selectedScanId,
        entityTypes: serverEntityTypes,
        minSeverity: filters.severity ?? undefined,
        relationships: serverRelationships,
        staticOnly: filters.runtimeMode === "static",
        dynamicOnly: filters.runtimeMode === "dynamic",
        maxDepth: filters.maxDepth,
        offset: pageOffset,
        limit: filters.pageSize,
      })
      .then((result) => {
        if (cancelled) return;
        setGraphData(result);
        setError(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e.message);
        setGraphData(null);
      })
      .finally(() => {
        if (!cancelled) setLoadingGraph(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    selectedScanId,
    serverEntityTypes,
    serverRelationships,
    filters.runtimeMode,
    filters.maxDepth,
    filters.severity,
    filters.pageSize,
    pageOffset,
    investigationMode,
  ]);

  const activeSnapshot = useMemo(
    () =>
      snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );
  const previousSnapshot = useMemo(() => {
    const index = snapshots.findIndex(
      (snapshot) => snapshot.scan_id === selectedScanId,
    );
    if (index < 0 || index + 1 >= snapshots.length) return null;
    return snapshots[index + 1];
  }, [snapshots, selectedScanId]);

  useEffect(() => {
    let cancelled = false;
    setGraphDiff(null);
    setDiffError(null);
    setEdgeChanges(null);
    setEdgeChangesError(null);
    if (!selectedScanId || !previousSnapshot) {
      setLoadingDiff(false);
      setLoadingEdgeChanges(false);
      return;
    }
    setLoadingDiff(true);
    setLoadingEdgeChanges(true);
    Promise.all([
      api.getGraphDiff(previousSnapshot.scan_id, selectedScanId),
      api.getGraphEdgeChanges(previousSnapshot.scan_id, selectedScanId),
    ])
      .then(([diffResult, edgeResult]) => {
        if (cancelled) return;
        setGraphDiff(diffResult);
        setEdgeChanges(edgeResult);
      })
      .catch((e: Error) => {
        if (cancelled) return;
        setDiffError(e.message);
        setEdgeChangesError(e.message);
      })
      .finally(() => {
        if (!cancelled) {
          setLoadingDiff(false);
          setLoadingEdgeChanges(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [previousSnapshot, selectedScanId]);

  useEffect(() => {
    if (!selectedNodeId || !selectedScanId) return;
    let cancelled = false;
    api
      .getGraphNode(selectedNodeId, selectedScanId)
      .then((detail) => {
        if (cancelled) return;
        setSelectedNode((current) => {
          const currentId = current?.attributes?.node_id;
          if (currentId && currentId !== selectedNodeId) return current;
          if (!current) return buildFallbackNodeData(detail.node);
          return mergeNodeDetail(current, detail);
        });
      })
      .catch(() => {
        // Keep the lightweight node view if enrichment fails.
      });

    return () => {
      cancelled = true;
    };
  }, [selectedNodeId, selectedScanId]);

  const graphNodeById = useMemo(
    () => new Map((graphData?.nodes ?? []).map((node) => [node.id, node])),
    [graphData?.nodes],
  );
  const activeScopePreset = graphScopePresetForFilters(filters);

  const attackPaths = useMemo(
    () =>
      [...(graphData?.attack_paths ?? [])].sort(
        (left, right) =>
          right.composite_risk - left.composite_risk ||
          right.hops.length - left.hops.length,
      ),
    [graphData?.attack_paths],
  );

  const effectiveSelectedAttackPathKey =
    selectedAttackPathKey ??
    (!autoPathDismissed && activeScopePreset !== "expanded" && attackPaths[0]
      ? attackPathKey(attackPaths[0])
      : null);

  const selectedAttackPath = useMemo(
    () =>
      effectiveSelectedAttackPathKey
        ? (attackPaths.find(
            (path) => attackPathKey(path) === effectiveSelectedAttackPathKey,
          ) ?? null)
        : null,
    [attackPaths, effectiveSelectedAttackPathKey],
  );

  useEffect(() => {
    if (!selectedAttackPathKey) return;
    if (
      !attackPaths.some((path) => attackPathKey(path) === selectedAttackPathKey)
    ) {
      setSelectedAttackPathKey(null);
    }
  }, [attackPaths, selectedAttackPathKey]);

  const estateNodeCount =
    activeSnapshot?.node_count ??
    rollupView?.summary.total_nodes ??
    graphData?.nodes.length ??
    0;

  const rollupEligible = graphRollupEligible({
    hasSelectedScan: Boolean(selectedScanId),
    rollupPreference: rollupPreferenceRef.current,
    rollupDismissed,
    investigationMode: Boolean(investigationMode),
    selectedAttackPath: Boolean(selectedAttackPath),
    reachabilityActive: Boolean(reachabilitySummary),
    blastRadiusActive: Boolean(blastRadius),
  });

  const rollupNavigationActive =
    rollupEligible && !rollupDismissed && rollupView !== null;

  useEffect(() => {
    if (!selectedScanId || !rollupEligible || rollupDismissed) {
      return;
    }

    let cancelled = false;
    setLoadingRollup(true);
    setRollupError(null);
    const drillNode = rollupStack.at(-1)?.id;

    api
      .getGraphRollup(selectedScanId, {
        ...(drillNode ? { node: drillNode } : {}),
        ...(filters.severity ? { minSeverity: filters.severity } : {}),
      })
      .then((result) => {
        if (cancelled) return;
        if (
          !rollupViewHasContainers(
            result.mode,
            result.top_level,
            result.children,
          )
        ) {
          setRollupDismissed(true);
          setRollupView(null);
          setRollupError(null);
          return;
        }
        setRollupView(result);
        setRollupError(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setRollupError(e.message);
        setRollupView(null);
      })
      .finally(() => {
        if (!cancelled) setLoadingRollup(false);
      });

    return () => {
      cancelled = true;
    };
  }, [
    selectedScanId,
    rollupEligible,
    rollupDismissed,
    rollupStack,
    filters.severity,
  ]);

  const flow = useMemo(() => {
    if (rollupNavigationActive && rollupView) {
      const items =
        rollupView.mode === "drilldown"
          ? (rollupView.children ?? [])
          : (rollupView.top_level ?? []);
      const rollupFlow = buildRollupFlowGraph(items);
      return {
        nodes: rollupFlow.nodes,
        edges: rollupFlow.edges,
        agentNames: [] as string[],
        legend: [] as ReturnType<typeof buildUnifiedFlowGraph>["legend"],
        summary: null as
          null | ReturnType<typeof buildUnifiedFlowGraph>["summary"],
      };
    }
    if (!graphData) {
      return {
        nodes: [],
        edges: [],
        agentNames: [],
        legend: [],
        summary: null as
          null | ReturnType<typeof buildUnifiedFlowGraph>["summary"],
      };
    }
    return buildUnifiedFlowGraph(graphData, filters);
  }, [
    graphData,
    filters,
    rollupNavigationActive,
    rollupView,
  ]);

  useEffect(() => {
    if (initializedFocus || flow.agentNames.length === 0) return;
    if (seededFromUrlRef.current) {
      // The user landed here with an explicit URL — respect it instead of
      // overriding agentName with the first agent in the snapshot.
      setInitializedFocus(true);
      return;
    }
    setFilters(createFocusedGraphFilters(flow.agentNames[0]));
    setInitializedFocus(true);
  }, [flow.agentNames, initializedFocus]);

  // Push the current filter state into the URL (replace, not push) so a
  // copied address bar reproduces the view but back/forward isn't spammed.
  useEffect(() => {
    if (typeof window === "undefined") return;
    // Read preserved renderer flags from the live address bar rather than
    // useSearchParams(): on this page the filter/layout state churns rapidly
    // on load and useSearchParams() can lag or read empty across those
    // re-renders.
    const currentSearch = new URLSearchParams(window.location.search);
    const nextParams = encodeFiltersToParams(filters);
    if (selectedScanId) nextParams.set("scan", selectedScanId);
    if (currentSearch.get("renderer") === "webgl") {
      nextParams.set("renderer", "webgl");
    }
    if (currentSearch.get("webgl") === "1") {
      nextParams.set("webgl", "1");
    }
    const shareableInvestigation =
      investigationMode ?? requestedInvestigationRef.current;
    if (shareableInvestigation) {
      nextParams.set("investigate", "1");
      nextParams.set("root", shareableInvestigation.rootId);
      if (
        shareableInvestigation.rootLabel &&
        shareableInvestigation.rootLabel !== shareableInvestigation.rootId
      ) {
        nextParams.set("q", shareableInvestigation.rootLabel);
      }
    }
    if (activeScopePreset === "assetDrift") {
      nextParams.set("scope", ASSET_DRIFT_GRAPH_SCOPE_PARAM);
    }
    if (rollupDismissed) {
      nextParams.set("rollup", "0");
      nextParams.delete("rollup_node");
    } else if (rollupNavigationActive || rollupPreferenceRef.current === "force") {
      nextParams.set("rollup", "1");
      const drillNode = rollupStack.at(-1)?.id;
      if (drillNode) {
        nextParams.set("rollup_node", drillNode);
      } else {
        nextParams.delete("rollup_node");
      }
    } else {
      nextParams.delete("rollup");
      nextParams.delete("rollup_node");
    }
    const next = nextParams.toString();
    const url = next ? `${pathname}?${next}` : pathname;
    // Guard against an infinite navigation loop. router.replace() in the App
    // Router applies history/useSearchParams updates asynchronously through a
    // transition, so neither useSearchParams() nor window.location.search is
    // guaranteed to reflect the URL we just wrote by the time this effect
    // re-runs. Comparing against either one therefore never settled and
    // router.replace fired on every render (dozens of navigations/second),
    // which hung Playwright screenshots on "waiting for navigation to finish".
    // Remembering the last URL we synced breaks the loop regardless of when
    // the router catches up; a genuine filter change produces a new target.
    if (lastSyncedUrlRef.current === url) return;
    lastSyncedUrlRef.current = url;
    if (next === currentSearch.toString()) return;
    router.replace(url, { scroll: false });
  }, [
    activeScopePreset,
    filters,
    investigationMode,
    pathname,
    rollupDismissed,
    rollupNavigationActive,
    rollupStack,
    router,
    selectedScanId,
  ]);

  // Constraint propagation — recompute valid values whenever graph or
  // filters change. Cheap on focused snapshots, BFS-bounded on expanded.
  const filterAlgebra = useMemo(
    () => applyFilters(graphData, filters),
    [graphData, filters],
  );
  const validValues = filterAlgebra.validValues;

  const handleResetFilters = useCallback(() => {
    setFilters(createFocusedGraphFilters(flow.agentNames[0] ?? null));
  }, [flow.agentNames]);

  const flowNodeDataById = useMemo(
    () => new Map(flow.nodes.map((node) => [node.id, node.data])),
    [flow.nodes],
  );

  // Sibling aggregation (#2257). Threshold tracks the active filter
  // preset — operator triage (focused) collapses faster than topology
  // review (expanded). Run before layout so the layout engine never positions
  // siblings that the cluster pill is going to hide.
  const aggregationThreshold = selectedAttackPath
    ? Number.MAX_SAFE_INTEGER
    : filters.vulnOnly
      ? FOCUSED_AGGREGATION_THRESHOLD
      : EXPANDED_AGGREGATION_THRESHOLD;

  const aggregated = useMemo(
    () => {
      if (rollupNavigationActive) {
        return {
          nodes: flow.nodes,
          edges: flow.edges,
          clusters: new Map<
            string,
            {
              parentId: string;
              childType: LineageNodeType;
              members: string[];
            }
          >(),
        };
      }
      return aggregateSiblings(flow.nodes, flow.edges, {
        thresholdN: aggregationThreshold,
        expandedClusterIds: expandedClusterIds,
      });
    },
    [
      flow.nodes,
      flow.edges,
      aggregationThreshold,
      expandedClusterIds,
      rollupNavigationActive,
    ],
  );
  const aggregatedClusterNodes = useMemo(
    () =>
      aggregated.nodes.filter((node) =>
        isClusterPillNode(node as Node<LineageNodeData>),
      ),
    [aggregated.nodes],
  );
  const graphIdentityKey = useMemo(
    () =>
      JSON.stringify({
        nodes: flow.nodes.map((node) => node.id),
        edges: flow.edges.map(
          (edge) => `${edge.source}->${edge.target}:${edge.id}`,
        ),
      }),
    [flow.nodes, flow.edges],
  );

  useEffect(() => {
    setExpandedClusterIds(new Set());
    setPinnedFocusId(null);
    setHoveredNodeId(null);
  }, [graphIdentityKey]);

  // The unified security graph is DAG-shaped (provider/identity → agent →
  // server → tool/package → finding, and user → role → resource). A
  // left-to-right hierarchical layout reads as blast-radius flow and never
  // overlaps nodes; the force layout piled siblings on top of each other on
  // the broad estate view. Large graphs switch to the WebGL/overview
  // renderers upstream, so ReactFlow only ever lays out small/medium graphs
  // where dagre is the better fit.
  const graphLayoutKind = "dagre-lr";
  const { nodes: layoutNodes, edges: layoutEdges } = useGraphLayout(
    graphLayoutKind,
    aggregated.nodes,
    aggregated.edges,
    {
      force: {
        idealEdgeLength: filters.agentName ? 168 : 196,
        nodeRepulsion: filters.agentName ? 3600 : 4400,
        preservePinnedPositions: true,
      },
      dagreLr: {
        // Bigger node boxes + tighter ranks keep the wide left-to-right DAG from
        // collapsing into a thin, far-zoomed strip. The extra vertical nodeSep
        // spreads short graphs so fitView fills the canvas instead of leaving a
        // tall empty band above and below the topology.
        nodeWidth: 248,
        nodeHeight: 96,
        rankSep: filters.agentName ? 120 : 140,
        nodeSep: filters.agentName ? 64 : 78,
      },
    },
  );

  // Focus mode (#2257). The "active" focus is whichever the operator
  // pinned (click) — falling back to whatever is hovered. Pinning
  // survives until the operator clicks the empty pane or pins another
  // node. Hover never overrides a pin.
  const activeFocusId = pinnedFocusId ?? hoveredNodeId;
  const localNeighborhoodIds = useMemo(
    () =>
      activeFocusId
        ? getLocalNeighborhoodIds(activeFocusId, layoutEdges)
        : null,
    [activeFocusId, layoutEdges],
  );

  const attackPathNodeIds = useMemo(
    () => (selectedAttackPath ? new Set(selectedAttackPath.hops) : null),
    [selectedAttackPath],
  );

  const attackPathEdgeKeys = useMemo(
    () =>
      selectedAttackPath ? buildPathEdgeKeys(selectedAttackPath.hops) : null,
    [selectedAttackPath],
  );
  const attackPathNodeOrder = useMemo(
    () =>
      selectedAttackPath
        ? new Map(selectedAttackPath.hops.map((hop, index) => [hop, index]))
        : null,
    [selectedAttackPath],
  );

  /**
   * Compose the existing className (e.g. `node-critical-pulse`) with the
   * focus-mode classes the issue spec asked for. We keep the data-driven
   * `dimmed`/`highlighted` flags too — node renderers were already wired
   * to those — so dimming works in unit tests that read `data.dimmed`
   * directly.
   */
  const composeFocusClass = (
    base: string | undefined,
    focused: boolean,
    dimmed: boolean,
  ): string =>
    [
      base,
      focused ? "lineage-node-focus" : "",
      dimmed ? "lineage-node-dim" : "",
    ]
      .filter(Boolean)
      .join(" ") || "";

  // Levels-of-detail (#2257). Hook reads `viewport.zoom` from the
  // xyflow store provided by the wrapping `<ReactFlowProvider>` and
  // returns "cluster" | "summary" | "detail". The chosen render band
  // keeps dense graphs readable without changing node positions or data.
  const lodBand = useLodBand();
  const effectiveLodBand = effectiveLodBandForGraph(lodBand, {
    sourceNodeCount: flow.nodes.length,
    renderedNodeCount: aggregated.nodes.length,
    clusterCount: aggregated.clusters.size,
  });

  const lineageLayoutNodes = layoutNodes as Node<LineageNodeData>[];
  const canvasLayoutNodes = rollupNavigationActive
    ? (aggregated.nodes as Node<LineageNodeData>[])
    : lineageLayoutNodes;
  const baseDisplayNodes = useMemo<Node<LineageNodeData>[]>(() => {
    if (blastRadius) {
      return canvasLayoutNodes.map((node) => {
        const inBlast = blastRadius.nodeIds.has(node.id);
        const isRoot = node.id === blastRadius.rootId;
        return {
          ...node,
          className: composeFocusClass(node.className, isRoot, !inBlast),
          data: {
            ...node.data,
            renderBand: effectiveLodBand,
            dimmed: !inBlast,
            highlighted: inBlast,
          },
        };
      });
    }
    if (attackPathNodeIds) {
      return canvasLayoutNodes
        .filter((node) => attackPathNodeIds.has(node.id))
        .map((node) => {
          const inPath = attackPathNodeIds.has(node.id);
          const order = attackPathNodeOrder?.get(node.id) ?? 0;
          return {
            ...node,
            position: {
              x: order * 255,
              y: order % 2 === 0 ? 0 : 96,
            },
            className: composeFocusClass(node.className, inPath, !inPath),
            data: {
              ...node.data,
              renderBand: effectiveLodBand,
              dimmed: !inPath,
              highlighted: inPath,
            },
          };
        });
    }
    if (reachabilitySummary) {
      return canvasLayoutNodes.map((node) => {
        const inReach = reachabilitySummary.nodeIds.has(node.id);
        const isRoot = node.id === reachabilitySummary.rootId;
        return {
          ...node,
          className: composeFocusClass(node.className, isRoot, !inReach),
          data: {
            ...node.data,
            renderBand: effectiveLodBand,
            dimmed: !inReach,
            highlighted: inReach,
          },
        };
      });
    }
    if (!localNeighborhoodIds) {
      return canvasLayoutNodes.map((node) => ({
        ...node,
        data: {
          ...node.data,
          renderBand: effectiveLodBand,
        },
      }));
    }
    return canvasLayoutNodes.map((node) => {
      const isFocused = node.id === activeFocusId;
      const isConnected = localNeighborhoodIds.has(node.id);
      const dimmed = !isConnected;
      return {
        ...node,
        className: composeFocusClass(node.className, isFocused, dimmed),
        data: {
          ...node.data,
          renderBand: effectiveLodBand,
          dimmed,
          highlighted: isConnected,
        },
      };
    });
  }, [
    canvasLayoutNodes,
    localNeighborhoodIds,
    attackPathNodeIds,
    attackPathNodeOrder,
    reachabilitySummary,
    blastRadius,
    activeFocusId,
    effectiveLodBand,
  ]);

  // Drift lens (#3192) — classify the currently-rendered snapshot against the
  // previous one using the diff index the server tags. The lens is inert unless
  // a diff exists AND the operator armed it, so the default view never changes.
  const driftIndex = useMemo(() => buildDriftIndex(graphDiff), [graphDiff]);
  const driftAttributeSummaryList = useMemo(
    () => driftAttributeSummaries(driftIndex),
    [driftIndex],
  );
  const driftLensEngaged =
    driftLensActive && Boolean(graphDiff) && driftIndex.hasChanges;

  // Keep the lens honest: a snapshot with no older baseline (or no changes)
  // disarms the lens and resets the focus chip so it can never linger as a
  // stale overlay on the default view.
  useEffect(() => {
    if (!graphDiff) {
      setDriftLensActive(false);
      setDriftFilter("all");
    }
  }, [graphDiff]);

  const displayNodes = useMemo<Node<LineageNodeData>[]>(() => {
    let nodes = baseDisplayNodes;
    if (driftLensEngaged) {
      nodes = nodes.map((node) => {
        const kind = changeKindForNode(node.id, driftIndex);
        const critical = isCriticalChange(kind, node.data.severity);
        const passes = driftFilterPasses(kind, driftFilter, critical);
        const ringClass =
          driftFilter === "critical" && critical
            ? "drift-ring-critical"
            : CHANGE_KIND_META[kind].ringClass;
        const className = [node.className, ringClass].filter(Boolean).join(" ");
        const dimmed = Boolean(node.data.dimmed) || !passes;
        return {
          ...node,
          className,
          data: { ...node.data, dimmed },
        };
      });
    }
    if (evidenceLensActive) {
      nodes = nodes.map((node) => {
        const passes = evidenceLensPasses(
          node.data.runtimeEvidenceTier,
          evidenceFilter,
        );
        return {
          ...node,
          data: {
            ...node.data,
            dimmed: Boolean(node.data.dimmed) || !passes,
          },
        };
      });
    }
    return nodes;
  }, [
    baseDisplayNodes,
    driftIndex,
    driftLensEngaged,
    driftFilter,
    evidenceLensActive,
    evidenceFilter,
  ]);

  // Live change-kind tallies over the rendered graph — `unchanged` is derived
  // here (the diff index only carries actively-changed ids) so the legend and
  // chips reflect exactly what the operator sees on the canvas.
  const drift = useMemo<{
    counts: Record<ChangeKind, number>;
    critical: number;
  }>(() => {
    const counts: Record<ChangeKind, number> = {
      new: 0,
      changed: 0,
      removed: driftIndex.counts.removed,
      unchanged: 0,
    };
    let critical = 0;
    for (const node of baseDisplayNodes) {
      const kind = changeKindForNode(node.id, driftIndex);
      if (kind === "new" || kind === "changed" || kind === "unchanged") {
        counts[kind] += 1;
      }
      if (isCriticalChange(kind, node.data.severity)) critical += 1;
    }
    return { counts, critical };
  }, [baseDisplayNodes, driftIndex]);

  const evidenceCounts = useMemo<
    Record<EvidenceLensFilter, number>
  >(() => {
    const counts: Record<EvidenceLensFilter, number> = {
      all: baseDisplayNodes.length,
      runtime_observed: 0,
      runtime_blocked: 0,
      static_scan: 0,
    };
    for (const node of baseDisplayNodes) {
      const tier = node.data.runtimeEvidenceTier ?? "static_scan";
      if (tier === "runtime_observed") counts.runtime_observed += 1;
      else if (tier === "runtime_blocked") counts.runtime_blocked += 1;
      else counts.static_scan += 1;
    }
    return counts;
  }, [baseDisplayNodes]);

  const compressedGroupCount = aggregatedClusterNodes.length;
  const sourceNodeCount = rollupNavigationActive
    ? (rollupView?.summary.total_nodes ?? estateNodeCount)
    : (graphData?.nodes.length ?? flow.nodes.length);
  const renderedNodeCount = displayNodes.length;

  const baseDisplayEdges = useMemo(() => {
    if (attackPathEdgeKeys) {
      return layoutEdges
        .filter((edge) =>
          attackPathEdgeKeys.has(`${edge.source}=>${edge.target}`),
        )
        .map((edge): Edge => {
          const inPath = attackPathEdgeKeys.has(
            `${edge.source}=>${edge.target}`,
          );
          const relationshipLabel =
            typeof edge.data?.relationshipLabel === "string"
              ? edge.data.relationshipLabel
              : typeof edge.data?.relationship === "string"
                ? edge.data.relationship.replace(/_/g, " ")
                : undefined;
          return {
            ...edge,
            label: relationshipLabel,
            labelShowBg: true,
            labelBgPadding: [8, 4],
            labelBgBorderRadius: 6,
            labelBgStyle: {
              fill: captureMode ? "#0a0a0a" : "rgba(24,24,27,0.92)",
              fillOpacity: 0.94,
            },
            labelStyle: {
              fill: "#f4f4f5",
              fontSize: 11,
              fontWeight: 600,
            },
            animated: captureMode ? false : Boolean(inPath || edge.animated),
            style: {
              ...edge.style,
              opacity: inPath ? 1 : 0.08,
              strokeWidth: inPath
                ? Math.max(
                    typeof edge.style?.strokeWidth === "number"
                      ? edge.style.strokeWidth
                      : 2,
                    3.2,
                  )
                : 1,
              ...(inPath
                ? { filter: "drop-shadow(0 0 6px rgba(249,115,22,0.55))" }
                : {}),
            },
          };
        });
    }
    if (blastRadius) {
      return layoutEdges.map((edge): Edge => {
        const inBlast =
          blastRadius.nodeIds.has(edge.source) &&
          blastRadius.nodeIds.has(edge.target);
        return {
          ...edge,
          animated: captureMode ? false : Boolean(inBlast || edge.animated),
          style: {
            ...edge.style,
            opacity: inBlast ? 0.95 : 0.06,
            strokeWidth: inBlast
              ? Math.max(
                  typeof edge.style?.strokeWidth === "number"
                    ? edge.style.strokeWidth
                    : 2,
                  3,
                )
              : 1,
            ...(inBlast
              ? { filter: "drop-shadow(0 0 6px rgba(139,92,246,0.55))" }
              : {}),
          },
        };
      });
    }
    if (reachabilitySummary) {
      return layoutEdges.map((edge): Edge => {
        const inReach =
          reachabilitySummary.edgeKeys.has(`${edge.source}=>${edge.target}`) ||
          reachabilitySummary.edgeKeys.has(`${edge.target}=>${edge.source}`);
        return {
          ...edge,
          animated: captureMode ? false : Boolean(inReach || edge.animated),
          style: {
            ...edge.style,
            opacity: inReach ? 0.95 : 0.07,
            strokeWidth: inReach
              ? Math.max(
                  typeof edge.style?.strokeWidth === "number"
                    ? edge.style.strokeWidth
                    : 2,
                  3,
                )
              : 1,
            ...(inReach
              ? { filter: "drop-shadow(0 0 6px rgba(244,63,94,0.5))" }
              : {}),
          },
        };
      });
    }
    return readableGraphEdges(layoutEdges, localNeighborhoodIds, {
      baseOpacity: graphLayoutKind === "dagre-lr" ? 0.34 : 0.26,
      highSignalOpacity: graphLayoutKind === "dagre-lr" ? 0.6 : 0.48,
      inactiveOpacity: 0.06,
      captureMode,
    });
  }, [
    layoutEdges,
    localNeighborhoodIds,
    attackPathEdgeKeys,
    reachabilitySummary,
    blastRadius,
    graphLayoutKind,
    captureMode,
  ]);

  // Drift lens edge emphasis — new/changed edges adopt their change-kind colour
  // so the lens reads as one system with the node rings. Inert (identity) when
  // the lens is disengaged.
  const displayEdges = useMemo(() => {
    if (!driftLensEngaged) return baseDisplayEdges;
    return baseDisplayEdges.map((edge): Edge => {
      const relationship =
        typeof edge.data?.relationship === "string"
          ? edge.data.relationship
          : "";
      const kind = changeKindForEdge(
        edge.source,
        edge.target,
        relationship,
        driftIndex,
      );
      if (kind === "unchanged") return edge;
      const meta = CHANGE_KIND_META[kind];
      const currentOpacity =
        typeof edge.style?.opacity === "number" ? edge.style.opacity : 0.4;
      const currentWidth =
        typeof edge.style?.strokeWidth === "number"
          ? edge.style.strokeWidth
          : 1.4;
      return {
        ...edge,
        style: {
          ...edge.style,
          stroke: meta.color,
          opacity: Math.max(currentOpacity, 0.85),
          strokeWidth: Math.max(currentWidth, 2.2),
          transition:
            "stroke 0.2s ease, opacity 0.2s ease, stroke-width 0.2s ease",
        },
      };
    });
  }, [baseDisplayEdges, driftLensEngaged, driftIndex]);

  const graphEvaluation = useMemo(
    () => evaluateGraphUx(graphData, displayNodes, displayEdges),
    [displayEdges, displayNodes, graphData],
  );

  const legendItems = useMemo(
    () => legendItemsForVisibleGraph(displayNodes, displayEdges),
    [displayEdges, displayNodes],
  );
  const viewportOptions = useMemo(
    () =>
      graphFitViewOptions({
        nodeCount: displayNodes.length,
        edgeCount: displayEdges.length,
        selectedNode: false,
        mode: "lineage",
        captureMode,
      }),
    [captureMode, displayEdges.length, displayNodes.length],
  );
  const showMiniMap = useMemo(
    () =>
      !captureMode &&
      shouldShowGraphMiniMap({
        nodeCount: displayNodes.length,
        edgeCount: displayEdges.length,
        selectedNode: Boolean(selectedNode),
        mode: "lineage",
      }),
    [captureMode, displayEdges.length, displayNodes.length, selectedNode],
  );

  const hasContextualGraph = useMemo(
    () =>
      displayNodes.some((node) => {
        const nodeType = (node.data as LineageNodeData).nodeType;
        return nodeType !== "vulnerability" && nodeType !== "misconfiguration";
      }),
    [displayNodes],
  );

  const graphOnlyFindings = displayNodes.length > 0 && !hasContextualGraph;
  // Match the filter→URL sync behavior above: during the initial graph load,
  // App Router search params can lag behind router.replace() churn. The live
  // address bar is the source of truth for renderer flags so explicit
  // /graph?renderer=webgl requests cannot briefly fall back to React Flow.
  const liveRendererParams =
    typeof window !== "undefined"
      ? new URLSearchParams(window.location.search)
      : searchParams;
  const webglGraphEnabled =
    liveRendererParams?.get("renderer") === "webgl" ||
    liveRendererParams?.get("webgl") === "1";
  const graphRenderer = decideGraphRenderer({
    nodeCount: sourceNodeCount,
    edgeCount: graphData?.edges.length ?? displayEdges.length,
    captureMode,
    selectedAttackPath: Boolean(selectedAttackPath),
    reachabilityActive: Boolean(reachabilitySummary),
    rollupActive: rollupNavigationActive,
    graphOnlyFindings,
    webglEnabled: webglGraphEnabled,
  });

  // Soft re-frame when drift/evidence lenses engage so ring emphasis stays in view.
  useEffect(() => {
    if (graphRenderer.kind !== "react-flow") return;
    if (!driftLensActive && !evidenceLensActive) return;
    const timer = window.setTimeout(() => {
      void reactFlow.fitView({ ...viewportOptions, duration: 280 });
    }, 80);
    return () => window.clearTimeout(timer);
  }, [
    driftLensActive,
    evidenceLensActive,
    driftFilter,
    evidenceFilter,
    graphRenderer.kind,
    reactFlow,
    viewportOptions,
  ]);

  const graphPanelError =
    error && snapshots.length > 0 ? graphErrorState(error) : null;
  const findingNodes = useMemo(
    () =>
      displayNodes
        .filter((node) => {
          const nodeType = (node.data as LineageNodeData).nodeType;
          return (
            nodeType === "vulnerability" || nodeType === "misconfiguration"
          );
        })
        .map((node) => ({ id: node.id, data: node.data as LineageNodeData })),
    [displayNodes],
  );

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      // Cluster-pill click → restore the absorbed siblings in place. We
      // never open the detail panel for a synthetic cluster node.
      if (isClusterPillNode(node as Node<LineageNodeData>)) {
        const id = node.id;
        setExpandedClusterIds((current) => {
          const next = new Set(current);
          next.add(id);
          return next;
        });
        return;
      }

      const data = node.data as LineageNodeData;
      if (rollupNavigationActive && data.attributes?.rollup_has_children === true) {
        setRollupStack((current) => {
          if (current.at(-1)?.id === node.id) return current;
          return [...current, { id: node.id, label: data.label }];
        });
      }

      setSelectedNode({
        ...data,
        attributes: {
          ...(data.attributes ?? {}),
          node_id: node.id,
        },
      });
      setSelectedNodeId(node.id);
      setSelectedAttackPathKey(null);
      setAutoPathDismissed(true);
      // Click pin (#2257): toggle a "pinned focus" on the clicked node.
      // Re-clicking the same node clears the pin. Hover state is reset
      // because the pin replaces hover as the focus source.
      setPinnedFocusId((current) => (current === node.id ? null : node.id));
      setHoveredNodeId(null);
    },
    [rollupNavigationActive],
  );

  const onLargeGraphNodeSelect = useCallback(
    (nodeId: string) => {
      const node = displayNodes.find((candidate) => candidate.id === nodeId);
      if (!node) return;
      onNodeClick({} as React.MouseEvent, node);
    },
    [displayNodes, onNodeClick],
  );

  const onNodeMouseEnter = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setHoveredNodeId(node.id);
    },
    [],
  );

  const onNodeMouseLeave = useCallback(() => {
    setHoveredNodeId(null);
  }, []);

  const selectFindingCard = useCallback((id: string, data: LineageNodeData) => {
    setSelectedNode({
      ...data,
      attributes: {
        ...(data.attributes ?? {}),
        node_id: id,
      },
    });
    setSelectedNodeId(id);
    setHoveredNodeId(id);
    setSelectedAttackPathKey(null);
    setAutoPathDismissed(true);
  }, []);

  const runSearch = useCallback(async () => {
    const query = searchQuery.trim();
    if (!query || !selectedScanId) {
      setSearchResults([]);
      return;
    }
    setSearching(true);
    try {
      const response = await api.searchGraph(query, {
        scanId: selectedScanId,
        entityTypes: serverEntityTypes,
        ...(filters.severity ? { minSeverity: filters.severity } : {}),
        limit: 16,
      });
      setSearchResults(response.results);
    } catch {
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }, [filters.severity, searchQuery, selectedScanId, serverEntityTypes]);

  const loadRootInvestigation = useCallback(
    async (
      request: GraphInvestigationRequest & { node?: UnifiedNode | undefined },
    ) => {
      if (!selectedScanId) return;

      const fallback = request.node
        ? (flowNodeDataById.get(request.node.id) ??
          buildFallbackNodeData(request.node))
        : null;
      if (fallback) {
        setSelectedNode({
          ...fallback,
          attributes: {
            ...(fallback.attributes ?? {}),
            node_id: request.rootId,
          },
        });
      } else {
        setSelectedNode(null);
      }
      setSelectedNodeId(request.rootId);
      setPinnedFocusId(null);
      setHoveredNodeId(request.rootId);
      setSelectedAttackPathKey(null);
      setAutoPathDismissed(true);
      setReachabilitySummary(null);
      setReachabilityError(null);
      setSearchResults([]);
      setSearchQuery(
        request.rootLabel ?? request.node?.label ?? request.rootId,
      );
      setLoadingGraph(true);
      try {
        const response = await api.queryGraph({
          roots: [request.rootId],
          scan_id: selectedScanId,
          direction: "both",
          max_depth: filters.vulnOnly ? 3 : 4,
          max_nodes: filters.vulnOnly ? 400 : 800,
          max_edges: filters.vulnOnly ? 3000 : 8000,
          timeout_ms: 2500,
          traversable_only: false,
          static_only: filters.runtimeMode === "static",
          dynamic_only: filters.runtimeMode === "dynamic",
          include_roots: true,
          include_attack_paths: true,
          relationship_types: serverRelationships,
        });
        const rootNode =
          response.nodes.find((node) => node.id === request.rootId) ??
          request.node;
        if (rootNode) {
          setSelectedNode(buildFallbackNodeData(rootNode));
        }
        setGraphData(queryResponseToGraphResponse(response));
        setInvestigationMode({
          rootId: request.rootId,
          rootLabel: rootNode?.label ?? request.rootLabel ?? request.rootId,
          truncated: response.truncated,
          nodeCount: response.nodes.length,
          edgeCount: response.edges.length,
        });
        setReachabilitySummary(
          summarizeReachability({
            rootId: request.rootId,
            rootLabel: rootNode?.label ?? request.rootLabel ?? request.rootId,
            nodes: response.nodes,
            edges: response.edges,
            depthByNode: response.depth_by_node,
            truncated: response.truncated,
          }),
        );
        setError(null);
      } catch (e) {
        setError(
          e instanceof Error ? e.message : "Failed to load root-centered graph",
        );
      } finally {
        setLoadingGraph(false);
      }
    },
    [
      filters.runtimeMode,
      filters.vulnOnly,
      flowNodeDataById,
      selectedScanId,
      serverRelationships,
    ],
  );

  useEffect(() => {
    const requested = requestedInvestigationRef.current;
    if (!requested || !selectedScanId) return;
    requestedInvestigationRef.current = null;
    void loadRootInvestigation(requested);
  }, [loadRootInvestigation, selectedScanId]);

  const focusSearchResult = useCallback(
    async (node: UnifiedNode) => {
      await loadRootInvestigation({
        rootId: node.id,
        rootLabel: node.label,
        node,
      });
    },
    [loadRootInvestigation],
  );

  const clearInvestigationMode = useCallback(() => {
    setInvestigationMode(null);
    setPinnedFocusId(null);
    setHoveredNodeId(null);
    setSelectedAttackPathKey(null);
    setAutoPathDismissed(false);
    setReachabilitySummary(null);
    setReachabilityError(null);
    setBlastRadius(null);
    setBlastError(null);
  }, []);

  const clearBlastRadius = useCallback(() => {
    setBlastRadius(null);
    setBlastError(null);
  }, []);

  const dismissRollup = useCallback(() => {
    setRollupDismissed(true);
    setRollupStack([]);
    setRollupError(null);
  }, []);

  const navigateRollupBreadcrumb = useCallback((index: number) => {
    setRollupStack((current) => current.slice(0, index + 1));
  }, []);

  const resetRollupToRoot = useCallback(() => {
    setRollupStack([]);
  }, []);

  const loadBlastRadius = useCallback(
    async (nodeId: string, nodeLabel: string) => {
      if (!nodeId) return;
      // Blast radius takes over the canvas; drop any competing overlays so the
      // impacted set is the only thing highlighted.
      setSelectedAttackPathKey(null);
      setReachabilitySummary(null);
      setReachabilityError(null);
      setLoadingBlast(true);
      setBlastError(null);
      try {
        const impact = await api.getGraphImpact(
          nodeId,
          selectedScanId || undefined,
          4,
        );
        setBlastRadius({
          rootId: impact.node_id,
          rootLabel: nodeLabel || impact.node_id,
          nodeIds: new Set<string>([impact.node_id, ...impact.affected_nodes]),
          countsByType: impact.affected_by_type,
          affectedCount: impact.affected_count,
          maxDepthReached: impact.max_depth_reached,
        });
      } catch (e) {
        setBlastRadius(null);
        setBlastError(
          e instanceof Error ? e.message : "Failed to compute blast radius",
        );
      } finally {
        setLoadingBlast(false);
      }
    },
    [selectedScanId],
  );

  const pageStart =
    graphData && graphData.pagination.total > 0
      ? graphData.pagination.offset + 1
      : 0;
  const pageEnd =
    graphData && graphData.pagination.total > 0
      ? Math.min(
          graphData.pagination.offset + graphData.pagination.limit,
          graphData.pagination.total,
        )
      : 0;
  const pageNumber =
    graphData && graphData.pagination.limit > 0
      ? Math.floor(graphData.pagination.offset / graphData.pagination.limit) + 1
      : 1;
  const totalPages =
    graphData && graphData.pagination.limit > 0
      ? Math.max(
          1,
          Math.ceil(graphData.pagination.total / graphData.pagination.limit),
        )
      : 1;
  if (loadingSnapshots) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading persisted graph snapshots...
      </div>
    );
  }

  if (error && snapshots.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">Could not load the unified graph</p>
        <p className="text-xs text-zinc-500">
          Run a scan first so the API can persist graph snapshots.
        </p>
      </div>
    );
  }

  if (snapshots.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <ShieldAlert className="w-8 h-8 text-zinc-600" />
        <p className="text-sm">No graph snapshots found</p>
        <p className="text-xs text-zinc-500">
          Run a scan to persist the unified inventory and security graph.
        </p>
      </div>
    );
  }

  return (
    // min-h instead of h so the page can grow taller than the viewport
    // when the snapshot diff cards / how-to-read prose / findings
    // fallback panel push content past the fold. Previously the fixed
    // h-[calc(100vh-3.5rem)] container clipped everything below the
    // viewport, leaving users stuck on the snapshot row with no way
    // to scroll to the React Flow canvas or the findings panel.
    <div className="min-h-[calc(100vh-3.5rem)] flex flex-col">
      <PulseStyles />

      <div className="border-b border-zinc-800 bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.10),transparent_24%),linear-gradient(180deg,rgba(24,24,27,0.96),rgba(9,9,11,0.96))] px-4 py-3">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-sky-400">
              Unified graph
            </p>
            <h1 className="mt-1 text-lg font-semibold text-zinc-100">
              Lineage Graph
            </h1>
            <p className="text-xs text-zinc-500">
              Evidence-backed relationships across agents, servers, packages,
              credentials, tools, and findings.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 xl:justify-end">
            {flow.summary && (
              <>
                <MetricCard value={flow.summary.agents} label="agents" />
                <MetricCard value={flow.summary.servers} label="servers" />
                <MetricCard
                  value={flow.summary.findings}
                  label="findings"
                  accent="orange"
                />
                <MetricCard
                  value={flow.summary.critical}
                  label="critical"
                  accent="red"
                />
                <MetricCard
                  value={flow.summary.attackPaths}
                  label="paths"
                  accent="blue"
                />
              </>
            )}

            <select
              value={selectedScanId}
              onChange={(event) => setSelectedScanId(event.target.value)}
              className="rounded-xl border border-zinc-700 bg-zinc-900/90 px-3 py-2 text-sm text-zinc-300 focus:border-sky-600 focus:outline-none"
            >
              {snapshots.map((snapshot) => (
                <option key={snapshot.scan_id} value={snapshot.scan_id}>
                  {snapshot.scan_id.slice(0, 12)} ·{" "}
                  {new Date(snapshot.created_at).toLocaleString()}
                </option>
              ))}
            </select>

            <GraphEvidenceExportButton
              scanId={selectedScanId || undefined}
              filenamePrefix={
                selectedScanId ? `scan-${selectedScanId}-graph` : undefined
              }
            />
            <FullscreenButton />
          </div>
        </div>

        <div className="mt-3">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void runSearch();
            }}
            className="flex flex-wrap items-center gap-2"
          >
            <input
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search nodes, tags, severities, or attributes"
              className="min-w-[260px] flex-1 rounded-xl border border-zinc-700 bg-zinc-900/90 px-3 py-2 text-sm text-zinc-300 placeholder:text-zinc-500 focus:border-sky-600 focus:outline-none"
            />
            <button
              type="submit"
              disabled={searching || !selectedScanId}
              className="rounded-xl border border-zinc-700 bg-zinc-900/80 px-3 py-2 text-sm text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {searching ? "Searching..." : "Search"}
            </button>
          </form>

          <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-zinc-400">
            <ViewPill
              label="Scope"
              value={filters.agentName ? filters.agentName : "all agents"}
            />
            <ViewPill label="View" value={graphScopeLabelForFilters(filters)} />
            <ViewPill
              label="Severity"
              value={filters.severity ? `${filters.severity}+` : "all"}
            />
            {sourceNodeCount > 0 && (
              <span
                data-testid="graph-compression-summary"
                className="rounded-lg border border-zinc-800 bg-zinc-900/80 px-2.5 py-1 text-zinc-400"
              >
                {compressedGroupCount > 0
                  ? `${compressedGroupCount} compressed groups`
                  : `${renderedNodeCount}/${sourceNodeCount} nodes rendered`}
              </span>
            )}
            {loadingGraph && (
              <span className="flex items-center gap-1 rounded-lg border border-sky-500/20 bg-sky-500/10 px-2.5 py-1 text-sky-200">
                <Loader2 className="h-3 w-3 animate-spin" />
                refreshing
              </span>
            )}
          </div>

          <details className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3 group">
            <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3 [&::-webkit-details-marker]:hidden">
              <div>
                <span className="text-[10px] uppercase tracking-[0.22em] text-zinc-500">
                  View controls
                </span>
                <p className="mt-1 text-xs text-zinc-400">
                  Change scope, layers, severity, traversal, and page size
                  without changing the persisted graph.
                </p>
              </div>
              <span className="text-[10px] uppercase tracking-[0.18em] text-zinc-500 group-open:hidden">
                show
              </span>
              <span className="hidden text-[10px] uppercase tracking-[0.18em] text-zinc-500 group-open:inline">
                hide
              </span>
            </summary>
            <div className="mt-3 space-y-3">
              <div className="flex flex-wrap gap-2 text-[11px]">
                <button
                  type="button"
                  onClick={() =>
                    setFilters(
                      createImmediateGraphFilters(
                        filters.agentName ?? flow.agentNames[0] ?? null,
                      ),
                    )
                  }
                  className={scopeButtonClass(
                    activeScopePreset === "immediate",
                  )}
                  title="One-hop triage around the selected agent"
                >
                  Immediate
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setFilters(
                      createFocusedGraphFilters(
                        filters.agentName ?? flow.agentNames[0] ?? null,
                      ),
                    )
                  }
                  className={scopeButtonClass(activeScopePreset === "relevant")}
                  title="Default fix-first graph with bounded path context"
                >
                  Relevant paths
                </button>
                <button
                  type="button"
                  onClick={() => setFilters(createExpandedGraphFilters(null))}
                  className={scopeButtonClass(activeScopePreset === "expanded")}
                  title="Broader topology review with lower-priority context included"
                >
                  Expanded topology
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setFilters(
                      createAssetLifecycleDriftGraphFilters(
                        filters.agentName ?? flow.agentNames[0] ?? null,
                      ),
                    )
                  }
                  className={scopeButtonClass(
                    activeScopePreset === "assetDrift",
                  )}
                  title="Governance paths and drift incidents across estate containers"
                >
                  Asset lifecycle drift
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setFilters({ ...filters, vulnOnly: !filters.vulnOnly })
                  }
                  className={scopeButtonClass(filters.vulnOnly)}
                  title="Limit the graph to vulnerability-bearing paths"
                >
                  Vulnerable only
                </button>
              </div>
              <FilterPanel
                filters={filters}
                onChange={setFilters}
                agentNames={flow.agentNames}
                validValues={validValues}
                onReset={handleResetFilters}
                variant="panel"
              />
            </div>
          </details>

          {activeScopePreset === "assetDrift" && (
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-orange-500/30 bg-orange-500/10 px-3 py-2 text-xs text-orange-100">
              <span>
                Asset lifecycle drift lens — governance and{" "}
                <span className="font-mono">exhibits_drift</span> edges with
                drift incidents on estate containers.
              </span>
              <a
                href="/drift"
                className="rounded-lg border border-orange-400/30 bg-orange-950/60 px-2.5 py-1 text-orange-100 transition hover:border-orange-300"
              >
                Open drift incidents
              </a>
            </div>
          )}

          {investigationMode && (
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-xs text-sky-100">
              <span>
                Root-centered investigation:{" "}
                <span className="font-mono">{investigationMode.rootId}</span>
                {investigationMode.truncated
                  ? " · traversal budget reached"
                  : ""}
              </span>
              <button
                type="button"
                onClick={clearInvestigationMode}
                className="rounded-lg border border-sky-400/30 bg-sky-950/60 px-2.5 py-1 text-sky-100 transition hover:border-sky-300"
              >
                Return to paged graph
              </button>
            </div>
          )}

          {(reachabilitySummary ||
            loadingReachability ||
            reachabilityError) && (
            <ReachabilityDrillInPanel
              summary={reachabilitySummary}
              loading={loadingReachability}
              error={reachabilityError}
              onClear={() => {
                setReachabilitySummary(null);
                setReachabilityError(null);
              }}
            />
          )}

          {(blastRadius || loadingBlast || blastError) && (
            <BlastRadiusPanel
              summary={blastRadius}
              loading={loadingBlast}
              error={blastError}
              onClear={clearBlastRadius}
            />
          )}

          {(rollupEligible || loadingRollup || rollupError) &&
            !rollupDismissed && (
              <RollupNavigationPanel
                summary={rollupView}
                estateNodeCount={estateNodeCount}
                breadcrumbs={rollupStack}
                loading={loadingRollup}
                error={rollupError}
                active={rollupNavigationActive}
                onDismiss={dismissRollup}
                onReset={resetRollupToRoot}
                onBreadcrumb={navigateRollupBreadcrumb}
              />
            )}

          {searchResults.length > 0 && (
            <div className="mt-2 rounded-2xl border border-zinc-800 bg-zinc-950/90 p-2">
              <div className="mb-2 px-1 text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                Search respects current entity scope
                {filters.severity ? ` and ${filters.severity}+ severity` : ""}
              </div>
              <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
                {searchResults.map((result) => (
                  <button
                    key={result.id}
                    type="button"
                    data-testid={`graph-search-result-${result.id}`}
                    onClick={() => void focusSearchResult(result)}
                    className="rounded-xl border border-zinc-800 bg-zinc-900/80 px-3 py-2 text-left transition hover:border-zinc-600 hover:bg-zinc-900"
                  >
                    <p className="truncate text-sm font-medium text-zinc-100">
                      {result.label}
                    </p>
                    <p className="mt-1 text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                      {String(result.entity_type)}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-zinc-500">
                      {result.severity && <span>{result.severity}</span>}
                      <span>
                        risk{" "}
                        {typeof result.risk_score === "number" &&
                        Number.isFinite(result.risk_score)
                          ? result.risk_score.toFixed(1)
                          : "N/A"}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-4 text-[11px] text-zinc-500">
          {activeSnapshot && (
            <>
              <span>{activeSnapshot.node_count} nodes</span>
              <span>{activeSnapshot.edge_count} edges</span>
              <span>
                captured {new Date(activeSnapshot.created_at).toLocaleString()}
              </span>
            </>
          )}
          {graphData && graphData.pagination.total > 0 && (
            <span>
              showing {pageStart}-{pageEnd} of {graphData.pagination.total}{" "}
              nodes
            </span>
          )}
        </div>

        <GraphEvaluationSummary evaluation={graphEvaluation} />

        {/* Snapshot diff + how-to-read default-collapsed so the canvas owns the
            viewport. The four redundant SnapshotMetaCards (Snapshot/Topology/
            Scope/Window) were removed — the inline summary above already
            surfaces nodes / edges / captured-at / paging. Keep the diff and
            the help available via <details> for operators who need them but
            stop them from owning a full screen of vertical space on every
            page-load. */}
        {activeSnapshot && (
          <details className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3 group">
            <summary className="flex flex-wrap items-center justify-between gap-3 cursor-pointer list-none [&::-webkit-details-marker]:hidden">
              <div className="flex items-center gap-3">
                <span className="text-[10px] uppercase tracking-[0.24em] text-sky-400">
                  Snapshot diff
                </span>
                <span className="text-xs text-zinc-500">
                  {graphDiff
                    ? `+${graphDiff.nodes_added.length} −${graphDiff.nodes_removed.length} nodes · +${graphDiff.edges_added.length} −${graphDiff.edges_removed.length} edges`
                    : previousSnapshot
                      ? `Compared with ${previousSnapshot.scan_id.slice(0, 12)}`
                      : "No older snapshot available."}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {loadingDiff && (
                  <span className="flex items-center gap-1 text-xs text-sky-400">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    loading
                  </span>
                )}
                <span className="text-[10px] uppercase tracking-[0.18em] text-zinc-500 group-open:hidden">
                  show
                </span>
                <span className="text-[10px] uppercase tracking-[0.18em] text-zinc-500 hidden group-open:inline">
                  hide
                </span>
              </div>
            </summary>
            {diffError ? (
              <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                {diffError}
              </div>
            ) : loadingDiff && !graphDiff ? (
              <DiffLoadingGrid />
            ) : (
              <div className="mt-3 grid gap-2 md:grid-cols-3 xl:grid-cols-5">
                <DiffMetric
                  label="nodes added"
                  value={graphDiff?.nodes_added.length ?? 0}
                  tone="green"
                />
                <DiffMetric
                  label="nodes removed"
                  value={graphDiff?.nodes_removed.length ?? 0}
                  tone="amber"
                />
                <DiffMetric
                  label="nodes changed"
                  value={graphDiff?.nodes_changed.length ?? 0}
                  tone="blue"
                />
                <DiffMetric
                  label="edges added"
                  value={graphDiff?.edges_added.length ?? 0}
                  tone="green"
                />
                <DiffMetric
                  label="edges removed"
                  value={graphDiff?.edges_removed.length ?? 0}
                  tone="amber"
                />
              </div>
            )}
            {graphDiff &&
              (graphDiff.nodes_added.length > 0 ||
                graphDiff.nodes_changed.length > 0 ||
                graphDiff.nodes_removed.length > 0) && (
                <div className="mt-3 grid gap-2 lg:grid-cols-3">
                  <DiffPreview label="Added" items={graphDiff.nodes_added} />
                  <DiffPreview
                    label="Changed"
                    items={graphDiff.nodes_changed}
                  />
                  <DiffPreview
                    label="Removed"
                    items={graphDiff.nodes_removed}
                  />
                </div>
              )}
          </details>
        )}

        {graphDiff && (
          <GraphDriftLegend
            active={driftLensActive}
            onToggleActive={(next) => {
              setDriftLensActive(next);
              if (!next) setDriftFilter("all");
            }}
            filter={driftFilter}
            onFilterChange={setDriftFilter}
            counts={drift.counts}
            criticalCount={drift.critical}
            comparedLabel={previousSnapshot?.scan_id.slice(0, 12)}
            attributeSummaries={driftAttributeSummaryList}
          />
        )}

        {driftLensActive && graphDiff ? (
          <GraphEdgeChangesPanel
            changes={edgeChanges}
            loading={loadingEdgeChanges}
            error={edgeChangesError}
            comparedLabel={previousSnapshot?.scan_id.slice(0, 12)}
          />
        ) : null}

        <GraphEvidenceLegend
          active={evidenceLensActive}
          onToggleActive={(next) => {
            setEvidenceLensActive(next);
            if (!next) setEvidenceFilter("all");
          }}
          filter={evidenceFilter}
          onFilterChange={setEvidenceFilter}
          counts={evidenceCounts}
        />

        <details className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3 text-xs text-zinc-400 group">
          <summary className="flex items-center justify-between cursor-pointer list-none [&::-webkit-details-marker]:hidden">
            <span className="font-medium text-zinc-200">
              How to read this graph
            </span>
            <span className="text-[10px] uppercase tracking-[0.18em] text-zinc-500 group-open:hidden">
              show
            </span>
            <span className="text-[10px] uppercase tracking-[0.18em] text-zinc-500 hidden group-open:inline">
              hide
            </span>
          </summary>
          <ul className="mt-2 space-y-1.5">
            <li>
              Each snapshot is a persisted control-plane view of entities,
              edges, attack paths, and relationship counts at one capture time.
            </li>
            <li>
              Node IDs are stable identifiers inside the graph model; the detail
              panel shows the node ID, first seen, last seen, sources, and edge
              counts.
            </li>
            <li>
              Pagination changes the visible canvas, not the persisted snapshot
              itself. Narrow the scope when the graph gets large; page when you
              need broader coverage.
            </li>
            <li>
              Relevant paths is for operator triage. Expanded is for topology
              review. Attack-path cards are the fix-first shortlist, not the
              whole graph.
            </li>
            <li>
              Pages at or above{" "}
              {LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD.toLocaleString()} visible
              nodes or {LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD.toLocaleString()}{" "}
              visible edges use the limited 2D overview. Narrowing, search
              results, attack-path focus, and reachability drill-ins return to
              React Flow.
            </li>
            <li>
              Hop depth controls how far traversal can move from the selected
              agent or root. Entity layers control what kinds of nodes can
              render, without changing the persisted graph.
            </li>
          </ul>
        </details>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <button
            type="button"
            onClick={() =>
              setPageOffset((current) =>
                Math.max(0, current - filters.pageSize),
              )
            }
            disabled={loadingGraph || pageOffset === 0}
            className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-3 py-1.5 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Previous page
          </button>
          <button
            type="button"
            onClick={() =>
              setPageOffset((current) => current + filters.pageSize)
            }
            disabled={loadingGraph || !graphData?.pagination.has_more}
            className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-3 py-1.5 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next page
          </button>
          <span className="text-zinc-500">
            Page {pageNumber} of {totalPages}
          </span>
          {graphData?.pagination.has_more && (
            <span className="text-amber-400">
              Large snapshot: narrow the graph or keep paging.
            </span>
          )}
        </div>

        {attackPaths.length > 0 && (
          <details
            className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/60 p-3 group"
            {...(selectedAttackPathKey ? { open: true } : {})}
          >
            <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 [&::-webkit-details-marker]:hidden">
              <div>
                <p className="text-[10px] uppercase tracking-[0.24em] text-orange-400">
                  Attack paths
                </p>
                <p className="mt-1 text-xs text-zinc-500">
                  {attackPaths.length} ranked path
                  {attackPaths.length === 1 ? "" : "s"} available for focused
                  investigation.
                </p>
              </div>
              <span className="text-[10px] uppercase tracking-[0.18em] text-zinc-500 group-open:hidden">
                show queue
              </span>
              <span className="hidden text-[10px] uppercase tracking-[0.18em] text-zinc-500 group-open:inline">
                hide queue
              </span>
            </summary>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="mt-3 text-xs text-zinc-500">
                  Focus the current graph on a precomputed exploit chain in this
                  filtered snapshot page.
                </p>
              </div>
              {selectedAttackPath && (
                <button
                  type="button"
                  onClick={() => {
                    setSelectedAttackPathKey(null);
                    setAutoPathDismissed(true);
                  }}
                  className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-3 py-1.5 text-xs text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100"
                >
                  Clear path focus
                </button>
              )}
            </div>

            <div className="mt-3 flex gap-3 overflow-x-auto pb-1">
              {attackPaths.map((path) => {
                const key = attackPathKey(path);
                const pathNodes = toAttackCardNodes(path, graphNodeById);
                if (pathNodes.length === 0) return null;
                const isActive = effectiveSelectedAttackPathKey === key;
                return (
                  <div
                    key={key}
                    className={`min-w-[360px] rounded-2xl transition ${isActive ? "ring-2 ring-orange-400/70 ring-offset-2 ring-offset-zinc-950" : ""}`}
                  >
                    <AttackPathCard
                      nodes={pathNodes}
                      riskScore={path.composite_risk}
                      captureMode={captureMode}
                      onClick={() => {
                        setReachabilitySummary(null);
                        setReachabilityError(null);
                        const clearing = effectiveSelectedAttackPathKey === key;
                        setAutoPathDismissed(clearing);
                        setSelectedAttackPathKey(clearing ? null : key);
                      }}
                    />
                  </div>
                );
              })}
            </div>

            {selectedAttackPath && (
              <div className="mt-3 grid gap-2 lg:grid-cols-4">
                <PathStat
                  label="Composite risk"
                  value={selectedAttackPath.composite_risk.toFixed(1)}
                  tone="red"
                />
                <PathStat
                  label="Hop count"
                  value={String(
                    Math.max(0, selectedAttackPath.hops.length - 1),
                  )}
                />
                <PathStat
                  label="Credential exposure"
                  value={
                    selectedAttackPath.credential_exposure.length > 0
                      ? selectedAttackPath.credential_exposure.length.toString()
                      : "none"
                  }
                  tone={
                    selectedAttackPath.credential_exposure.length > 0
                      ? "amber"
                      : "zinc"
                  }
                />
                <PathStat
                  label="Tool exposure"
                  value={
                    selectedAttackPath.tool_exposure.length > 0
                      ? selectedAttackPath.tool_exposure.length.toString()
                      : "none"
                  }
                  tone={
                    selectedAttackPath.tool_exposure.length > 0
                      ? "blue"
                      : "zinc"
                  }
                />
                <PathTagList
                  label="Summary"
                  tags={[selectedAttackPath.summary || "No summary provided"]}
                  wide
                />
                {selectedAttackPath.vuln_ids.length > 0 && (
                  <PathTagList
                    label="Findings"
                    tags={selectedAttackPath.vuln_ids}
                  />
                )}
                {selectedAttackPath.credential_exposure.length > 0 && (
                  <PathTagList
                    label="Credentials"
                    tags={selectedAttackPath.credential_exposure}
                  />
                )}
                {selectedAttackPath.tool_exposure.length > 0 && (
                  <PathTagList
                    label="Tools"
                    tags={selectedAttackPath.tool_exposure}
                  />
                )}
              </div>
            )}
          </details>
        )}
      </div>

      <div className="flex-1 flex relative min-h-[68vh]">
        <div className="flex-1 relative min-h-[60vh] flex flex-col">
          <div className="mb-2 shrink-0 px-1">
            <GraphLensSwitcher variant="compact" />
          </div>
          <div className="relative min-h-0 flex-1">
          {loadingGraph && !graphData ? (
            <GraphPanelSkeleton
              title="Loading graph window"
              detail={`Fetching the selected snapshot with the ${graphScopeLabelForFilters(filters).toLowerCase()} scope and active layer filters.`}
            />
          ) : graphPanelError ? (
            <GraphEmptyState
              title={graphPanelError.title}
              detail={graphPanelError.detail}
              suggestions={graphPanelError.suggestions}
            />
          ) : displayNodes.length === 0 ? (
            <GraphEmptyState
              title="No nodes match the current graph scope"
              detail="The current combination of layers, severity, agent, depth, and runtime scope filtered everything out."
              suggestions={[
                "Drop the severity threshold or turn off vulnerable-only.",
                "Switch from Relevant paths to Expanded when you need broader topology.",
                "Re-enable the package or server layers to recover the path context.",
              ]}
              command="agent-bom agents --demo --offline"
            />
          ) : graphOnlyFindings ? (
            <GraphFindingsFallback
              nodes={findingNodes}
              onSelect={selectFindingCard}
              scanId={selectedScanId || undefined}
              onExpandScope={() =>
                setFilters(
                  createExpandedGraphFilters(
                    filters.agentName ?? flow.agentNames[0] ?? null,
                  ),
                )
              }
            />
          ) : graphRenderer.kind === "large-overview" ? (
            <LargeGraphOverview
              nodes={displayNodes}
              edges={displayEdges}
              legendItems={legendItems}
              onNodeSelect={onLargeGraphNodeSelect}
            />
          ) : graphRenderer.kind === "webgl" ? (
            <SigmaGraphOverview
              nodes={displayNodes}
              edges={displayEdges}
              legendItems={legendItems}
              onNodeSelect={onLargeGraphNodeSelect}
            />
          ) : (
            <ReactFlow
              key={captureMode ? "lineage-capture" : "lineage-interactive"}
              nodes={displayNodes}
              edges={displayEdges}
              nodeTypes={lineageNodeTypesAdaptive}
              fitView
              fitViewOptions={viewportOptions}
              minZoom={0.16}
              maxZoom={2.5}
              zoomOnScroll={false}
              panOnScroll={false}
              preventScrolling={false}
              onlyRenderVisibleElements
              defaultEdgeOptions={{ type: "smoothstep" }}
              proOptions={{ hideAttribution: true }}
              onNodeClick={onNodeClick}
              onNodeMouseEnter={onNodeMouseEnter}
              onNodeMouseLeave={onNodeMouseLeave}
              onPaneClick={() => {
                setSelectedNode(null);
                setSelectedNodeId(null);
                setHoveredNodeId(null);
                // #2257: empty-pane click clears the pinned focus too,
                // so the operator always has a single deterministic
                // gesture to "stop focusing".
                setPinnedFocusId(null);
                setReachabilitySummary(null);
                setReachabilityError(null);
                setBlastRadius(null);
                setBlastError(null);
              }}
            >
              <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
              <Controls className={CONTROLS_CLASS} />
              {showMiniMap && (
                <MiniMap
                  nodeColor={minimapNodeColor}
                  className={MINIMAP_CLASS}
                  bgColor={MINIMAP_BG}
                  maskColor={MINIMAP_MASK}
                />
              )}
              {/* Dock legend on the canvas itself so node-color -> entity-type
                  is one glance away. */}
              <Panel position="top-right" className="!m-2">
                <GraphLegend items={legendItems} />
              </Panel>
            </ReactFlow>
          )}

          {loadingGraph && graphData && <GraphRefreshOverlay />}

          {selectedNode && (
            <LineageDetailPanel
              data={selectedNode}
              onClose={() => {
                setSelectedNode(null);
                setSelectedNodeId(null);
              }}
              blastRadiusActive={blastRadius?.rootId === selectedNodeId}
              blastRadiusLoading={loadingBlast}
              onShowBlastRadius={
                selectedNodeId
                  ? () =>
                      void loadBlastRadius(
                        selectedNodeId,
                        selectedNode.label ?? selectedNodeId,
                      )
                  : undefined
              }
            />
          )}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  value,
  label,
  accent = "zinc",
}: {
  value: number;
  label: string;
  accent?: "zinc" | "red" | "orange" | "blue";
}) {
  const accentClass =
    accent === "red"
      ? "border-red-500/20 bg-red-500/10 text-red-200"
      : accent === "orange"
        ? "border-orange-500/20 bg-orange-500/10 text-orange-200"
        : accent === "blue"
          ? "border-sky-500/20 bg-sky-500/10 text-sky-200"
          : "border-zinc-800 bg-zinc-900/80 text-zinc-300";

  return (
    <div className={`rounded-xl border px-3 py-1.5 text-xs ${accentClass}`}>
      <span className="font-mono text-zinc-100">{value}</span> {label}
    </div>
  );
}

function ViewPill({ label, value }: { label: string; value: string }) {
  return (
    <span className="rounded-lg border border-zinc-800 bg-zinc-900/80 px-2.5 py-1">
      <span className="text-zinc-500">{label}</span>
      <span className="ml-1 text-zinc-300">{value}</span>
    </span>
  );
}

function ReachabilityDrillInPanel({
  summary,
  loading,
  error,
  onClear,
}: {
  summary: ReachabilitySummary | null;
  loading: boolean;
  error: string | null;
  onClear: () => void;
}) {
  const affectedCount = summary ? Math.max(0, summary.nodeIds.size - 1) : 0;
  return (
    <div className="mt-3 rounded-2xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-100">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Route className="mt-0.5 h-4 w-4 text-rose-300" />
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-rose-300">
              Reachability drill-in
            </p>
            <p className="mt-1 text-sm font-medium text-rose-50">
              {summary
                ? `${summary.rootLabel} can reach ${affectedCount} node${affectedCount === 1 ? "" : "s"}`
                : "Loading reachable graph"}
            </p>
            {summary?.truncated && (
              <p className="mt-1 text-[11px] text-amber-200">
                Traversal budget reached; narrow the graph or inspect a smaller
                root.
              </p>
            )}
            {error && (
              <p className="mt-1 text-[11px] text-amber-200">{error}</p>
            )}
            {loading && (
              <p className="mt-1 flex items-center gap-1 text-[11px] text-rose-200">
                <Loader2 className="h-3 w-3 animate-spin" />
                Refreshing reachability
              </p>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="rounded-lg border border-rose-400/30 bg-rose-950/60 px-2.5 py-1 text-rose-100 transition hover:border-rose-300"
        >
          Clear reachability
        </button>
      </div>

      {summary && (
        <div className="mt-3 grid gap-3 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
          <div className="rounded-xl border border-rose-400/20 bg-zinc-950/45 p-2">
            <p className="text-[10px] uppercase tracking-[0.2em] text-rose-300">
              Affected by type
            </p>
            {Object.keys(summary.countsByType).length === 0 ? (
              <p className="mt-2 text-zinc-400">
                No downstream nodes returned for this root.
              </p>
            ) : (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {Object.entries(summary.countsByType)
                  .sort((left, right) => right[1] - left[1])
                  .map(([type, count]) => (
                    <span
                      key={type}
                      className="rounded border border-rose-400/20 bg-rose-950/60 px-1.5 py-0.5 text-[10px] text-rose-100"
                    >
                      {prettifyReachabilityType(type)}: {count}
                    </span>
                  ))}
              </div>
            )}
          </div>

          <div className="rounded-xl border border-rose-400/20 bg-zinc-950/45 p-2">
            <p className="text-[10px] uppercase tracking-[0.2em] text-rose-300">
              Bounded paths
            </p>
            {summary.pathPreviews.length === 0 ? (
              <p className="mt-2 text-zinc-400">
                No path preview is available for this root.
              </p>
            ) : (
              <div className="mt-2 grid gap-1.5">
                {summary.pathPreviews.map((path) => (
                  <div
                    key={`${path.targetId}:${path.hops.join(">")}`}
                    className="rounded-lg bg-zinc-950/70 px-2 py-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium text-rose-50">
                        {path.targetLabel}
                      </span>
                      <span className="text-[10px] uppercase tracking-[0.16em] text-zinc-500">
                        {prettifyReachabilityType(path.targetType)} ·{" "}
                        {path.depth} hop{path.depth === 1 ? "" : "s"}
                      </span>
                    </div>
                    <p className="mt-1 truncate font-mono text-[10px] text-zinc-400">
                      {path.labels.join(" -> ")}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function BlastRadiusPanel({
  summary,
  loading,
  error,
  onClear,
}: {
  summary: BlastRadiusState | null;
  loading: boolean;
  error: string | null;
  onClear: () => void;
}) {
  return (
    <div className="mt-3 rounded-2xl border border-violet-500/30 bg-violet-500/10 p-3 text-xs text-violet-100">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Radar className="mt-0.5 h-4 w-4 text-violet-300" />
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-violet-300">
              Blast radius
            </p>
            <p className="mt-1 text-sm font-medium text-violet-50">
              {summary
                ? `${summary.affectedCount} asset${summary.affectedCount === 1 ? "" : "s"} impacted if ${summary.rootLabel} is compromised`
                : "Computing blast radius"}
            </p>
            {summary && (
              <p className="mt-1 text-[11px] text-violet-200/80">
                Reverse-dependency reach · up to {summary.maxDepthReached} hop
                {summary.maxDepthReached === 1 ? "" : "s"}
              </p>
            )}
            {error && (
              <p className="mt-1 text-[11px] text-amber-200">{error}</p>
            )}
            {loading && (
              <p className="mt-1 flex items-center gap-1 text-[11px] text-violet-200">
                <Loader2 className="h-3 w-3 animate-spin" />
                Tracing downstream dependents
              </p>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="rounded-lg border border-violet-400/30 bg-violet-950/60 px-2.5 py-1 text-violet-100 transition hover:border-violet-300"
        >
          Clear blast radius
        </button>
      </div>

      {summary && Object.keys(summary.countsByType).length > 0 && (
        <div className="mt-3 rounded-xl border border-violet-400/20 bg-zinc-950/45 p-2">
          <p className="text-[10px] uppercase tracking-[0.2em] text-violet-300">
            Impacted by type
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {Object.entries(summary.countsByType)
              .sort((left, right) => right[1] - left[1])
              .map(([type, count]) => (
                <span
                  key={type}
                  className="rounded border border-violet-400/20 bg-violet-950/60 px-1.5 py-0.5 text-[10px] text-violet-100"
                >
                  {prettifyReachabilityType(type)}: {count}
                </span>
              ))}
          </div>
        </div>
      )}

      {summary && summary.affectedCount === 0 && (
        <p className="mt-2 text-zinc-400">
          Nothing downstream depends on this node in the current snapshot.
        </p>
      )}
    </div>
  );
}

function RollupNavigationPanel({
  summary,
  estateNodeCount,
  breadcrumbs,
  loading,
  error,
  active,
  onDismiss,
  onReset,
  onBreadcrumb,
}: {
  summary: GraphRollupResponse | null;
  estateNodeCount: number;
  breadcrumbs: RollupBreadcrumb[];
  loading: boolean;
  error: string | null;
  active: boolean;
  onDismiss: () => void;
  onReset: () => void;
  onBreadcrumb: (index: number) => void;
}) {
  const visibleCount =
    summary?.mode === "drilldown"
      ? (summary.children?.length ?? 0)
      : (summary?.top_level?.length ?? 0);

  return (
    <div className="mt-3 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-100">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Layers className="mt-0.5 h-4 w-4 text-emerald-300" />
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-emerald-300">
              Estate roll-up
            </p>
            <p className="mt-1 text-sm font-medium text-emerald-50">
              {active
                ? `${visibleCount} container${visibleCount === 1 ? "" : "s"} at this level · ${estateNodeCount} nodes in snapshot`
                : `Loading CONTAINS roll-up · ${estateNodeCount} nodes in snapshot`}
            </p>
            {active && (
              <p className="mt-1 text-[11px] text-emerald-200/80">
                Click a container with descendants to drill down one CONTAINS
                level. Severity filters apply to rolled-up aggregates.
              </p>
            )}
            {error && (
              <p className="mt-1 text-[11px] text-amber-200">{error}</p>
            )}
            {loading && (
              <p className="mt-1 flex items-center gap-1 text-[11px] text-emerald-200">
                <Loader2 className="h-3 w-3 animate-spin" />
                Collapsing containment hierarchy
              </p>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          className="rounded-lg border border-emerald-400/30 bg-emerald-950/60 px-2.5 py-1 text-emerald-100 transition hover:border-emerald-300"
        >
          Show full graph
        </button>
      </div>

      {breadcrumbs.length > 0 && (
        <nav
          aria-label="Roll-up breadcrumb"
          className="mt-3 flex flex-wrap items-center gap-1 text-[11px] text-emerald-100"
        >
          <button
            type="button"
            onClick={onReset}
            className="rounded border border-emerald-400/20 bg-emerald-950/50 px-2 py-0.5 transition hover:border-emerald-300"
          >
            Estate root
          </button>
          {breadcrumbs.map((crumb, index) => (
            <span key={crumb.id} className="flex items-center gap-1">
              <span className="text-emerald-400/70">/</span>
              <button
                type="button"
                onClick={() => onBreadcrumb(index)}
                className="max-w-[12rem] truncate rounded border border-emerald-400/20 bg-emerald-950/50 px-2 py-0.5 transition hover:border-emerald-300"
              >
                {crumb.label}
              </button>
            </span>
          ))}
        </nav>
      )}
    </div>
  );
}

function scopeButtonClass(active: boolean): string {
  return active
    ? "rounded-lg border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 text-sky-100 transition hover:border-sky-400/70"
    : "rounded-lg border border-zinc-700 bg-zinc-900/80 px-2.5 py-1 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100";
}

function PathStat({
  label,
  value,
  tone = "zinc",
}: {
  label: string;
  value: string;
  tone?: "zinc" | "red" | "amber" | "blue";
}) {
  const toneClass =
    tone === "red"
      ? "border-red-500/20 bg-red-500/10 text-red-200"
      : tone === "amber"
        ? "border-amber-500/20 bg-amber-500/10 text-amber-200"
        : tone === "blue"
          ? "border-sky-500/20 bg-sky-500/10 text-sky-200"
          : "border-zinc-800 bg-zinc-900/80 text-zinc-300";

  return (
    <div className={`rounded-xl border px-3 py-2 ${toneClass}`}>
      <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
        {label}
      </p>
      <p className="mt-1 font-mono text-sm text-zinc-100">{value}</p>
    </div>
  );
}

function PathTagList({
  label,
  tags,
  wide = false,
}: {
  label: string;
  tags: string[];
  wide?: boolean;
}) {
  return (
    <div
      className={`rounded-xl border border-zinc-800 bg-zinc-900/70 p-3 ${wide ? "lg:col-span-4" : ""}`}
    >
      <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {tags.map((tag) => (
          <span
            key={`${label}-${tag}`}
            className="rounded-lg border border-zinc-700 bg-zinc-800/80 px-2 py-1 text-[11px] text-zinc-300"
          >
            {tag}
          </span>
        ))}
      </div>
    </div>
  );
}

function DiffMetric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "green" | "amber" | "blue";
}) {
  const toneClass =
    tone === "green"
      ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-200"
      : tone === "amber"
        ? "border-amber-500/20 bg-amber-500/10 text-amber-200"
        : "border-sky-500/20 bg-sky-500/10 text-sky-200";

  return (
    <div className={`rounded-xl border px-3 py-2 ${toneClass}`}>
      <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
        {label}
      </p>
      <p className="mt-1 font-mono text-lg text-zinc-100">{value}</p>
    </div>
  );
}

function DiffLoadingGrid() {
  return (
    <div
      className="mt-3 grid gap-2 md:grid-cols-3 xl:grid-cols-5"
      data-testid="graph-diff-loading"
    >
      {[
        "nodes added",
        "nodes removed",
        "nodes changed",
        "edges added",
        "edges removed",
      ].map((label) => (
        <div
          key={label}
          className="rounded-xl border border-zinc-800 bg-zinc-900/70 px-3 py-2"
        >
          <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
            {label}
          </p>
          <div className="mt-2 h-6 w-12 animate-pulse rounded-full bg-zinc-800" />
        </div>
      ))}
    </div>
  );
}

function DiffPreview({ label, items }: { label: string; items: string[] }) {
  const visible = items.slice(0, 5);
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">
          {label}
        </p>
        <span className="font-mono text-[11px] text-zinc-500">
          {items.length}
        </span>
      </div>
      <div className="mt-2 space-y-1">
        {visible.map((item) => (
          <p
            key={`${label}-${item}`}
            className="truncate font-mono text-[11px] text-zinc-300"
          >
            {item}
          </p>
        ))}
        {items.length > visible.length && (
          <p className="text-[11px] text-zinc-500">
            +{items.length - visible.length} more
          </p>
        )}
      </div>
    </div>
  );
}
