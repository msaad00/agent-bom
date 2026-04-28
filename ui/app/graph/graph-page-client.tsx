"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AlertTriangle, Loader2, ShieldAlert } from "lucide-react";

import { AttackPathCard } from "@/components/attack-path-card";
import { GraphLegend, FullscreenButton } from "@/components/graph-chrome";
import { LineageDetailPanel } from "@/components/lineage-detail";
import {
  GraphControlGroup,
  GraphEmptyState,
  GraphFindingsFallback,
  GraphPanelSkeleton,
  GraphRefreshOverlay,
} from "@/components/graph-state-panels";
import {
  FilterPanel,
  DEFAULT_FILTERS,
  createExpandedGraphFilters,
  createFocusedGraphFilters,
  type FilterState,
} from "@/components/lineage-filter";
import { lineageNodeTypes, type LineageNodeData, type LineageNodeType } from "@/components/lineage-nodes";
import { useDagreLayout } from "@/lib/use-dagre-layout";
import {
  EntityType,
  RelationshipType,
  type UnifiedNode,
} from "@/lib/graph-schema";
import { attackPathKey, toAttackCardNodes } from "@/lib/attack-paths";
import {
  BACKGROUND_COLOR,
  BACKGROUND_GAP,
  CONTROLS_CLASS,
  legendItemsForVisibleGraph,
  MINIMAP_BG,
  MINIMAP_CLASS,
  MINIMAP_MASK,
  minimapNodeColor,
} from "@/lib/graph-utils";
import {
  api,
  type GraphDiffResponse,
  type GraphNodeDetailResponse,
  type GraphSnapshot,
  type UnifiedGraphResponse,
} from "@/lib/api";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";

function PulseStyles() {
  return (
    <style jsx global>{`
      @keyframes pulse-critical {
        0%, 100% { box-shadow: 0 0 8px rgba(239, 68, 68, 0.4); }
        50% { box-shadow: 0 0 20px rgba(239, 68, 68, 0.8); }
      }
      .node-critical-pulse {
        animation: pulse-critical 2s ease-in-out infinite;
      }
    `}</style>
  );
}

function getConnectedIds(nodeId: string, edges: Edge[]): Set<string> {
  const adjacency = new Map<string, Set<string>>();
  for (const edge of edges) {
    addNeighbor(adjacency, edge.source, edge.target);
    addNeighbor(adjacency, edge.target, edge.source);
  }

  const visited = new Set<string>([nodeId]);
  const queue = [nodeId];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (visited.has(neighbor)) continue;
      visited.add(neighbor);
      queue.push(neighbor);
    }
  }

  return visited;
}

function addNeighbor(map: Map<string, Set<string>>, source: string, target: string): void {
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
];

const RELATIONSHIP_SCOPE_MAP: Record<FilterState["relationshipScope"], RelationshipType[] | undefined> = {
  all: undefined,
  inventory: [
    RelationshipType.HOSTS,
    RelationshipType.USES,
    RelationshipType.DEPENDS_ON,
    RelationshipType.PROVIDES_TOOL,
    RelationshipType.EXPOSES_CRED,
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
  ],
  runtime: [
    RelationshipType.INVOKED,
    RelationshipType.ACCESSED,
    RelationshipType.DELEGATED_TO,
  ],
  governance: [
    RelationshipType.MANAGES,
    RelationshipType.OWNS,
    RelationshipType.PART_OF,
    RelationshipType.MEMBER_OF,
  ],
};

function entityTypesForLayers(filters: FilterState): EntityType[] {
  return LAYER_ENTITY_TYPES.filter(([layer]) => filters.layers[layer]).map(([, entityType]) => entityType);
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
  return LAYER_ENTITY_TYPES.find(([, current]) => current === entityType)?.[0] ?? "server";
}

function stringAttribute(attributes: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = attributes?.[key];
  return typeof value === "string" ? value : undefined;
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
    version: stringAttribute(attributes, "version") || stringAttribute(attributes, "hash"),
    ecosystem: stringAttribute(attributes, "ecosystem"),
    command:
      stringAttribute(attributes, "command") ||
      stringAttribute(attributes, "transport") ||
      stringAttribute(attributes, "url"),
    agentType: stringAttribute(attributes, "agent_type"),
    agentStatus: stringAttribute(attributes, "status"),
  };
}

function mergeNodeDetail(base: LineageNodeData, detail: GraphNodeDetailResponse): LineageNodeData {
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
    dataSources: detail.node.data_sources?.length ? detail.node.data_sources : base.dataSources,
    complianceTags: detail.node.compliance_tags?.length ? detail.node.compliance_tags : base.complianceTags,
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
    version: base.version || stringAttribute(mergedAttributes, "version") || stringAttribute(mergedAttributes, "hash"),
    ecosystem: base.ecosystem || stringAttribute(mergedAttributes, "ecosystem"),
    command:
      base.command ||
      stringAttribute(mergedAttributes, "command") ||
      stringAttribute(mergedAttributes, "transport") ||
      stringAttribute(mergedAttributes, "url"),
    agentType: base.agentType || stringAttribute(mergedAttributes, "agent_type"),
    agentStatus: base.agentStatus || stringAttribute(mergedAttributes, "status"),
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

function graphErrorState(message: string): { title: string; detail: string; suggestions: string[] } {
  const lowered = message.toLowerCase();
  if (lowered.includes("budget") || lowered.includes("limit") || lowered.includes("too large")) {
    return {
      title: "Graph query budget reached",
      detail: message,
      suggestions: [
        "Reduce depth or page size before retrying.",
        "Switch back to Focused view for operator triage.",
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
  if (lowered.includes("permission") || lowered.includes("tenant") || lowered.includes("forbidden") || lowered.includes("unauthorized")) {
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

export default function GraphPageClient() {
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
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedAttackPathKey, setSelectedAttackPathKey] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UnifiedNode[]>([]);
  const [searching, setSearching] = useState(false);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);
  const [initializedFocus, setInitializedFocus] = useState(false);

  useEffect(() => {
    setLoadingSnapshots(true);
    api
      .getGraphSnapshots(40)
      .then((items) => {
        setSnapshots(items);
        if (items.length > 0) {
          setSelectedScanId((current) => current || items[0]!.scan_id);
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoadingSnapshots(false));
  }, []);

  const serverEntityTypes = useMemo(() => entityTypesForLayers(filters), [filters]);

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
  }, [serverFilterKey]);

  useEffect(() => {
    setSearchResults([]);
    setSearchQuery("");
    setSelectedAttackPathKey(null);
    setFilters(DEFAULT_FILTERS);
    setInitializedFocus(false);
  }, [selectedScanId]);

  useEffect(() => {
    if (!selectedScanId) {
      setGraphData(null);
      return;
    }

    if (serverEntityTypes.length === 0) {
      setGraphData(emptyGraphResponse(selectedScanId));
      setSelectedNode(null);
      setError(null);
      return;
    }

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
        setGraphData(result);
        setError(null);
      })
      .catch((e) => {
        setError(e.message);
        setGraphData(null);
      })
      .finally(() => setLoadingGraph(false));
  }, [
    selectedScanId,
    serverEntityTypes,
    serverRelationships,
    filters.runtimeMode,
    filters.maxDepth,
    filters.severity,
    filters.pageSize,
    pageOffset,
  ]);

  const activeSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );
  const previousSnapshot = useMemo(() => {
    const index = snapshots.findIndex((snapshot) => snapshot.scan_id === selectedScanId);
    if (index < 0 || index + 1 >= snapshots.length) return null;
    return snapshots[index + 1];
  }, [snapshots, selectedScanId]);

  useEffect(() => {
    let cancelled = false;
    setGraphDiff(null);
    setDiffError(null);
    if (!selectedScanId || !previousSnapshot) {
      setLoadingDiff(false);
      return;
    }
    setLoadingDiff(true);
    api
      .getGraphDiff(previousSnapshot.scan_id, selectedScanId)
      .then((result) => {
        if (!cancelled) setGraphDiff(result);
      })
      .catch((e) => {
        if (!cancelled) setDiffError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoadingDiff(false);
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

  const attackPaths = useMemo(
    () =>
      [...(graphData?.attack_paths ?? [])].sort(
        (left, right) =>
          right.composite_risk - left.composite_risk || right.hops.length - left.hops.length,
      ),
    [graphData?.attack_paths],
  );

  const selectedAttackPath = useMemo(
    () =>
      selectedAttackPathKey
        ? attackPaths.find((path) => attackPathKey(path) === selectedAttackPathKey) ?? null
        : null,
    [attackPaths, selectedAttackPathKey],
  );

  useEffect(() => {
    if (!selectedAttackPathKey) return;
    if (!attackPaths.some((path) => attackPathKey(path) === selectedAttackPathKey)) {
      setSelectedAttackPathKey(null);
    }
  }, [attackPaths, selectedAttackPathKey]);

  const flow = useMemo(() => {
    if (!graphData) {
      return { nodes: [], edges: [], agentNames: [], legend: [], summary: null as null | ReturnType<typeof buildUnifiedFlowGraph>["summary"] };
    }
    return buildUnifiedFlowGraph(graphData, filters);
  }, [graphData, filters]);

  useEffect(() => {
    if (initializedFocus || flow.agentNames.length === 0) return;
    setFilters(createFocusedGraphFilters(flow.agentNames[0]));
    setInitializedFocus(true);
  }, [flow.agentNames, initializedFocus]);

  const flowNodeDataById = useMemo(
    () => new Map(flow.nodes.map((node) => [node.id, node.data])),
    [flow.nodes],
  );

  const { nodes: layoutNodes, edges: layoutEdges } = useDagreLayout(flow.nodes, flow.edges, {
    direction: filters.agentName || filters.vulnOnly ? "TB" : "LR",
    nodeWidth: filters.agentName ? 208 : 188,
    nodeHeight: 72,
    rankSep: filters.agentName ? 118 : 104,
    nodeSep: filters.agentName ? 22 : 28,
  });

  const connectedIds = useMemo(
    () => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null),
    [hoveredNodeId, layoutEdges],
  );

  const attackPathNodeIds = useMemo(
    () => (selectedAttackPath ? new Set(selectedAttackPath.hops) : null),
    [selectedAttackPath],
  );

  const attackPathEdgeKeys = useMemo(
    () => (selectedAttackPath ? buildPathEdgeKeys(selectedAttackPath.hops) : null),
    [selectedAttackPath],
  );

  const displayNodes = useMemo(() => {
    if (attackPathNodeIds) {
      return layoutNodes.map((node) => ({
        ...node,
        data: {
          ...node.data,
          dimmed: !attackPathNodeIds.has(node.id),
          highlighted: attackPathNodeIds.has(node.id),
        },
      }));
    }
    if (!connectedIds) return layoutNodes;
    return layoutNodes.map((node) => ({
      ...node,
      data: {
        ...node.data,
        dimmed: !connectedIds.has(node.id),
        highlighted: connectedIds.has(node.id),
      },
    }));
  }, [layoutNodes, connectedIds, attackPathNodeIds]);

  const displayEdges = useMemo(() => {
    if (attackPathEdgeKeys) {
      return layoutEdges.map((edge): Edge => {
        const inPath = attackPathEdgeKeys.has(`${edge.source}=>${edge.target}`);
        return {
          ...edge,
          animated: Boolean(inPath || edge.animated),
          style: {
            ...edge.style,
            opacity: inPath ? 1 : 0.08,
            strokeWidth: inPath
              ? Math.max(typeof edge.style?.strokeWidth === "number" ? edge.style.strokeWidth : 2, 3.2)
              : 1,
            ...(inPath ? { filter: "drop-shadow(0 0 6px rgba(249,115,22,0.55))" } : {}),
          },
        };
      });
    }
    if (!connectedIds) return layoutEdges;
    return layoutEdges.map((edge) => ({
      ...edge,
      style: {
        ...edge.style,
        opacity: connectedIds.has(edge.source) && connectedIds.has(edge.target) ? 1 : 0.12,
      },
    }));
  }, [layoutEdges, connectedIds, attackPathEdgeKeys]);

  const legendItems = useMemo(
    () => legendItemsForVisibleGraph(displayNodes, displayEdges),
    [displayEdges, displayNodes],
  );

  const hasContextualGraph = useMemo(
    () => displayNodes.some((node) => {
      const nodeType = (node.data as LineageNodeData).nodeType;
      return nodeType !== "vulnerability" && nodeType !== "misconfiguration";
    }),
    [displayNodes],
  );

  const graphOnlyFindings = displayNodes.length > 0 && !hasContextualGraph;
  const graphPanelError = error && snapshots.length > 0 ? graphErrorState(error) : null;
  const findingNodes = useMemo(
    () =>
      displayNodes
        .filter((node) => {
          const nodeType = (node.data as LineageNodeData).nodeType;
          return nodeType === "vulnerability" || nodeType === "misconfiguration";
        })
        .map((node) => ({ id: node.id, data: node.data as LineageNodeData })),
    [displayNodes],
  );

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    const data = node.data as LineageNodeData;
    setSelectedNode({
      ...data,
      attributes: {
        ...(data.attributes ?? {}),
        node_id: node.id,
      },
    });
    setSelectedNodeId(node.id);
    setSelectedAttackPathKey(null);
    setHoveredNodeId(null);
  }, []);

  const onNodeMouseEnter = useCallback((_event: React.MouseEvent, node: Node) => {
    setHoveredNodeId(node.id);
  }, []);

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
  }, []);

  const runSearch = useCallback(async () => {
    const query = searchQuery.trim();
    if (!query || !selectedScanId) {
      setSearchResults([]);
      return;
    }
    setSearching(true);
    try {
      const response = await api.searchGraph(query, { scanId: selectedScanId, limit: 8 });
      setSearchResults(response.results);
    } catch {
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }, [searchQuery, selectedScanId]);

  const focusSearchResult = useCallback(
    (node: UnifiedNode) => {
      const fallback = flowNodeDataById.get(node.id) ?? buildFallbackNodeData(node);
      setSelectedNode({
        ...fallback,
        attributes: {
          ...(fallback.attributes ?? {}),
          node_id: node.id,
        },
      });
      setSelectedNodeId(node.id);
      setHoveredNodeId(node.id);
      setSelectedAttackPathKey(null);
      setSearchResults([]);
      setSearchQuery(node.label);
    },
    [flowNodeDataById],
  );

  const pageStart = graphData && graphData.pagination.total > 0 ? graphData.pagination.offset + 1 : 0;
  const pageEnd =
    graphData && graphData.pagination.total > 0
      ? Math.min(graphData.pagination.offset + graphData.pagination.limit, graphData.pagination.total)
      : 0;
  const pageNumber =
    graphData && graphData.pagination.limit > 0
      ? Math.floor(graphData.pagination.offset / graphData.pagination.limit) + 1
      : 1;
  const totalPages =
    graphData && graphData.pagination.limit > 0
      ? Math.max(1, Math.ceil(graphData.pagination.total / graphData.pagination.limit))
      : 1;
  const relationshipScopeLabel =
    filters.relationshipScope === "all"
      ? "all relationships"
      : `${filters.relationshipScope} relationships`;
  const runtimeModeLabel =
    filters.runtimeMode === "all"
      ? "static + runtime"
      : filters.runtimeMode === "static"
        ? "static only"
        : "runtime only";

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
        <p className="text-xs text-zinc-500">Run a scan first so the API can persist graph snapshots.</p>
      </div>
    );
  }

  if (snapshots.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <ShieldAlert className="w-8 h-8 text-zinc-600" />
        <p className="text-sm">No graph snapshots found</p>
        <p className="text-xs text-zinc-500">Run a scan to persist the unified inventory and security graph.</p>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      <PulseStyles />

      <div className="border-b border-zinc-800 bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.12),transparent_26%),linear-gradient(180deg,rgba(24,24,27,0.96),rgba(9,9,11,0.96))] px-4 py-4">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-sky-400">Unified graph</p>
            <h1 className="mt-1 text-lg font-semibold text-zinc-100">Security Graph</h1>
            <p className="text-xs text-zinc-500">
              Focused agent-to-finding graph with packages, credentials, tools, and runtime links.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 xl:justify-end">
            {flow.summary && (
              <>
                <MetricCard value={flow.summary.agents} label="agents" />
                <MetricCard value={flow.summary.servers} label="servers" />
                <MetricCard value={flow.summary.findings} label="findings" accent="orange" />
                <MetricCard value={flow.summary.critical} label="critical" accent="red" />
                <MetricCard value={flow.summary.attackPaths} label="paths" accent="blue" />
              </>
            )}

            <select
              value={selectedScanId}
              onChange={(event) => setSelectedScanId(event.target.value)}
              className="rounded-xl border border-zinc-700 bg-zinc-900/90 px-3 py-2 text-sm text-zinc-300 focus:border-sky-600 focus:outline-none"
            >
              {snapshots.map((snapshot) => (
                <option key={snapshot.scan_id} value={snapshot.scan_id}>
                  {snapshot.scan_id.slice(0, 12)} · {new Date(snapshot.created_at).toLocaleString()}
                </option>
              ))}
            </select>

            <FullscreenButton />
            <GraphLegend items={legendItems} />
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

          <div className="mt-3 flex flex-wrap gap-4 text-[11px]">
            <GraphControlGroup label="View">
              <button
                type="button"
                onClick={() => setFilters(createFocusedGraphFilters(filters.agentName ?? flow.agentNames[0] ?? null))}
                className="rounded-lg border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-sky-200 transition hover:border-sky-400/60"
              >
                Focused
              </button>
              <button
                type="button"
                onClick={() => setFilters(createExpandedGraphFilters(null))}
                className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-2.5 py-1 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100"
              >
                Expanded
              </button>
            </GraphControlGroup>
            <GraphControlGroup label="Scope">
              <span className="rounded-lg border border-zinc-800 bg-zinc-900/80 px-2.5 py-1 text-zinc-400">
                {filters.agentName ? `agent ${filters.agentName}` : "all agents"}
              </span>
            </GraphControlGroup>
            <GraphControlGroup label="Filters">
              <span className="rounded-lg border border-zinc-800 bg-zinc-900/80 px-2.5 py-1 text-zinc-400">
                {filters.severity ? `${filters.severity}+` : "all severities"}
              </span>
              <span className="rounded-lg border border-zinc-800 bg-zinc-900/80 px-2.5 py-1 text-zinc-400">
                depth {filters.maxDepth}
              </span>
              {filters.vulnOnly && (
                <span className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-emerald-200">
                  vulnerable only
                </span>
              )}
            </GraphControlGroup>
          </div>

          <div className="mt-2 text-xs text-zinc-500">
            {graphOnlyFindings
              ? "This scope currently resolves to findings without surrounding context. Relax filters or expand the view to recover package, server, and agent relationships."
              : filters.agentName
                ? `Focused on ${filters.agentName}. Expand only when you need more of the surrounding graph.`
                : "Focused view keeps the graph scoped. Use Expanded when you need broader topology."}
          </div>

          {searchResults.length > 0 && (
            <div className="mt-2 rounded-2xl border border-zinc-800 bg-zinc-950/90 p-2">
              <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
                {searchResults.map((result) => (
                  <button
                    key={result.id}
                    type="button"
                    onClick={() => focusSearchResult(result)}
                    className="rounded-xl border border-zinc-800 bg-zinc-900/80 px-3 py-2 text-left transition hover:border-zinc-600 hover:bg-zinc-900"
                  >
                    <p className="truncate text-sm font-medium text-zinc-100">{result.label}</p>
                    <p className="mt-1 text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                      {String(result.entity_type)}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-zinc-500">
                      {result.severity && <span>{result.severity}</span>}
                      <span>
                        risk{" "}
                        {typeof result.risk_score === "number" && Number.isFinite(result.risk_score)
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
              <span>captured {new Date(activeSnapshot.created_at).toLocaleString()}</span>
            </>
          )}
          {graphData && graphData.pagination.total > 0 && (
            <span>
              showing {pageStart}-{pageEnd} of {graphData.pagination.total} nodes
            </span>
          )}
          {loadingGraph && (
            <span className="flex items-center gap-1 text-sky-400">
              <Loader2 className="w-3 h-3 animate-spin" />
              refreshing graph
            </span>
          )}
        </div>

        {activeSnapshot && graphData && (
          <div className="mt-4 grid gap-3 lg:grid-cols-4">
            <SnapshotMetaCard
              label="Snapshot"
              value={`${activeSnapshot.scan_id.slice(0, 12)}…`}
              detail={`Persisted ${new Date(activeSnapshot.created_at).toLocaleString()}`}
            />
            <SnapshotMetaCard
              label="Topology"
              value={`${activeSnapshot.node_count} nodes · ${activeSnapshot.edge_count} edges`}
              detail={`${graphData.attack_paths.length} attack paths on this page`}
            />
            <SnapshotMetaCard
              label="Scope"
              value={filters.agentName ? filters.agentName : "all agents"}
              detail={`${relationshipScopeLabel} · ${runtimeModeLabel}`}
            />
            <SnapshotMetaCard
              label="Window"
              value={graphData.pagination.total > 0 ? `${pageStart}-${pageEnd} of ${graphData.pagination.total}` : "empty"}
              detail={`page ${pageNumber} of ${totalPages} · depth ${filters.maxDepth}`}
            />
          </div>
        )}

        {activeSnapshot && (
          <div className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-[10px] uppercase tracking-[0.24em] text-sky-400">Snapshot diff</p>
                <p className="mt-1 text-xs text-zinc-500">
                  {previousSnapshot
                    ? `Compared with ${previousSnapshot.scan_id.slice(0, 12)} captured ${new Date(previousSnapshot.created_at).toLocaleString()}`
                    : "No older snapshot available for this tenant."}
                </p>
              </div>
              {loadingDiff && (
                <span className="flex items-center gap-1 text-xs text-sky-400">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  loading diff
                </span>
              )}
            </div>
            {diffError ? (
              <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                {diffError}
              </div>
            ) : loadingDiff && !graphDiff ? (
              <DiffLoadingGrid />
            ) : (
              <div className="mt-3 grid gap-2 md:grid-cols-3 xl:grid-cols-5">
                <DiffMetric label="nodes added" value={graphDiff?.nodes_added.length ?? 0} tone="green" />
                <DiffMetric label="nodes removed" value={graphDiff?.nodes_removed.length ?? 0} tone="amber" />
                <DiffMetric label="nodes changed" value={graphDiff?.nodes_changed.length ?? 0} tone="blue" />
                <DiffMetric label="edges added" value={graphDiff?.edges_added.length ?? 0} tone="green" />
                <DiffMetric label="edges removed" value={graphDiff?.edges_removed.length ?? 0} tone="amber" />
              </div>
            )}
            {graphDiff && (graphDiff.nodes_added.length > 0 || graphDiff.nodes_changed.length > 0 || graphDiff.nodes_removed.length > 0) && (
              <div className="mt-3 grid gap-2 lg:grid-cols-3">
                <DiffPreview label="Added" items={graphDiff.nodes_added} />
                <DiffPreview label="Changed" items={graphDiff.nodes_changed} />
                <DiffPreview label="Removed" items={graphDiff.nodes_removed} />
              </div>
            )}
          </div>
        )}

        <div className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3 text-xs text-zinc-400">
          <div className="font-medium text-zinc-200">How to read this graph</div>
          <ul className="mt-2 space-y-1.5">
            <li>Each snapshot is a persisted control-plane view of entities, edges, attack paths, and relationship counts at one capture time.</li>
            <li>Node IDs are stable identifiers inside the graph model; the detail panel shows the node ID, first seen, last seen, sources, and edge counts.</li>
            <li>Pagination changes the visible canvas, not the persisted snapshot itself. Narrow the scope when the graph gets large; page when you need broader coverage.</li>
            <li>Focused view is for operator triage. Expanded view is for topology review. Attack-path cards are the fix-first shortlist, not the whole graph.</li>
          </ul>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <button
            type="button"
            onClick={() => setPageOffset((current) => Math.max(0, current - filters.pageSize))}
            disabled={loadingGraph || pageOffset === 0}
            className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-3 py-1.5 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Previous page
          </button>
          <button
            type="button"
            onClick={() => setPageOffset((current) => current + filters.pageSize)}
            disabled={loadingGraph || !graphData?.pagination.has_more}
            className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-3 py-1.5 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next page
          </button>
          <span className="text-zinc-500">
            Page {pageNumber} of {totalPages}
          </span>
          {graphData?.pagination.has_more && (
            <span className="text-amber-400">Large snapshot: narrow the graph or keep paging.</span>
          )}
        </div>

        {attackPaths.length > 0 && (
          <div className="mt-4 rounded-2xl border border-zinc-800 bg-zinc-950/60 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-[10px] uppercase tracking-[0.24em] text-orange-400">Attack paths</p>
                <p className="mt-1 text-xs text-zinc-500">
                  Focus the current graph on a precomputed exploit chain in this filtered snapshot page.
                </p>
              </div>
              {selectedAttackPath && (
                <button
                  type="button"
                  onClick={() => setSelectedAttackPathKey(null)}
                  className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-3 py-1.5 text-xs text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100"
                >
                  Clear path focus
                </button>
              )}
            </div>

            <div className="mt-3 flex gap-3 overflow-x-auto pb-1">
              {attackPaths.slice(0, 6).map((path) => {
                const key = attackPathKey(path);
                const pathNodes = toAttackCardNodes(path, graphNodeById);
                if (pathNodes.length === 0) return null;
                const isActive = selectedAttackPathKey === key;
                return (
                  <div
                    key={key}
                    className={`min-w-[360px] rounded-2xl transition ${isActive ? "ring-2 ring-orange-400/70 ring-offset-2 ring-offset-zinc-950" : ""}`}
                  >
                    <AttackPathCard
                      nodes={pathNodes}
                      riskScore={path.composite_risk}
                      onClick={() => setSelectedAttackPathKey((current) => (current === key ? null : key))}
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
                  value={String(Math.max(0, selectedAttackPath.hops.length - 1))}
                />
                <PathStat
                  label="Credential exposure"
                  value={selectedAttackPath.credential_exposure.length > 0 ? selectedAttackPath.credential_exposure.length.toString() : "none"}
                  tone={selectedAttackPath.credential_exposure.length > 0 ? "amber" : "zinc"}
                />
                <PathStat
                  label="Tool exposure"
                  value={selectedAttackPath.tool_exposure.length > 0 ? selectedAttackPath.tool_exposure.length.toString() : "none"}
                  tone={selectedAttackPath.tool_exposure.length > 0 ? "blue" : "zinc"}
                />
                <PathTagList label="Summary" tags={[selectedAttackPath.summary || "No summary provided"]} wide />
                {selectedAttackPath.vuln_ids.length > 0 && (
                  <PathTagList label="Findings" tags={selectedAttackPath.vuln_ids} />
                )}
                {selectedAttackPath.credential_exposure.length > 0 && (
                  <PathTagList label="Credentials" tags={selectedAttackPath.credential_exposure} />
                )}
                {selectedAttackPath.tool_exposure.length > 0 && (
                  <PathTagList label="Tools" tags={selectedAttackPath.tool_exposure} />
                )}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex-1 flex relative overflow-hidden">
        <FilterPanel filters={filters} onChange={setFilters} agentNames={flow.agentNames} />

        <div className="flex-1 relative">
          {loadingGraph && !graphData ? (
            <GraphPanelSkeleton
              title="Loading graph window"
              detail="Fetching the selected snapshot with the current layer, severity, depth, and relationship filters."
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
                "Switch from Focused to Expanded when you need broader topology.",
                "Re-enable the package or server layers to recover the path context.",
              ]}
            />
          ) : graphOnlyFindings ? (
            <GraphFindingsFallback nodes={findingNodes} onSelect={selectFindingCard} />
          ) : (
            <ReactFlow
              nodes={displayNodes}
              edges={displayEdges}
              nodeTypes={lineageNodeTypes}
              fitView
              fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
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
              }}
            >
              <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
              <Controls className={CONTROLS_CLASS} />
              <MiniMap
                nodeColor={minimapNodeColor}
                className={MINIMAP_CLASS}
                bgColor={MINIMAP_BG}
                maskColor={MINIMAP_MASK}
              />
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
            />
          )}
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
      <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{label}</p>
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
    <div className={`rounded-xl border border-zinc-800 bg-zinc-900/70 p-3 ${wide ? "lg:col-span-4" : ""}`}>
      <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{label}</p>
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

function SnapshotMetaCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
      <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{label}</p>
      <p className="mt-1 font-mono text-sm text-zinc-100">{value}</p>
      <p className="mt-1 text-[11px] text-zinc-500">{detail}</p>
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
      <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{label}</p>
      <p className="mt-1 font-mono text-lg text-zinc-100">{value}</p>
    </div>
  );
}

function DiffLoadingGrid() {
  return (
    <div className="mt-3 grid gap-2 md:grid-cols-3 xl:grid-cols-5" data-testid="graph-diff-loading">
      {["nodes added", "nodes removed", "nodes changed", "edges added", "edges removed"].map((label) => (
        <div key={label} className="rounded-xl border border-zinc-800 bg-zinc-900/70 px-3 py-2">
          <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{label}</p>
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
        <p className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{label}</p>
        <span className="font-mono text-[11px] text-zinc-500">{items.length}</span>
      </div>
      <div className="mt-2 space-y-1">
        {visible.map((item) => (
          <p key={`${label}-${item}`} className="truncate font-mono text-[11px] text-zinc-300">
            {item}
          </p>
        ))}
        {items.length > visible.length && (
          <p className="text-[11px] text-zinc-500">+{items.length - visible.length} more</p>
        )}
      </div>
    </div>
  );
}
