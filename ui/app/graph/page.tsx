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

import { GraphLegend, FullscreenButton } from "@/components/graph-chrome";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { FilterPanel, DEFAULT_FILTERS, type FilterState } from "@/components/lineage-filter";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { applyDagreLayout } from "@/lib/dagre-layout";
import {
  BACKGROUND_COLOR,
  BACKGROUND_GAP,
  CONTROLS_CLASS,
  MINIMAP_CLASS,
  minimapNodeColor,
} from "@/lib/graph-utils";
import { api, type GraphSnapshot, type UnifiedGraphResponse } from "@/lib/api";
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

export default function GraphPage() {
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [graphData, setGraphData] = useState<UnifiedGraphResponse | null>(null);
  const [loadingSnapshots, setLoadingSnapshots] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);

  useEffect(() => {
    setLoadingSnapshots(true);
    api
      .getGraphSnapshots(40)
      .then((items) => {
        setSnapshots(items);
        if (items.length > 0) {
          setSelectedScanId((current) => current || items[0].scan_id);
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoadingSnapshots(false));
  }, []);

  useEffect(() => {
    if (!selectedScanId) {
      setGraphData(null);
      return;
    }

    setLoadingGraph(true);
    setSelectedNode(null);
    api
      .getGraph({ scanId: selectedScanId, limit: 5000, offset: 0 })
      .then((result) => {
        setGraphData(result);
        setError(null);
      })
      .catch((e) => {
        setError(e.message);
        setGraphData(null);
      })
      .finally(() => setLoadingGraph(false));
  }, [selectedScanId]);

  const activeSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );

  const flow = useMemo(() => {
    if (!graphData) {
      return { nodes: [], edges: [], agentNames: [], legend: [], summary: null as null | ReturnType<typeof buildUnifiedFlowGraph>["summary"] };
    }
    return buildUnifiedFlowGraph(graphData, filters);
  }, [graphData, filters]);

  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(
    () =>
      flow.nodes.length > 0
        ? applyDagreLayout(flow.nodes, flow.edges, {
            direction: "LR",
            nodeWidth: 180,
            nodeHeight: 64,
            rankSep: 110,
            nodeSep: 28,
          })
        : { nodes: [], edges: [] },
    [flow.nodes, flow.edges],
  );

  const connectedIds = useMemo(
    () => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null),
    [hoveredNodeId, layoutEdges],
  );

  const displayNodes = useMemo(() => {
    if (!connectedIds) return layoutNodes;
    return layoutNodes.map((node) => ({
      ...node,
      data: {
        ...node.data,
        dimmed: !connectedIds.has(node.id),
        highlighted: connectedIds.has(node.id),
      },
    }));
  }, [layoutNodes, connectedIds]);

  const displayEdges = useMemo(() => {
    if (!connectedIds) return layoutEdges;
    return layoutEdges.map((edge) => ({
      ...edge,
      style: {
        ...edge.style,
        opacity: connectedIds.has(edge.source) && connectedIds.has(edge.target) ? 1 : 0.12,
      },
    }));
  }, [layoutEdges, connectedIds]);

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node.data as LineageNodeData);
    setHoveredNodeId(null);
  }, []);

  const onNodeMouseEnter = useCallback((_event: React.MouseEvent, node: Node) => {
    setHoveredNodeId(node.id);
  }, []);

  const onNodeMouseLeave = useCallback(() => {
    setHoveredNodeId(null);
  }, []);

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
              Provider → Agent → Server → Package → Findings · Models · Datasets · Containers · Cloud resources · Runtime edges
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
            <GraphLegend items={flow.legend} />
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-4 text-[11px] text-zinc-500">
          {activeSnapshot && (
            <>
              <span>{activeSnapshot.node_count} nodes</span>
              <span>{activeSnapshot.edge_count} edges</span>
              <span>captured {new Date(activeSnapshot.created_at).toLocaleString()}</span>
            </>
          )}
          {graphData?.pagination.has_more && (
            <span className="text-amber-400">
              Showing {graphData.pagination.limit} of {graphData.pagination.total} nodes in this snapshot
            </span>
          )}
          {loadingGraph && (
            <span className="flex items-center gap-1 text-sky-400">
              <Loader2 className="w-3 h-3 animate-spin" />
              refreshing graph
            </span>
          )}
        </div>
      </div>

      <div className="flex-1 flex relative overflow-hidden">
        <FilterPanel filters={filters} onChange={setFilters} agentNames={flow.agentNames} />

        <div className="flex-1 relative">
          <ReactFlow
            nodes={displayNodes}
            edges={displayEdges}
            nodeTypes={lineageNodeTypes}
            fitView
            minZoom={0.05}
            maxZoom={2.5}
            defaultEdgeOptions={{ type: "smoothstep" }}
            proOptions={{ hideAttribution: true }}
            onNodeClick={onNodeClick}
            onNodeMouseEnter={onNodeMouseEnter}
            onNodeMouseLeave={onNodeMouseLeave}
            onPaneClick={() => {
              setSelectedNode(null);
              setHoveredNodeId(null);
            }}
          >
            <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
            <Controls className={CONTROLS_CLASS} />
            <MiniMap nodeColor={minimapNodeColor} className={MINIMAP_CLASS} />
          </ReactFlow>

          {selectedNode && (
            <LineageDetailPanel data={selectedNode} onClose={() => setSelectedNode(null)} />
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
