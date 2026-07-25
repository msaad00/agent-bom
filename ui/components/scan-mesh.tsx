"use client";

import { useState, useCallback, useMemo, useEffect } from "react";
import Link from "next/link";
import {
  ReactFlow, Background, Controls, MiniMap, type Node, type Edge, type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useGraphLayout } from "@/lib/use-graph-layout";
import { ArrowLeft, Loader2, AlertTriangle } from "lucide-react";
import { api, type ScanJob } from "@/lib/api";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import { MeshStats } from "@/components/mesh-stats";
import { buildMeshGraph, getConnectedIds, type MeshStatsData } from "@/lib/mesh-graph";
import { CONTROLS_CLASS, MINIMAP_CLASS, BACKGROUND_COLOR, BACKGROUND_GAP, legendItemsForVisibleNodes, minimapNodeColor, readableGraphEdges } from "@/lib/graph-utils";
import { READABLE_LINEAGE_DAGRE_LR } from "@/lib/graph-node-dimensions";
import { GraphInteractionToolbar, GraphLegend } from "@/components/graph-chrome";
import { useGraphPresentation } from "@/hooks/use-graph-presentation";
import { selectGraphSubgraph } from "@/lib/graph-presentation";

export function ScanMeshView({ id }: { id: string }) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [flowInstance, setFlowInstance] = useState<ReactFlowInstance<Node<LineageNodeData>, Edge> | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [pathFocusEnabled, setPathFocusEnabled] = useState(true);

  useEffect(() => {
    api.getScan(id).then(setJob).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, [id]);

  const { rawNodes, rawEdges, stats } = useMemo(() => {
    const empty: MeshStatsData = {
      totalAgents: 0, sharedServers: 0, uniqueCredentials: 0, toolOverlap: 0,
      credentialBlast: [], totalPackages: 0, totalVulnerabilities: 0,
      omittedCredentials: 0, omittedTools: 0, omittedPackages: 0, omittedVulnerabilities: 0,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, kevCount: 0,
    };
    if (!job?.result) return { rawNodes: [] as Node[], rawEdges: [] as Edge[], stats: empty };
    const { nodes, edges, stats } = buildMeshGraph(job.result);
    return { rawNodes: nodes, rawEdges: edges, stats };
  }, [job]);

  const pathFocusIds = useMemo(() => {
    if (!pathFocusEnabled || !stats.topExposurePath || hoveredNodeId) return null;
    return new Set(stats.topExposurePath.nodeIds);
  }, [hoveredNodeId, pathFocusEnabled, stats.topExposurePath]);
  const layoutInput = useMemo(() => selectGraphSubgraph(rawNodes, rawEdges, pathFocusIds), [pathFocusIds, rawEdges, rawNodes]);
  const { nodes: layoutNodes, edges: layoutEdges } = useGraphLayout("dagre-lr", layoutInput.nodes, layoutInput.edges, {
    dagreLr: READABLE_LINEAGE_DAGRE_LR,
  });

  const connectedIds = useMemo(() => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null), [hoveredNodeId, layoutEdges]);
  const displayNodes = useMemo(() => {
    if (pathFocusIds) {
      return layoutNodes?.map((n) => ({
        ...n,
        data: { ...n.data, dimmed: !pathFocusIds.has(n.id), highlighted: pathFocusIds.has(n.id) },
      }));
    }
    if (!connectedIds) return layoutNodes;
    return layoutNodes?.map((n) => ({ ...n, data: { ...n.data, dimmed: !connectedIds.has(n.id), highlighted: connectedIds.has(n.id) } }));
  }, [layoutNodes, connectedIds, pathFocusIds]);

  const presentation = useGraphPresentation({
    nodes: displayNodes as Node<LineageNodeData>[],
    scope: { tenantId: "local", subject: "local-viewer", snapshotId: id, lens: "mesh", scope: pathFocusEnabled ? "path" : "full" },
    layout: "dagre-lr",
  });

  const displayEdges = useMemo(() => {
    return readableGraphEdges(layoutEdges, connectedIds ?? pathFocusIds, {
      baseOpacity: 0.3,
      highSignalOpacity: 0.58,
      inactiveOpacity: 0.06,
      zoom: presentation.viewport.zoom,
    });
  }, [layoutEdges, connectedIds, pathFocusIds, presentation.viewport.zoom]);

  const legendItems = useMemo(() => legendItemsForVisibleNodes(displayNodes), [displayNodes]);

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => { setSelectedNode(node.data as LineageNodeData); setSelectedNodeId(node.id); setHoveredNodeId(null); }, []);
  const onNodeMouseEnter = useCallback((_event: React.MouseEvent, node: Node) => { setHoveredNodeId(node.id); }, []);
  const onNodeMouseLeave = useCallback(() => { setHoveredNodeId(null); }, []);

  if (loading) return <div className="flex items-center justify-center h-[80vh] text-[var(--text-secondary)]"><Loader2 className="w-5 h-5 animate-spin mr-2" />Loading mesh...</div>;

  if (error || !job?.result) return (
    <div className="flex flex-col items-center justify-center h-[80vh] text-[var(--text-secondary)] gap-3">
      <AlertTriangle className="w-8 h-8 text-amber-500" />
      <p className="text-sm">{error ?? "No scan results found"}</p>
      <Link href={`/scan?id=${id}`} className="text-xs text-emerald-400 hover:text-emerald-300 underline">Back to scan results</Link>
    </div>
  );

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2">
            <Link href={`/scan?id=${id}`} className="text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"><ArrowLeft className="w-4 h-4" /></Link>
            <h1 className="text-lg font-semibold text-[var(--foreground)]">Agent Mesh</h1>
          </div>
          <p className="text-xs text-[var(--text-tertiary)] ml-6">
            Agent-centered shared infrastructure for scan {id.slice(0, 8)} — {job.created_at ? new Date(job.created_at).toLocaleDateString() : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <GraphLegend items={legendItems} />
          <GraphInteractionToolbar
            editing={presentation.editing} hasSelection={Boolean(selectedNodeId)}
            onFitVisible={() => void flowInstance?.fitView({ padding: 0.2, duration: 240 })}
            onFitSelection={() => { const node = selectedNodeId ? flowInstance?.getNode(selectedNodeId) : undefined; if (node) void flowInstance?.fitView({ nodes: [node], padding: 0.7, duration: 240 }); }}
            onAutoLayout={presentation.autoLayout} onReset={presentation.reset} onToggleEditing={presentation.toggleEditing}
          />
        </div>
      </div>
      <MeshStats
        stats={stats}
        pathFocusActive={Boolean(pathFocusIds)}
        onTogglePathFocus={stats.topExposurePath ? () => setPathFocusEnabled((current) => !current) : undefined}
      />
      <div className="flex-1 relative">
        <ReactFlow
          key={presentation.storageKey}
          nodes={presentation.nodes} edges={displayEdges} nodeTypes={lineageNodeTypes}
          fitView={!presentation.hasSavedState}
          defaultViewport={presentation.viewport}
          minZoom={0.05} maxZoom={2.5}
          defaultEdgeOptions={{ type: "smoothstep" }}
          proOptions={{ hideAttribution: true }}
          deleteKeyCode={null}
          nodesDraggable={presentation.editing} nodesConnectable={false}
          onNodesChange={presentation.onNodesChange} onNodeDragStop={presentation.onNodeDragStop}
          onMoveEnd={presentation.onMoveEnd} onInit={setFlowInstance}
          onNodeClick={onNodeClick} onNodeMouseEnter={onNodeMouseEnter} onNodeMouseLeave={onNodeMouseLeave}
          onPaneClick={() => { setSelectedNode(null); setSelectedNodeId(null); setHoveredNodeId(null); }}
        >
          <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
          <Controls className={CONTROLS_CLASS} />
          <MiniMap nodeColor={minimapNodeColor} className={MINIMAP_CLASS} />
        </ReactFlow>
        {selectedNode && (
          <GraphEntityDrawer
            data={selectedNode}
            onClose={() => { setSelectedNode(null); setSelectedNodeId(null); }}
            enrich={false}
          />
        )}
      </div>
    </div>
  );
}
