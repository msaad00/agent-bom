"use client";

import { useState, useCallback, useMemo, useEffect } from "react";
import Link from "next/link";
import {
  ReactFlow, Background, Controls, MiniMap, type Node, type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useDagreLayout } from "@/lib/use-dagre-layout";
import { ArrowLeft, Loader2, AlertTriangle } from "lucide-react";
import { api, type ScanJob } from "@/lib/api";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { MeshStats } from "@/components/mesh-stats";
import { buildMeshGraph, getConnectedIds, type MeshStatsData } from "@/lib/mesh-graph";
import { CONTROLS_CLASS, MINIMAP_CLASS, BACKGROUND_COLOR, BACKGROUND_GAP, legendItemsForVisibleNodes, minimapNodeColor } from "@/lib/graph-utils";
import { GraphLegend } from "@/components/graph-chrome";

export function ScanMeshView({ id }: { id: string }) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  useEffect(() => {
    api.getScan(id).then(setJob).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, [id]);

  const { rawNodes, rawEdges, stats } = useMemo(() => {
    const empty: MeshStatsData = {
      totalAgents: 0, sharedServers: 0, uniqueCredentials: 0, toolOverlap: 0,
      credentialBlast: [], totalPackages: 0, totalVulnerabilities: 0,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, kevCount: 0,
    };
    if (!job?.result) return { rawNodes: [] as Node[], rawEdges: [] as Edge[], stats: empty };
    const { nodes, edges, stats } = buildMeshGraph(job.result);
    return { rawNodes: nodes, rawEdges: edges, stats };
  }, [job]);

  const { nodes: layoutNodes, edges: layoutEdges } = useDagreLayout(rawNodes, rawEdges, {
    direction: "LR",
    nodeWidth: 200,
    nodeHeight: 70,
    rankSep: 140,
    nodeSep: 25,
  });

  const connectedIds = useMemo(() => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null), [hoveredNodeId, layoutEdges]);

  const displayNodes = useMemo(() => {
    if (!connectedIds) return layoutNodes;
    return layoutNodes?.map((n) => ({ ...n, data: { ...n.data, dimmed: !connectedIds.has(n.id), highlighted: connectedIds.has(n.id) } }));
  }, [layoutNodes, connectedIds]);

  const displayEdges = useMemo(() => {
    if (!connectedIds) return layoutEdges;
    return layoutEdges?.map((e) => ({ ...e, style: { ...e.style, opacity: connectedIds.has(e.source) && connectedIds.has(e.target) ? 1 : 0.12 } }));
  }, [layoutEdges, connectedIds]);

  const legendItems = useMemo(() => legendItemsForVisibleNodes(displayNodes), [displayNodes]);

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => { setSelectedNode(node.data as LineageNodeData); setHoveredNodeId(null); }, []);
  const onNodeMouseEnter = useCallback((_event: React.MouseEvent, node: Node) => { setHoveredNodeId(node.id); }, []);
  const onNodeMouseLeave = useCallback(() => { setHoveredNodeId(null); }, []);

  if (loading) return <div className="flex items-center justify-center h-[80vh] text-zinc-400"><Loader2 className="w-5 h-5 animate-spin mr-2" />Loading mesh...</div>;

  if (error || !job?.result) return (
    <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
      <AlertTriangle className="w-8 h-8 text-amber-500" />
      <p className="text-sm">{error ?? "No scan results found"}</p>
      <Link href={`/scan?id=${id}`} className="text-xs text-emerald-400 hover:text-emerald-300 underline">Back to scan results</Link>
    </div>
  );

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div>
          <div className="flex items-center gap-2">
            <Link href={`/scan?id=${id}`} className="text-zinc-500 hover:text-zinc-300"><ArrowLeft className="w-4 h-4" /></Link>
            <h1 className="text-lg font-semibold text-zinc-100">Agent Mesh</h1>
          </div>
          <p className="text-xs text-zinc-500 ml-6">
            Agent-centered shared infrastructure for scan {id.slice(0, 8)} — {job.created_at ? new Date(job.created_at).toLocaleDateString() : ""}
          </p>
        </div>
        <GraphLegend items={legendItems} />
      </div>
      <MeshStats stats={stats} />
      <div className="flex-1 relative">
        <ReactFlow
          nodes={displayNodes} edges={displayEdges} nodeTypes={lineageNodeTypes}
          fitView minZoom={0.05} maxZoom={2.5}
          defaultEdgeOptions={{ type: "smoothstep" }}
          proOptions={{ hideAttribution: true }}
          onNodeClick={onNodeClick} onNodeMouseEnter={onNodeMouseEnter} onNodeMouseLeave={onNodeMouseLeave}
          onPaneClick={() => { setSelectedNode(null); setHoveredNodeId(null); }}
        >
          <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
          <Controls className={CONTROLS_CLASS} />
          <MiniMap nodeColor={minimapNodeColor} className={MINIMAP_CLASS} />
        </ReactFlow>
        {selectedNode && <LineageDetailPanel data={selectedNode} onClose={() => setSelectedNode(null)} />}
      </div>
    </div>
  );
}
