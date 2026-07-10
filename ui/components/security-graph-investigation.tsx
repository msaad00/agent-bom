"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Focus, GitBranch, Loader2 } from "lucide-react";

import { LineageDetailPanel } from "@/components/lineage-detail";
import { FullscreenButton, GraphLegend } from "@/components/graph-chrome";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";
import {
  BACKGROUND_COLOR,
  BACKGROUND_GAP,
  CONTROLS_CLASS,
  MINIMAP_BG,
  MINIMAP_CLASS,
  MINIMAP_MASK,
  legendItemsForVisibleGraph,
  minimapNodeColor,
  readableGraphEdges,
} from "@/lib/graph-utils";
import { graphFitViewOptions, shouldShowGraphMiniMap } from "@/lib/graph-viewport";
import { buildFocusedGraphData } from "@/lib/security-graph-focus";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { useGraphLayout } from "@/lib/use-graph-layout";

const INVESTIGATION_LAYERS = {
  provider: false,
  agent: true,
  org: false,
  account: false,
  user: false,
  group: false,
  role: false,
  policy: false,
  serviceAccount: false,
  servicePrincipal: false,
  federatedIdentity: false,
  environment: true,
  fleet: false,
  cluster: true,
  server: true,
  sharedServer: true,
  package: true,
  vulnerability: true,
  credential: true,
  tool: true,
  model: false,
  framework: true,
  dataset: false,
  container: true,
  cloudResource: true,
  misconfiguration: true,
  managedIdentity: false,
  accessGrant: false,
  accessPolicy: false,
  driftIncident: false,
  dataStore: false,
  directory: false,
  sourceFile: false,
  configFile: false,
} as const;

export function SecurityGraphInvestigation({
  graph,
  attackPath,
  focusMode,
  onFocusModeChange,
  fullGraphHref,
  loading = false,
}: {
  graph: UnifiedGraphData | null;
  attackPath: AttackPath | null;
  focusMode: boolean;
  onFocusModeChange: (next: boolean) => void;
  fullGraphHref: string;
  loading?: boolean;
}) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const activeGraph = useMemo(() => {
    if (!graph) return null;
    if (focusMode && attackPath) {
      return buildFocusedGraphData(graph, attackPath) ?? graph;
    }
    return graph;
  }, [attackPath, focusMode, graph]);

  const flow = useMemo(() => {
    if (!activeGraph) {
      return { nodes: [] as Node<LineageNodeData>[], edges: [] as Edge[], legend: [] };
    }
    return buildUnifiedFlowGraph(activeGraph, {
      layers: { ...INVESTIGATION_LAYERS },
      severity: null,
      agentName: null,
      vulnOnly: false,
      maxDepth: 12,
    });
  }, [activeGraph]);

  const layout = useGraphLayout("dagre-lr", flow.nodes, flow.edges);
  const displayEdges = useMemo(() => readableGraphEdges(layout.edges), [layout.edges]);
  const legendItems = useMemo(
    () => legendItemsForVisibleGraph(layout.nodes, displayEdges),
    [displayEdges, layout.nodes],
  );
  const viewportInput = useMemo(
    () => ({
      nodeCount: layout.nodes.length,
      edgeCount: displayEdges.length,
      selectedNode: Boolean(selectedNodeId),
      mode: "lineage" as const,
    }),
    [displayEdges.length, layout.nodes.length, selectedNodeId],
  );

  const selectedNode = useMemo(
    () => layout.nodes.find((node) => node.id === selectedNodeId) ?? null,
    [layout.nodes, selectedNodeId],
  );

  useEffect(() => {
    if (!selectedNodeId) return;
    if (!layout.nodes.some((node) => node.id === selectedNodeId)) {
      setSelectedNodeId(null);
    }
  }, [layout.nodes, selectedNodeId]);

  return (
    <section className="overflow-hidden rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[color:var(--border-subtle)] px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Live investigation</h2>
          <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]">
            {focusMode
              ? "Focus mode highlights the selected exposure path in an interactive graph."
              : "Full snapshot mode shows the persisted subgraph for this scan."}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onFocusModeChange(!focusMode)}
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
              focusMode
                ? "border-emerald-600/50 bg-emerald-500/10 text-emerald-200"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]"
            }`}
          >
            <Focus className="h-3.5 w-3.5" />
            {focusMode ? "Focus on path" : "Full snapshot"}
          </button>
          <Link
            href={fullGraphHref}
            className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
          >
            Open lineage
            <GitBranch className="h-3.5 w-3.5" />
          </Link>
          <FullscreenButton />
        </div>
      </div>

      <div
        id="security-graph-investigation-canvas"
        className="relative min-h-[28rem] bg-[color:var(--surface-muted)]"
        data-testid="security-graph-investigation"
      >
        {loading ? (
          <div className="flex h-[28rem] items-center justify-center gap-2 text-sm text-[color:var(--text-secondary)]">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading graph evidence…
          </div>
        ) : layout.nodes.length === 0 ? (
          <div className="flex h-[28rem] items-center justify-center px-6 text-center text-sm text-[color:var(--text-secondary)]">
            No graph nodes matched this path. Run a fresh scan or clear focus to inspect the full snapshot.
          </div>
        ) : (
          <ReactFlow
            nodes={layout.nodes}
            edges={displayEdges}
            nodeTypes={lineageNodeTypes}
            fitView
            fitViewOptions={graphFitViewOptions(viewportInput)}
            minZoom={0.2}
            maxZoom={1.8}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable
            onNodeClick={(_, node) => setSelectedNodeId(node.id)}
            proOptions={{ hideAttribution: true }}
          >
            <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
            <Controls className={CONTROLS_CLASS} showInteractive={false} />
            {shouldShowGraphMiniMap(viewportInput) && (
              <MiniMap
                className={MINIMAP_CLASS}
                style={{ background: MINIMAP_BG }}
                maskColor={MINIMAP_MASK}
                nodeColor={minimapNodeColor}
              />
            )}
          </ReactFlow>
        )}

        <div className="pointer-events-none absolute left-3 top-3 max-w-[min(24rem,calc(100vw-2rem))]">
          <GraphLegend items={legendItems} />
        </div>
      </div>

      {selectedNode && (
        <div className="border-t border-[color:var(--border-subtle)] p-4">
          <LineageDetailPanel
            data={selectedNode.data as LineageNodeData}
            onClose={() => setSelectedNodeId(null)}
          />
        </div>
      )}
    </section>
  );
}
