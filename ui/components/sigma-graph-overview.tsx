"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type Sigma from "sigma";
import type { Edge, Node } from "@xyflow/react";
import { Activity, GitBranch, Layers3, Network, ShieldAlert, Sparkles } from "lucide-react";

import { GraphLegend } from "@/components/graph-chrome";
import type { LineageNodeData } from "@/components/lineage-nodes";
import type { LegendItem } from "@/lib/graph-utils";
import {
  LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
  LARGE_GRAPH_OVERVIEW_MAX_RENDERED_EDGES,
  LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES,
  LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
} from "@/lib/large-graph-overview";
import {
  buildSigmaGraphOverviewModel,
  type SigmaEdgeAttributes,
  type SigmaNodeAttributes,
} from "@/lib/sigma-graph-overview";

interface SigmaGraphOverviewProps {
  nodes: Node<LineageNodeData>[];
  edges: Edge[];
  legendItems: LegendItem[];
  onNodeSelect?: (nodeId: string) => void;
}

function StatPill({
  icon: Icon,
  label,
  value,
  tone = "zinc",
}: {
  icon: typeof Network;
  label: string;
  value: string;
  tone?: "zinc" | "red" | "amber" | "emerald";
}) {
  const toneClass = {
    zinc: "border-zinc-800 bg-zinc-950/70 text-zinc-300",
    red: "border-red-500/30 bg-red-950/25 text-red-100",
    amber: "border-amber-500/30 bg-amber-950/25 text-amber-100",
    emerald: "border-emerald-500/30 bg-emerald-950/25 text-emerald-100",
  }[tone];

  return (
    <div className={`flex min-w-0 items-center gap-2 rounded-lg border px-2.5 py-2 ${toneClass}`}>
      <Icon className="h-4 w-4 shrink-0" />
      <span className="min-w-0 truncate text-[11px] uppercase tracking-[0.14em] text-zinc-500">{label}</span>
      <span className="ml-auto shrink-0 font-mono text-sm font-semibold">{value}</span>
    </div>
  );
}

function RelationshipRail({ items }: { items: Array<{ relationship: string; count: number }> }) {
  if (items.length === 0) return null;
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      {items.map((item) => (
        <span
          key={item.relationship}
          className="inline-flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-950/75 px-2.5 py-1 text-[11px] text-zinc-300"
        >
          <span className="max-w-36 truncate" title={item.relationship}>
            {item.relationship.replace(/_/g, " ")}
          </span>
          <span className="font-mono text-zinc-500">{item.count}</span>
        </span>
      ))}
    </div>
  );
}

export function SigmaGraphOverview({
  nodes,
  edges,
  legendItems,
  onNodeSelect,
}: SigmaGraphOverviewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rendererRef = useRef<Sigma<SigmaNodeAttributes, SigmaEdgeAttributes> | null>(null);
  const selectedNodeIdRef = useRef<string | null>(null);
  const onNodeSelectRef = useRef<SigmaGraphOverviewProps["onNodeSelect"]>(onNodeSelect);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [renderError, setRenderError] = useState<string | null>(null);
  const model = useMemo(() => buildSigmaGraphOverviewModel(nodes, edges), [nodes, edges]);
  const isBudgeted = model.overview.omittedNodeCount > 0 || model.overview.omittedEdgeCount > 0;

  useEffect(() => {
    selectedNodeIdRef.current = selectedNodeId;
    rendererRef.current?.refresh();
  }, [selectedNodeId]);

  useEffect(() => {
    onNodeSelectRef.current = onNodeSelect;
  }, [onNodeSelect]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    let renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes> | null = null;
    let alive = true;

    const start = async () => {
      try {
        const { default: SigmaRenderer } = await import("sigma");
        if (!alive || !containerRef.current) return;
        renderer = new SigmaRenderer(model.graph, container, {
          allowInvalidContainer: true,
          autoCenter: true,
          autoRescale: true,
          defaultEdgeColor: "#52525b",
          defaultNodeColor: "#71717a",
          enableEdgeEvents: false,
          hideEdgesOnMove: true,
          hideLabelsOnMove: true,
          itemSizesReference: "positions",
          labelColor: { color: "#e4e4e7" },
          labelDensity: 0.08,
          labelFont: "Inter, ui-sans-serif, system-ui, sans-serif",
          labelGridCellSize: 180,
          labelRenderedSizeThreshold: 8.5,
          labelSize: 11,
          minCameraRatio: 0.04,
          maxCameraRatio: 4,
          minEdgeThickness: 0.35,
          renderEdgeLabels: false,
          renderLabels: true,
          stagePadding: 36,
          zIndex: true,
          nodeReducer: (node, data) => {
            const selected = selectedNodeIdRef.current === node;
            const dimmedBySelection = selectedNodeIdRef.current !== null && !selected;
            return {
              ...data,
              color: selected ? "#f8fafc" : data.color,
              forceLabel: selected || data.forceLabel,
              hidden: data.hidden,
              highlighted: selected || data.highlighted,
              size: selected ? data.size * 1.65 : data.size,
              zIndex: selected ? 4 : data.zIndex,
              ...(dimmedBySelection ? { color: "#3f3f46" } : {}),
            };
          },
          edgeReducer: (_edge, data) => {
            const selected = selectedNodeIdRef.current;
            const selectedEdge = selected
              ? model.graph.source(_edge) === selected || model.graph.target(_edge) === selected
              : false;
            return {
              ...data,
              color: selectedEdge ? data.color : selected ? "#27272a" : data.color,
              hidden: data.hidden,
              size: selectedEdge ? data.size * 2.3 : data.size,
              zIndex: selectedEdge ? 3 : data.zIndex,
            };
          },
        });
        rendererRef.current = renderer;
        renderer.on("clickNode", ({ node }) => {
          setSelectedNodeId(node);
          onNodeSelectRef.current?.(node);
        });
        renderer.on("clickStage", () => {
          setSelectedNodeId(null);
        });
        renderer.getCamera().setState({ ratio: 1.05 });
        renderer.refresh();
        setRenderError(null);
      } catch (error) {
        if (!alive) return;
        setRenderError(error instanceof Error ? error.message : "WebGL graph renderer failed to initialize.");
      }
    };

    void start();

    return () => {
      alive = false;
      renderer?.kill();
      rendererRef.current = null;
      container.replaceChildren();
    };
  }, [model]);

  return (
    <div
      className="flex h-full min-h-[72vh] flex-col overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl shadow-black/30"
      data-testid="sigma-graph-overview"
    >
      <div className="border-b border-zinc-800 bg-zinc-950/95 p-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="inline-flex shrink-0 items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-950/25 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-emerald-200">
            <Sparkles className="h-3.5 w-3.5" />
            WebGL graph overview
          </span>
          <span className="min-w-0 text-xs text-zinc-500">
            Sigma.js renderer for broad estate scans; focused investigations still use React Flow.
          </span>
        </div>
        <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-zinc-500">
          <span>
            Switches on with renderer=webgl at {LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD.toLocaleString()} nodes or{" "}
            {LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD.toLocaleString()} edges.
          </span>
          <span>
            Draw budget: {model.overview.nodes.length.toLocaleString()}/{model.overview.sourceNodeCount.toLocaleString()} nodes,{" "}
            {model.overview.edges.length.toLocaleString()}/{model.overview.sourceEdgeCount.toLocaleString()} edges.
          </span>
          {isBudgeted && (
            <span className="text-amber-300">
              Lower-signal items are omitted from this overview; use search, filters, or drill-in for exact detail.
            </span>
          )}
        </div>
        <div className="mt-2">
          <RelationshipRail items={model.summary.topRelationships} />
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 lg:grid-cols-5">
          <StatPill icon={Layers3} label="Nodes" value={model.summary.nodes.toLocaleString()} tone="emerald" />
          <StatPill icon={GitBranch} label="Edges" value={model.summary.edges.toLocaleString()} />
          <StatPill icon={ShieldAlert} label="Findings" value={model.summary.findings.toLocaleString()} tone="amber" />
          <StatPill icon={ShieldAlert} label="Critical" value={model.summary.criticalFindings.toLocaleString()} tone="red" />
          <StatPill icon={Activity} label="Creds/tools" value={`${model.summary.credentials}/${model.summary.tools}`} />
        </div>
      </div>

      <div className="relative min-h-0 flex-1 bg-[#050505]">
        <div
          ref={containerRef}
          className="h-full min-h-[58vh] w-full"
          aria-label="WebGL security graph overview"
          data-testid="sigma-graph-overview-canvas"
        />
        {renderError && (
          <div className="absolute inset-4 flex items-center justify-center rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-sm text-red-100">
            WebGL renderer unavailable: {renderError}
          </div>
        )}
        <div className="pointer-events-auto absolute right-3 top-3 max-w-[min(30rem,calc(100vw-2rem))]">
          <details className="rounded-xl border border-zinc-800 bg-zinc-950/85 p-2 backdrop-blur">
            <summary className="cursor-pointer list-none text-[10px] uppercase tracking-[0.18em] text-zinc-400 [&::-webkit-details-marker]:hidden">
              Legend
            </summary>
            <div className="mt-2">
              <GraphLegend items={legendItems} embedded />
            </div>
          </details>
        </div>
        <div className="pointer-events-none absolute bottom-3 left-3 max-w-[min(34rem,calc(100vw-2rem))] rounded-xl border border-zinc-800 bg-zinc-950/80 px-3 py-2 text-[11px] text-zinc-400 backdrop-blur">
          WebGL mode supports pan, zoom, node selection, server-side search, filters, and selected-node detail.
          React Flow-only affordances return after narrowing the graph below{" "}
          {LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD.toLocaleString()} nodes / {LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD.toLocaleString()} edges
          or entering a bounded drill-in.
          <span className="sr-only">
            Maximum overview draw budget is {LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES.toLocaleString()} nodes and{" "}
            {LARGE_GRAPH_OVERVIEW_MAX_RENDERED_EDGES.toLocaleString()} edges.
          </span>
        </div>
      </div>
    </div>
  );
}
