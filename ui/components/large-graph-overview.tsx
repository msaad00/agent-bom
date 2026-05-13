"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Edge, Node } from "@xyflow/react";
import { Activity, GitBranch, Layers3, Network, ShieldAlert } from "lucide-react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import { GraphLegend } from "@/components/graph-chrome";
import type { LegendItem } from "@/lib/graph-utils";
import {
  buildLargeGraphOverviewModel,
  LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
  LARGE_GRAPH_OVERVIEW_MAX_RENDERED_EDGES,
  LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES,
  LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
  summarizeLargeGraphOverview,
  type LargeGraphNode,
} from "@/lib/large-graph-overview";

interface LargeGraphOverviewProps {
  nodes: Node<LineageNodeData>[];
  edges: Edge[];
  legendItems: LegendItem[];
  onNodeSelect?: (nodeId: string) => void;
}

interface Viewport {
  scale: number;
  offsetX: number;
  offsetY: number;
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
  tone?: "zinc" | "red" | "amber" | "cyan";
}) {
  const toneClass = {
    zinc: "border-zinc-800 bg-zinc-950/70 text-zinc-300",
    red: "border-red-500/30 bg-red-950/25 text-red-100",
    amber: "border-amber-500/30 bg-amber-950/25 text-amber-100",
    cyan: "border-cyan-500/30 bg-cyan-950/25 text-cyan-100",
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

function graphBounds(nodes: LargeGraphNode[]) {
  if (nodes.length === 0) return { minX: -1, maxX: 1, minY: -1, maxY: 1 };
  return nodes.reduce(
    (bounds, node) => ({
      minX: Math.min(bounds.minX, node.x),
      maxX: Math.max(bounds.maxX, node.x),
      minY: Math.min(bounds.minY, node.y),
      maxY: Math.max(bounds.maxY, node.y),
    }),
    { minX: Infinity, maxX: -Infinity, minY: Infinity, maxY: -Infinity },
  );
}

function fitViewport(nodes: LargeGraphNode[], width: number, height: number): Viewport {
  const bounds = graphBounds(nodes);
  const graphWidth = Math.max(1, bounds.maxX - bounds.minX);
  const graphHeight = Math.max(1, bounds.maxY - bounds.minY);
  const scale = Math.max(0.08, Math.min(1.2, Math.min(width / graphWidth, height / graphHeight) * 0.82));
  return {
    scale,
    offsetX: width / 2 - ((bounds.minX + bounds.maxX) / 2) * scale,
    offsetY: height / 2 - ((bounds.minY + bounds.maxY) / 2) * scale,
  };
}

function screenToGraph(x: number, y: number, viewport: Viewport): { x: number; y: number } {
  return {
    x: (x - viewport.offsetX) / viewport.scale,
    y: (y - viewport.offsetY) / viewport.scale,
  };
}

function drawGraph(
  canvas: HTMLCanvasElement,
  model: ReturnType<typeof buildLargeGraphOverviewModel>,
  viewport: Viewport,
  selectedNodeId: string | null,
) {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.floor(width * ratio));
  canvas.height = Math.max(1, Math.floor(height * ratio));
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);

  ctx.fillStyle = "#050505";
  ctx.fillRect(0, 0, width, height);
  ctx.save();
  ctx.translate(viewport.offsetX, viewport.offsetY);
  ctx.scale(viewport.scale, viewport.scale);

  for (const edge of model.edges) {
    if (edge.hidden) continue;
    const source = model.nodeById.get(edge.source);
    const target = model.nodeById.get(edge.target);
    if (!source || !target || source.hidden || target.hidden) continue;
    const selected = selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId);
    ctx.globalAlpha = selectedNodeId ? (selected ? 0.78 : 0.08) : 0.25;
    ctx.strokeStyle = edge.color;
    ctx.lineWidth = selected ? edge.size * 2.1 : edge.size;
    ctx.beginPath();
    ctx.moveTo(source.x, source.y);
    ctx.lineTo(target.x, target.y);
    ctx.stroke();
  }

  const orderedNodes = [...model.nodes].sort((left, right) => {
    const leftScore = left.forceLabel || left.highlighted ? 1 : 0;
    const rightScore = right.forceLabel || right.highlighted ? 1 : 0;
    return leftScore - rightScore;
  });
  for (const node of orderedNodes) {
    if (node.hidden) continue;
    const selected = selectedNodeId === node.id;
    const dimmed = selectedNodeId !== null && !selected;
    ctx.globalAlpha = dimmed ? 0.34 : 1;
    ctx.fillStyle = selected ? "#f8fafc" : node.color;
    ctx.beginPath();
    ctx.arc(node.x, node.y, selected ? node.size * 1.9 : node.size, 0, Math.PI * 2);
    ctx.fill();
    if (selected || node.forceLabel) {
      ctx.globalAlpha = selected ? 1 : 0.78;
      ctx.font = `${Math.max(10, 12 / viewport.scale)}px Inter, ui-sans-serif, system-ui, sans-serif`;
      ctx.fillStyle = "#e4e4e7";
      ctx.fillText(node.label, node.x + node.size + 4 / viewport.scale, node.y - node.size);
    }
  }

  ctx.restore();
  ctx.globalAlpha = 1;
}

export function LargeGraphOverview({
  nodes,
  edges,
  legendItems,
  onNodeSelect,
}: LargeGraphOverviewProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const dragRef = useRef<{ x: number; y: number; offsetX: number; offsetY: number } | null>(null);
  const model = useMemo(() => buildLargeGraphOverviewModel(nodes, edges), [nodes, edges]);
  const summary = useMemo(() => summarizeLargeGraphOverview(nodes, edges), [nodes, edges]);
  const isBudgeted = model.omittedNodeCount > 0 || model.omittedEdgeCount > 0;
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [viewport, setViewport] = useState<Viewport>({ scale: 1, offsetX: 0, offsetY: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const resize = () => setViewport(fitViewport(model.nodes, canvas.clientWidth, canvas.clientHeight));
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    return () => observer.disconnect();
  }, [model]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    drawGraph(canvas, model, viewport, selectedNodeId);
  }, [model, selectedNodeId, viewport]);

  return (
    <div className="flex h-full min-h-[72vh] flex-col overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl shadow-black/30" data-testid="large-graph-overview">
      <div className="border-b border-zinc-800 bg-zinc-950/95 p-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="inline-flex shrink-0 items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-950/25 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-emerald-200">
            <Network className="h-3.5 w-3.5" />
            Large graph overview
          </span>
          <span className="min-w-0 text-xs text-zinc-500">
            2D canvas overview for broad estate scans; focused investigations still use React Flow.
          </span>
        </div>
        <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-zinc-500">
          <span>
            Switches on at {LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD.toLocaleString()} nodes or{" "}
            {LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD.toLocaleString()} edges.
          </span>
          <span>
            Draw budget: {model.nodes.length.toLocaleString()}/{model.sourceNodeCount.toLocaleString()} nodes,{" "}
            {model.edges.length.toLocaleString()}/{model.sourceEdgeCount.toLocaleString()} edges.
          </span>
          {isBudgeted && (
            <span className="text-amber-300">
              Lower-signal items are omitted from this overview; use search, filters, or drill-in for exact detail.
            </span>
          )}
        </div>
        <div className="mt-2">
          <RelationshipRail items={summary.topRelationships} />
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 lg:grid-cols-5">
          <StatPill icon={Layers3} label="Nodes" value={summary.nodes.toLocaleString()} tone="cyan" />
          <StatPill icon={GitBranch} label="Edges" value={summary.edges.toLocaleString()} />
          <StatPill icon={ShieldAlert} label="Findings" value={summary.findings.toLocaleString()} tone="amber" />
          <StatPill icon={ShieldAlert} label="Critical" value={summary.criticalFindings.toLocaleString()} tone="red" />
          <StatPill icon={Activity} label="Creds/tools" value={`${summary.credentials}/${summary.tools}`} />
        </div>
      </div>

      <div className="relative min-h-0 flex-1 bg-[radial-gradient(circle_at_25%_15%,rgba(16,185,129,0.10),transparent_28%),radial-gradient(circle_at_75%_65%,rgba(59,130,246,0.10),transparent_30%),#050505]">
        <canvas
          ref={canvasRef}
          className="h-full min-h-[58vh] w-full cursor-grab active:cursor-grabbing"
          aria-label="Large security graph overview"
          data-testid="large-graph-overview-canvas"
          onMouseDown={(event) => {
            dragRef.current = {
              x: event.clientX,
              y: event.clientY,
              offsetX: viewport.offsetX,
              offsetY: viewport.offsetY,
            };
          }}
          onMouseMove={(event) => {
            const drag = dragRef.current;
            if (!drag) return;
            setViewport((current) => ({
              ...current,
              offsetX: drag.offsetX + event.clientX - drag.x,
              offsetY: drag.offsetY + event.clientY - drag.y,
            }));
          }}
          onMouseLeave={() => {
            dragRef.current = null;
          }}
          onMouseUp={(event) => {
            const drag = dragRef.current;
            dragRef.current = null;
            if (drag && Math.hypot(event.clientX - drag.x, event.clientY - drag.y) > 4) return;
            const rect = event.currentTarget.getBoundingClientRect();
            const point = screenToGraph(event.clientX - rect.left, event.clientY - rect.top, viewport);
            let nearest: LargeGraphNode | null = null;
            let nearestDistance = Infinity;
            for (const node of model.nodes) {
              if (node.hidden) continue;
              const distance = Math.hypot(node.x - point.x, node.y - point.y);
              if (distance < nearestDistance) {
                nearest = node;
                nearestDistance = distance;
              }
            }
            if (!nearest || nearestDistance * viewport.scale > 18) {
              setSelectedNodeId(null);
              return;
            }
            setSelectedNodeId(nearest.id);
            onNodeSelect?.(nearest.id);
          }}
          onWheel={(event) => {
            event.preventDefault();
            const rect = event.currentTarget.getBoundingClientRect();
            const before = screenToGraph(event.clientX - rect.left, event.clientY - rect.top, viewport);
            const nextScale = Math.max(0.04, Math.min(3.2, viewport.scale * (event.deltaY > 0 ? 0.9 : 1.1)));
            setViewport({
              scale: nextScale,
              offsetX: event.clientX - rect.left - before.x * nextScale,
              offsetY: event.clientY - rect.top - before.y * nextScale,
            });
          }}
        />
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
          Large mode supports pan, zoom, node selection, server-side search, filters, selected-node detail, and reachability drill-in.
          React Flow-only affordances such as node cards, minimap, and path highlighting return after narrowing the graph below{" "}
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
