"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type Sigma from "sigma";
import type { Edge, Node } from "@xyflow/react";
import { Sparkles } from "lucide-react";

import { GraphLegend } from "@/components/graph-chrome";
import { GraphTextAlternative } from "@/components/graph-text-alternative";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { useGraphCanvasPalette } from "@/lib/graph-canvas-theme";
import type { LegendItem } from "@/lib/graph-utils";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import {
  registerGraphPresentationKey,
  type GraphPresentationScope,
} from "@/lib/graph-presentation";
import {
  readSigmaCameraPresentation,
  sanitizeSigmaCameraState,
  sigmaCameraStorageKey,
  writeSigmaCameraPresentation,
  type SigmaCameraState,
} from "@/lib/sigma-camera-presentation";
import type { UnifiedGraphFlowFilters } from "@/lib/unified-graph-flow";
import { useCaptureMode } from "@/lib/use-capture-mode";
import {
  LARGE_GRAPH_OVERVIEW_MAX_RENDERED_EDGES,
  LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES,
} from "@/lib/large-graph-overview";
import {
  buildSigmaGraphOverviewModel,
  buildSigmaGraphOverviewModelFromUnifiedGraph,
  type SigmaEdgeAttributes,
  type SigmaNodeAttributes,
} from "@/lib/sigma-graph-overview";

type SigmaGraphOverviewProps = {
  legendItems: LegendItem[];
  embedded?: boolean;
  onNodeSelect?: (nodeId: string) => void;
  selectedId?: string | null;
  onClearSelection?: () => void;
  presentationScope?: GraphPresentationScope;
  presentationEnabled?: boolean;
} & (
  {
    nodes: Node<LineageNodeData>[];
    edges: Edge[];
    graph?: never;
    filters?: never;
  }
  | {
      graph: UnifiedGraphData;
      filters?: UnifiedGraphFlowFilters;
      nodes?: never;
      edges?: never;
    }
);

function RelationshipRail({ items }: { items: Array<{ relationship: string; count: number }> }) {
  if (items.length === 0) return null;
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      {items.map((item) => (
        <span
          key={item.relationship}
          className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border-subtle)] bg-[var(--background)]/75 px-2.5 py-1 text-[11px] text-[var(--text-secondary)]"
        >
          <span className="max-w-36 truncate" title={item.relationship}>
            {item.relationship.replace(/_/g, " ")}
          </span>
          <span className="font-mono text-[var(--text-tertiary)]">{item.count}</span>
        </span>
      ))}
    </div>
  );
}

function browserStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function SigmaGraphOverview({
  graph,
  filters,
  nodes,
  edges,
  legendItems,
  embedded = false,
  onNodeSelect,
  selectedId,
  onClearSelection,
  presentationScope,
  presentationEnabled = true,
}: SigmaGraphOverviewProps) {
  const captureMode = useCaptureMode();
  const [assetQuery, setAssetQuery] = useState("");
  const [grouping, setGrouping] = useState<"type" | "environment">("type");
  const controlsRef = useRef<HTMLDetailsElement | null>(null);
  const groupLabelsRef = useRef<HTMLDivElement | null>(null);
  const palette = useGraphCanvasPalette();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rendererRef = useRef<Sigma<SigmaNodeAttributes, SigmaEdgeAttributes> | null>(null);
  const selectedNodeIdRef = useRef<string | null>(null);
  const onNodeSelectRef = useRef<SigmaGraphOverviewProps["onNodeSelect"]>(onNodeSelect);
  const [localSelectedId, setSelectedNodeId] = useState<string | null>(null);
  const selectedNodeId = selectedId === undefined ? localSelectedId : selectedId;
  const onClearRef = useRef(onClearSelection);
  const neighborsRef = useRef(new Set<string>());
  const [renderError, setRenderError] = useState<string | null>(null);
  const hasPresentationScope = presentationScope !== undefined;
  const presentationTenantId = presentationScope?.tenantId ?? "";
  const presentationSubject = presentationScope?.subject ?? "";
  const presentationSnapshotId = presentationScope?.snapshotId ?? "";
  const presentationLens = presentationScope?.lens ?? "";
  const presentationFilterScope = presentationScope?.scope ?? "";
  const cameraStorageKey = useMemo(
    () => hasPresentationScope
      ? sigmaCameraStorageKey({
          tenantId: presentationTenantId,
          subject: presentationSubject,
          snapshotId: presentationSnapshotId,
          lens: presentationLens,
          scope: grouping === "type" ? presentationFilterScope : `${presentationFilterScope}:grouping=environment`,
        })
      : null,
    [
      hasPresentationScope,
      presentationFilterScope,
      presentationLens,
      presentationSnapshotId,
      presentationSubject,
      presentationTenantId,
      grouping,
    ],
  );
  const cameraOwner = useMemo(
    () => hasPresentationScope
      ? { tenantId: presentationTenantId, subject: presentationSubject }
      : null,
    [hasPresentationScope, presentationSubject, presentationTenantId],
  );
  const cameraPersistenceEnabled = Boolean(
    presentationEnabled && cameraOwner && cameraStorageKey && !captureMode,
  );
  const model = useMemo(
    () =>
      graph
        ? buildSigmaGraphOverviewModelFromUnifiedGraph(graph, filters, grouping)
        : buildSigmaGraphOverviewModel(nodes, edges, grouping),
    [edges, filters, graph, nodes, grouping],
  );
  const isBudgeted = model.overview.omittedNodeCount > 0 || model.overview.omittedEdgeCount > 0;

  useEffect(() => {
    const valid = selectedNodeId !== null && model.graph.hasNode(selectedNodeId);
    selectedNodeIdRef.current = valid ? selectedNodeId : null;
    neighborsRef.current = new Set(valid ? model.graph.neighbors(selectedNodeId) : []);
    rendererRef.current?.refresh();
  }, [selectedNodeId, model]);

  useEffect(() => {
    onNodeSelectRef.current = onNodeSelect;
    onClearRef.current = onClearSelection;
  }, [onNodeSelect, onClearSelection]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    let renderer: Sigma<SigmaNodeAttributes, SigmaEdgeAttributes> | null = null;
    let alive = true;
    let pendingCamera: SigmaCameraState | null = null;
    let persistTimer: number | null = null;

    const storage = cameraPersistenceEnabled ? browserStorage() : null;
    const flushCamera = () => {
      if (!cameraStorageKey || !cameraOwner || !pendingCamera) return;
      registerGraphPresentationKey(storage, cameraOwner, cameraStorageKey);
      writeSigmaCameraPresentation(storage, cameraStorageKey, pendingCamera);
      pendingCamera = null;
      persistTimer = null;
    };

    const start = async () => {
      try {
        const { default: SigmaRenderer } = await import("sigma");
        if (!alive || !containerRef.current) return;
        renderer = new SigmaRenderer(model.graph, container, {
          allowInvalidContainer: true,
          autoCenter: true,
          autoRescale: true,
          defaultEdgeColor: palette.defaultEdge,
          defaultNodeColor: palette.defaultNode,
          enableEdgeEvents: false,
          hideEdgesOnMove: true,
          hideLabelsOnMove: true,
          itemSizesReference: grouping === "environment" ? "screen" : "positions",
          labelColor: { color: palette.label },
          // Label level-of-detail. The grid keeps at most a handful of labels
          // per cell so they never overlap into a smear; the size threshold
          // surfaces the largest / highest-signal nodes first and lets the rest
          // appear as the user zooms in (rendered size grows) or hovers a node.
          labelDensity: 0.08,
          labelFont: "Inter, ui-sans-serif, system-ui, sans-serif",
          labelGridCellSize: 170,
          labelRenderedSizeThreshold: 6,
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
            const neighbor = neighborsRef.current.has(node);
            const dimmedBySelection = selectedNodeIdRef.current !== null && !selected && !neighbor;
            return {
              ...data,
              color: selected ? palette.selected : data.color,
              forceLabel: selected || data.forceLabel,
              // Parent focus marks unrelated nodes hidden; retain them as faded context here.
              hidden: selectedNodeIdRef.current ? false : data.hidden,
              highlighted: selected || data.highlighted,
              size: selected ? data.size * 1.65 : data.size,
              zIndex: selected ? 4 : data.zIndex,
              ...(dimmedBySelection ? { color: palette.dimmed } : {}),
            };
          },
          edgeReducer: (_edge, data) => {
            const selected = selectedNodeIdRef.current;
            const selectedEdge = selected
              ? model.graph.source(_edge) === selected || model.graph.target(_edge) === selected
              : false;
            return {
              ...data,
              color: selectedEdge ? data.color : selected ? palette.dimmed : data.color,
              hidden: selectedEdge ? false : data.hidden,
              size: selectedEdge ? data.size * 2.3 : data.size,
              zIndex: selectedEdge ? 3 : data.zIndex,
            };
          },
        });
        rendererRef.current = renderer;
        const positionGroupLabels = () => {
          if (!renderer || !groupLabelsRef.current) return;
          const activeRenderer = renderer;
          const dimensions = activeRenderer.getDimensions();
          model.groups.forEach((group, index) => {
            const label = groupLabelsRef.current?.children[index] as HTMLElement | undefined;
            if (!label) return;
            const position = activeRenderer.graphToViewport({ x: group.x, y: group.y });
            const beside = activeRenderer.graphToViewport({ x: group.x + 120, y: group.y });
            const readable = dimensions.width >= 640 && (model.groups.length <= 4 || Math.abs(beside.x - position.x) >= 65);
            label.style.display = readable && position.x >= 0 && position.y >= 0 && position.x <= dimensions.width && position.y <= dimensions.height ? "block" : "none";
            label.style.transform = `translate(${Math.max(112, Math.min(dimensions.width - 112, position.x))}px, ${Math.max(52, position.y - label.offsetHeight)}px) translateX(-50%)`;
          });
        };
        renderer.on("afterRender", positionGroupLabels);
        renderer.on("clickNode", ({ node }) => {
          setSelectedNodeId(node);
          onNodeSelectRef.current?.(node);
        });
        renderer.on("clickStage", () => {
          setSelectedNodeId(null);
          onClearRef.current?.();
        });
        const camera = renderer.getCamera();
        const savedCamera = cameraPersistenceEnabled && cameraStorageKey
          ? readSigmaCameraPresentation(storage, cameraStorageKey)
          : null;
        // Sigma's constructor performs its normal fit/centering. A valid saved
        // camera takes precedence over that one-shot default; absent or invalid
        // state gets the established overview framing.
        camera.setState(savedCamera ?? { ratio: 1.05 });
        if (cameraPersistenceEnabled) {
          camera.on("updated", (state) => {
            const sanitized = sanitizeSigmaCameraState(state);
            if (!sanitized) return;
            pendingCamera = sanitized;
            if (persistTimer === null) {
              // Camera updates fire continuously while panning. Throttle the
              // synchronous localStorage write while retaining the latest frame.
              persistTimer = window.setTimeout(flushCamera, 80);
            }
          });
        }
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
      if (persistTimer !== null) window.clearTimeout(persistTimer);
      flushCamera();
      renderer?.kill();
      rendererRef.current = null;
      container.replaceChildren();
    };
  }, [cameraOwner, cameraPersistenceEnabled, cameraStorageKey, model, palette, grouping]);

  const focused = selectedNodeId && model.graph.hasNode(selectedNodeId) ? selectedNodeId : null;
  const neighbors = focused ? model.graph.neighbors(focused).filter((id) => id !== focused) : [];

  return (
    <div
      className={`flex h-full flex-col overflow-hidden bg-[var(--background)] ${
        embedded
          ? "min-h-0"
          : "min-h-[72vh] rounded-xl border border-[var(--border-subtle)] shadow-2xl shadow-black/30"
      }`}
      data-testid="sigma-graph-overview"
    >
      <div className="border-b border-[var(--border-subtle)] bg-[var(--background)]/95 p-3">
        <div className="flex min-w-0 flex-col gap-1 sm:flex-row sm:flex-wrap sm:items-center sm:gap-2">
          <span className="inline-flex w-fit shrink-0 items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 dark:bg-emerald-950/25 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-emerald-700 dark:text-emerald-200">
            <Sparkles className="h-3.5 w-3.5" />
            Estate map
          </span>
          <span className="min-w-0 text-xs leading-snug text-[var(--text-tertiary)] sm:min-w-[12rem] sm:flex-1">
            Select an asset to investigate its related evidence. Use Summary to drill into groups.
          </span>
        </div>
        <details ref={controlsRef} className="mt-2 text-xs text-ink-secondary">
          <summary className="cursor-pointer">Map controls</summary>
          <label className="mt-2 flex flex-col gap-1">Find a displayed asset
            <input value={assetQuery} onChange={(event) => setAssetQuery(event.target.value)} className="rounded border border-outline bg-background px-2 py-1 text-foreground" placeholder="Name or exact ID" />
          </label>
          {assetQuery.trim() && <ul className="mt-2 max-h-36 overflow-y-auto">
            {model.overview.nodes.filter((node) => `${node.id} ${node.label}`.toLowerCase().includes(assetQuery.trim().toLowerCase())).slice(0, 10).map((node) => <li key={node.id}><button type="button" className="break-all py-1 text-left text-sky-700 dark:text-sky-300" onClick={() => { setSelectedNodeId(node.id); if (controlsRef.current) controlsRef.current.open = false; onNodeSelectRef.current?.(node.id); }}>{node.label} · {node.id}</button></li>)}
            <li className="mt-1 text-ink-tertiary">Up to 10 matches from displayed assets. Use graph search for broader coverage.</li>
          </ul>}
        <label className="mt-2 flex items-center gap-2 text-xs text-ink-secondary">Group displayed assets by
          <select aria-label="Map grouping" value={grouping} onChange={(event) => setGrouping(event.target.value as "type" | "environment")} className="rounded border border-outline bg-background px-2 py-1 text-foreground">
            <option value="type">Asset type</option><option value="environment">Environment</option>
          </select>
        </label>
        </details>
        <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-[var(--text-tertiary)]">
          <span>
            Displayed: {model.overview.nodes.length.toLocaleString()}/{model.overview.sourceNodeCount.toLocaleString()} nodes,{" "}
            {model.overview.edges.length.toLocaleString()}/{model.overview.sourceEdgeCount.toLocaleString()} edges.
          </span>
          {isBudgeted && (
            <span className="text-amber-700 dark:text-amber-300">
              Lower-signal items are omitted from this overview; use search, filters, or drill-in for exact detail.
            </span>
          )}
        </div>
        <details className="mt-2 text-xs text-ink-secondary">
          <summary className="cursor-pointer">Graph summary</summary>
        <div className="mt-2">
          <RelationshipRail items={model.summary.topRelationships} />
        </div>
        <p className="mt-2 text-xs text-ink-secondary">{model.summary.findings.toLocaleString()} findings · {model.summary.criticalFindings.toLocaleString()} critical · {model.summary.credentials.toLocaleString()} credentials · {model.summary.tools.toLocaleString()} tools</p>
        </details>
      </div>

      {focused && <div className="border-b border-outline bg-surface px-3 py-2 text-xs" aria-label="Focused graph asset">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="min-w-0 break-words"><strong>{model.graph.getNodeAttribute(focused, "label")}</strong> · {neighbors.length} connected assets in this displayed graph</p>
          <button type="button" className="graph-chip-neutral" onClick={() => { setSelectedNodeId(null); onClearSelection?.(); }}>Clear focus</button>
        </div>
        <details className="mt-2">
          <summary className="cursor-pointer">Explore connected assets</summary>
          <p className="my-2 text-ink-secondary">Recorded connections, not proof of authorized access or execution. Open an asset’s details to inspect evidence or expand beyond this view.</p>
          <ul className="max-h-40 space-y-1 overflow-y-auto">
            {neighbors.slice(0, 12).map((id) => <li key={id}><button type="button" className="text-sky-700 underline dark:text-sky-300" title={id} onClick={() => { setSelectedNodeId(id); onNodeSelectRef.current?.(id); }}>{model.graph.getNodeAttribute(id, "label")} <span className="text-ink-secondary">({model.graph.getNodeAttribute(id, "nodeType")})</span></button></li>)}
          </ul>
          {neighbors.length > 12 && <p>Showing 12 of {neighbors.length} connected assets. Use the details panel to investigate further.</p>}
          {neighbors.length === 0 && <p>No connected assets are present in this displayed scope.</p>}
        </details>
      </div>}
      <div className="relative min-h-0 flex-1 bg-[var(--background)]">
        <div
          ref={containerRef}
          className="h-full min-h-[20rem] w-full"
          role="img"
          aria-label="WebGL security graph overview"
          aria-describedby="sigma-graph-overview-text"
          data-testid="sigma-graph-overview-canvas"
        />
        <div ref={groupLabelsRef} className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
          {model.groups.map((group) => <div key={group.key} className="absolute left-0 top-0 hidden max-w-52 rounded border border-outline bg-surface/95 px-2 py-1 text-center text-xs text-foreground">{group.label}<span className="block text-ink-secondary">{group.count} displayed assets</span></div>)}
        </div>
        {model.groups.length > 0 && <details className="absolute left-3 top-3 max-w-64 rounded border border-outline bg-surface/95 p-2 text-xs">
          <summary className="cursor-pointer">Environment groups ({model.groups.length})</summary>
          <p className="my-2 text-ink-secondary">Grouped by recorded provider, account and environment. Unknown fields stay unknown. Map labels appear on wider views; this list remains available at every size.</p>
          <ul className="max-h-40 overflow-y-auto">{model.groups.slice(0, 20).map((group) => <li key={group.key} className="mb-2 break-words">{group.label} · {group.count} displayed</li>)}</ul>
          {model.groups.length > 20 && <p>Showing 20 of {model.groups.length} groups. Use Summary to narrow the scope.</p>}
        </details>}
        <GraphTextAlternative
          id="sigma-graph-overview-text"
          renderer="Estate map"
          model={model.overview}
          summary={model.summary}
        />
        {renderError && (
          <div className="absolute inset-4 flex items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10 dark:bg-red-950/30 p-4 text-sm text-red-800 dark:text-red-100">
            WebGL renderer unavailable: {renderError}
          </div>
        )}
        <div className="pointer-events-auto absolute right-3 top-3 max-w-[min(30rem,calc(100vw-2rem))]">
          <details className="rounded-xl border border-[var(--border-subtle)] bg-[var(--background)]/85 p-2 backdrop-blur">
            <summary className="cursor-pointer list-none text-[10px] uppercase tracking-[0.18em] text-[var(--text-secondary)] [&::-webkit-details-marker]:hidden">
              Legend
            </summary>
            <div className="mt-2">
              <GraphLegend items={legendItems} embedded />
            </div>
          </details>
        </div>
        {!captureMode && (
        <div className="pointer-events-none absolute bottom-3 left-3 max-w-[min(34rem,calc(100vw-2rem))] rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]/90 px-3 py-2 text-xs text-[color:var(--text-secondary)] backdrop-blur">
          Pan or zoom to explore. Search for an exact asset, or use Summary to narrow the estate.
          <span className="sr-only">
            Maximum overview draw budget is {LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES.toLocaleString()} nodes and{" "}
            {LARGE_GRAPH_OVERVIEW_MAX_RENDERED_EDGES.toLocaleString()} edges.
          </span>
        </div>
        )}
      </div>
    </div>
  );
}
