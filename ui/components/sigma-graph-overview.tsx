"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  const [groupQuery, setGroupQuery] = useState("");
  const [assetQuery, setAssetQuery] = useState("");
  const [grouping, setGrouping] = useState<"type" | "environment">("type");
  const [scopeSelection, setScopeSelection] = useState<{ snapshot: string; key: string } | null>(null);
  const scopeControlsRef = useRef<HTMLDetailsElement | null>(null);
  const controlsRef = useRef<HTMLDetailsElement | null>(null);
  const groupEdgesRef = useRef<SVGSVGElement | null>(null);
  const groupLabelsRef = useRef<HTMLDivElement | null>(null);
  const palette = useGraphCanvasPalette();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rendererRef = useRef<Sigma<SigmaNodeAttributes, SigmaEdgeAttributes> | null>(null);
  const selectedNodeIdRef = useRef<string | null>(null);
  const requestedFocusRef = useRef<string | null>(null);
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
  const scopeKey = scopeSelection?.snapshot === presentationSnapshotId ? scopeSelection.key : null;
  const presentationLens = presentationScope?.lens ?? "";
  const presentationFilterScope = presentationScope?.scope ?? "";
  const cameraStorageKey = useMemo(
    () => hasPresentationScope
      ? sigmaCameraStorageKey({
          tenantId: presentationTenantId,
          subject: presentationSubject,
          snapshotId: presentationSnapshotId,
          lens: presentationLens,
          scope: `${grouping === "type" ? presentationFilterScope : `${presentationFilterScope}:grouping=environment`}${scopeKey ? `:cluster=${scopeKey}` : ""}`,
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
      scopeKey,
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
        ? buildSigmaGraphOverviewModelFromUnifiedGraph(graph, filters, grouping, scopeKey)
        : buildSigmaGraphOverviewModel(nodes, edges, grouping, scopeKey),
    [edges, filters, graph, nodes, grouping, scopeKey],
  );
  const enterScope = (key: string | null) => {
    if (scopeControlsRef.current) scopeControlsRef.current.open = false;
    const camera = rendererRef.current?.getCamera().getState();
    if (camera && cameraPersistenceEnabled && cameraStorageKey && cameraOwner) {
      registerGraphPresentationKey(browserStorage(), cameraOwner, cameraStorageKey);
      writeSigmaCameraPresentation(browserStorage(), cameraStorageKey, camera);
    }
    setScopeSelection(key ? { snapshot: presentationSnapshotId, key } : null);
    setSelectedNodeId(null);
    onClearSelection?.();
  };
  const currentModel = useRef(model);
  const currentCameraKey = useRef(cameraStorageKey);
  useEffect(() => {
    currentModel.current = model;
    const scopeChanged = currentCameraKey.current !== cameraStorageKey;
    currentCameraKey.current = cameraStorageKey;
    const renderer = rendererRef.current;
    if (!renderer) return;
    renderer.setGraph(model.graph);
    if (!scopeChanged) return;
    const saved = cameraPersistenceEnabled && cameraStorageKey
      ? readSigmaCameraPresentation(browserStorage(), cameraStorageKey) : null;
    renderer.getCamera().setState(saved ?? { x: 0.5, y: 0.5, angle: 0, ratio: 1.05 });
  }, [model, cameraStorageKey, cameraPersistenceEnabled]);
  const groupByKey = new Map(model.groups.map(group => [group.key, group]));
  const overviewConnections = model.connections.filter(edge => groupByKey.has(edge.source) && groupByKey.has(edge.target)).slice(0, 12);
  const isBudgeted = model.overview.omittedNodeCount > 0 || model.overview.omittedEdgeCount > 0;
  const frameRequestedNode = useCallback(() => {
    const id = requestedFocusRef.current;
    const renderer = rendererRef.current;
    if (!id || !renderer) return;
    requestedFocusRef.current = null;
    const position = renderer.getNodeDisplayData(id);
    if (!position) return;
    // Instant framing respects reduced motion and leaves subsequent manual pan alone.
    renderer.getCamera().setState({ x: position.x, y: position.y, ratio: Math.min(renderer.getCamera().getState().ratio, 0.3) });
  }, []);
  const selectDisplayedNode = (id: string) => {
    requestedFocusRef.current = id;
    setSelectedNodeId(id);
    if (controlsRef.current) controlsRef.current.open = false;
    onNodeSelectRef.current?.(id);
    // Selection can resize the canvas or replace its renderer; use the current one.
    window.requestAnimationFrame(frameRequestedNode);
  };


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
    let pendingCamera: { key: string; camera: SigmaCameraState } | null = null;
    let persistTimer: number | null = null;

    const storage = cameraPersistenceEnabled ? browserStorage() : null;
    const flushCamera = () => {
      if (!cameraOwner || !pendingCamera) return;
      registerGraphPresentationKey(storage, cameraOwner, pendingCamera.key);
      writeSigmaCameraPresentation(storage, pendingCamera.key, pendingCamera.camera);
      pendingCamera = null;
      persistTimer = null;
    };

    const start = async () => {
      try {
        const { default: SigmaRenderer } = await import("sigma");
        if (!alive || !containerRef.current) return;
        renderer = new SigmaRenderer(currentModel.current.graph, container, {
          allowInvalidContainer: true,
          autoCenter: true,
          autoRescale: true,
          defaultEdgeColor: palette.defaultEdge,
          defaultNodeColor: palette.defaultNode,
          enableEdgeEvents: false,
          hideEdgesOnMove: true,
          hideLabelsOnMove: true,
          itemSizesReference: "screen",
          labelColor: { color: palette.label },
          // Label level-of-detail. The grid keeps at most a handful of labels
          // per cell so they never overlap into a smear; the size threshold
          // surfaces the largest / highest-signal nodes first and lets the rest
          // appear as the user zooms in (rendered size grows) or hovers a node.
          labelDensity: 0.08,
          labelFont: "Inter, ui-sans-serif, system-ui, sans-serif",
          labelGridCellSize: 170,
          labelRenderedSizeThreshold: 3,
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
              forceLabel: selected,
              label: dimmedBySelection ? "" : data.label,
              // Parent focus marks unrelated nodes hidden; retain them as faded context here.
              hidden: selectedNodeIdRef.current ? false : data.hidden,
              highlighted: selected,
              size: selected ? 6 : neighbor ? 4 : 2.2,
              zIndex: selected ? 4 : data.zIndex,
              ...(dimmedBySelection ? { color: palette.stage, size: 0.5 } : {}),
            };
          },
          edgeReducer: (_edge, data) => {
            const selected = selectedNodeIdRef.current;
            const selectedEdge = selected
              ? currentModel.current.graph.source(_edge) === selected || currentModel.current.graph.target(_edge) === selected
              : false;
            return {
              ...data,
              color: palette.defaultEdge,
              hidden: !selectedEdge,
              size: 1.4,
              zIndex: selectedEdge ? 3 : data.zIndex,
            };
          },
        });
        // Sigma's hover bubble is white in both themes; use dark text inside it.
        const drawHover = renderer.getSetting("defaultDrawNodeHover");
        renderer.setSetting("defaultDrawNodeHover", (context, data, settings) =>
          drawHover(context, data, { ...settings, labelColor: { color: palette.hoverLabel } }),
        );
        rendererRef.current = renderer;
        const positionGroupLabels = () => {
          if (!renderer || !groupLabelsRef.current) return;
          const activeRenderer = renderer;
          const dimensions = activeRenderer.getDimensions();
          const model = currentModel.current;
          const drawnGroups = new Map(model.groups.map(group => [group.key, group]));
          model.connections.filter(edge => drawnGroups.has(edge.source) && drawnGroups.has(edge.target)).slice(0, 12).forEach((edge, index) => {
            const line = groupEdgesRef.current?.children[index] as SVGLineElement | undefined;
            if (!line) return;
            const source = drawnGroups.get(edge.source)!, target = drawnGroups.get(edge.target)!;
            const from = activeRenderer.graphToViewport({ x: source.x, y: source.centerY });
            const to = activeRenderer.graphToViewport({ x: target.x, y: target.centerY });
            line.setAttribute("x1", String(from.x)); line.setAttribute("y1", String(from.y));
            line.setAttribute("x2", String(to.x)); line.setAttribute("y2", String(to.y));
          });
          const placed: Array<{ x: number; y: number }> = [];
          model.groups.forEach((group, index) => {
            const label = groupLabelsRef.current?.children[index] as HTMLElement | undefined;
            if (!label) return;
            const position = activeRenderer.graphToViewport({ x: group.x, y: group.centerY });
            const beside = activeRenderer.graphToViewport({ x: group.x + 120, y: group.y });
            const anchor = { x: Math.max(80, Math.min(dimensions.width - 80, position.x)), y: Math.max(52, position.y - 28) };
            const readable = (model.groups.length <= 8 || Math.abs(beside.x - position.x) >= 65) && !placed.some(p => Math.abs(p.x - anchor.x) < 160 && Math.abs(p.y - anchor.y) < 52);
            if (readable) placed.push(anchor);
            label.style.display = readable && position.x >= 0 && position.y >= 0 && position.x <= dimensions.width && position.y <= dimensions.height ? "block" : "none";
            label.style.transform = `translate(${anchor.x}px, ${anchor.y}px) translateX(-50%)`;
          });
        };
        renderer.on("afterRender", positionGroupLabels);
        renderer.on("clickNode", ({ node }) => {
          requestedFocusRef.current = null;
          setSelectedNodeId(node);
          onNodeSelectRef.current?.(node);
        });
        renderer.on("clickStage", () => {
          requestedFocusRef.current = null;
          setSelectedNodeId(null);
          onClearRef.current?.();
        });
        const camera = renderer.getCamera();
        const savedCamera = cameraPersistenceEnabled && currentCameraKey.current
          ? readSigmaCameraPresentation(storage, currentCameraKey.current)
          : null;
        // Sigma's constructor performs its normal fit/centering. A valid saved
        // camera takes precedence over that one-shot default; absent or invalid
        // state gets the established overview framing.
        camera.setState(savedCamera ?? { ratio: 1.05 });
        if (cameraPersistenceEnabled) {
          camera.on("updated", (state) => {
            const sanitized = sanitizeSigmaCameraState(state);
            if (!sanitized) return;
            const key = currentCameraKey.current;
            if (!key) return;
            if (pendingCamera && pendingCamera.key !== key) flushCamera();
            pendingCamera = { key, camera: sanitized };

            if (persistTimer === null) {
              // Camera updates fire continuously while panning. Throttle the
              // synchronous localStorage write while retaining the latest frame.
              persistTimer = window.setTimeout(flushCamera, 80);
            }
          });
        }
        renderer.refresh();
        frameRequestedNode();
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
  }, [cameraOwner, cameraPersistenceEnabled, palette, frameRequestedNode]);

  const focused = selectedNodeId && model.graph.hasNode(selectedNodeId) ? selectedNodeId : null;
  const neighbors = focused ? model.graph.neighbors(focused).filter((id) => id !== focused) : [];

  return (
    <div
      className={`flex h-full flex-col overflow-hidden bg-background ${
        embedded
          ? "min-h-0"
          : "min-h-[72vh] rounded-xl border border-outline shadow-2xl shadow-black/30"
      }`}
      data-testid="sigma-graph-overview"
    >
      <div className="border-b border-outline bg-background/95 p-3">
        <div className="flex min-w-0 flex-col gap-1 sm:flex-row sm:flex-wrap sm:items-center sm:gap-2">
          <span className="inline-flex w-fit shrink-0 items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 dark:bg-emerald-950/25 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-emerald-700 dark:text-emerald-200">
            <Sparkles className="h-3.5 w-3.5" />
            Estate map
          </span>
          <span className="min-w-0 text-xs leading-snug text-ink-tertiary sm:min-w-[12rem] sm:flex-1">
            Select an asset to reveal its connections.
          </span>
          <button type="button" className="shrink-0 rounded-full border border-outline px-3 py-1 text-xs text-ink-secondary" onClick={() => rendererRef.current?.getCamera().setState({ x: 0.5, y: 0.5, angle: 0, ratio: 1.05 })}>Fit map</button>
        </div>
        <details ref={controlsRef} className="mt-2 text-xs text-ink-secondary">
          <summary className="cursor-pointer">Map controls</summary>
          <label className="mt-2 flex flex-col gap-1">Find a displayed asset
            <input value={assetQuery} onChange={(event) => setAssetQuery(event.target.value)} className="rounded border border-outline bg-background px-2 py-1 text-foreground" placeholder="Name or exact ID" />
          </label>
          {assetQuery.trim() && <ul className="mt-2 max-h-36 overflow-y-auto">
            {model.overview.nodes.filter((node) => `${node.id} ${node.label}`.toLowerCase().includes(assetQuery.trim().toLowerCase())).slice(0, 10).map((node) => <li key={node.id}><button type="button" className="break-all py-1 text-left text-sky-700 dark:text-sky-300" onClick={() => selectDisplayedNode(node.id)}>{node.label} · {node.id}</button></li>)}
            <li className="mt-1 text-ink-tertiary">Up to 10 matches from displayed assets. Use graph search for broader coverage.</li>
          </ul>}
        <label className="mt-2 flex items-center gap-2 text-xs text-ink-secondary">Group displayed assets by
          <select aria-label="Map grouping" value={grouping} onChange={(event) => { enterScope(null); setGrouping(event.target.value as "type" | "environment"); }} className="rounded border border-outline bg-background px-2 py-1 text-foreground">
            <option value="type">Asset type</option><option value="environment">Environment</option>
          </select>
        </label>
        </details>
        {scopeKey && <button type="button" className="mt-2 graph-chip-neutral" onClick={() => enterScope(null)}>Back to all groups</button>}
        <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-ink-tertiary">
          <span>
            Displayed: {model.overview.nodes.length.toLocaleString()}/{model.overview.sourceNodeCount.toLocaleString()} nodes · {" "}
            {model.overview.edges.length.toLocaleString()}/{model.overview.sourceEdgeCount.toLocaleString()} available connections.
          </span>
          {isBudgeted && (
            <details><summary className="cursor-pointer">Partial overview</summary><p className="mt-1 max-w-lg">Lower-signal items are omitted from this overview; use search, filters, or drill-in for exact detail. Connections appear when an asset is selected.</p></details>
          )}
        </div>
        <details className="mt-2 text-xs text-ink-secondary">
          <summary className="cursor-pointer">Graph summary</summary>
        <div className="mt-2">
          {model.summary.topRelationships.map(item => `${item.relationship.replace(/_/g, " ")}: ${item.count}`).join(" · ")}
        </div>
        <p className="mt-2 text-xs text-ink-secondary">{model.summary.findings.toLocaleString()} findings · {model.summary.criticalFindings.toLocaleString()} critical · {model.summary.credentials.toLocaleString()} credentials · {model.summary.tools.toLocaleString()} tools</p>
        </details>
      </div>

      {focused && <div className="border-b border-outline bg-surface px-3 py-2 text-xs" aria-label="Focused graph asset">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="min-w-0 break-words"><strong>{model.graph.getNodeAttribute(focused, "label")}</strong> · {neighbors.length} connected assets in this displayed graph</p>
          <button type="button" className="graph-chip-neutral" onClick={() => {
            const renderer = rendererRef.current;
            if (!renderer) return;
            const points = [focused, ...neighbors].map(id => renderer.getNodeDisplayData(id)).filter((point): point is NonNullable<typeof point> => Boolean(point));
            if (!points.length) return;
            const xs = points.map(p => p.x), ys = points.map(p => p.y);
            const left = Math.min(...xs), right = Math.max(...xs), bottom = Math.min(...ys), top = Math.max(...ys);
            const { width, height } = renderer.getDimensions();
            const shortest = Math.min(width, height);
            const ratio = Math.max((right - left) * shortest / width, (top - bottom) * shortest / height, 0.2) * 1.4;
            renderer.getCamera().setState({ x: (left + right) / 2, y: (bottom + top) / 2, angle: 0, ratio });
          }}>Fit connections</button>
          <button type="button" className="graph-chip-neutral" onClick={() => { requestedFocusRef.current = null; setSelectedNodeId(null); onClearSelection?.(); }}>Clear focus</button>
        </div>
        <details className="mt-2">
          <summary className="cursor-pointer">Explore connected assets</summary>
          <p className="my-2 text-ink-secondary">Recorded connections, not proof of authorized access or execution. Open an asset’s details to inspect evidence or expand beyond this view.</p>
          <ul className="max-h-40 space-y-1 overflow-y-auto">
            {neighbors.slice(0, 12).map((id) => <li key={id}><button type="button" className="text-sky-700 underline dark:text-sky-300" title={id} onClick={() => selectDisplayedNode(id)}>{model.graph.getNodeAttribute(id, "label")} <span className="text-ink-secondary">({model.graph.getNodeAttribute(id, "nodeType")})</span></button></li>)}
          </ul>
          {neighbors.length > 12 && <p>Showing 12 of {neighbors.length} connected assets. Use the details panel to investigate further.</p>}
          {neighbors.length === 0 && <p>No connected assets are present in this displayed scope.</p>}
        </details>
      </div>}
      <div className="relative min-h-0 flex-1 bg-background">
        <div
          ref={containerRef}
          className="h-full min-h-[20rem] w-full"
          role="img"
          aria-label="WebGL security graph overview"
          aria-describedby="sigma-graph-overview-text"
          data-testid="sigma-graph-overview-canvas"
        />
        {!focused && <svg ref={groupEdgesRef} className="pointer-events-none absolute inset-0 h-full w-full text-ink-tertiary" aria-hidden="true">
          {overviewConnections.map(edge => <line key={`${edge.source}:${edge.target}`} stroke="currentColor" strokeOpacity="0.25" strokeWidth="1" strokeDasharray="3 5"><title>{edge.count} recorded relationships between groups</title></line>)}
        </svg>}
        <div ref={groupLabelsRef} className="pointer-events-none absolute inset-0 overflow-hidden">
          {model.groups.map((group) => <button type="button" key={group.key} onClick={() => enterScope(group.key)} className="pointer-events-auto absolute left-0 top-0 hidden max-w-36 rounded border border-outline bg-surface/95 px-2 py-1 text-center text-xs text-foreground">{group.label}<span className="block text-ink-secondary">{group.count} displayed / {group.loadedCount} loaded</span></button>)}
        </div>
        {model.scopes.length > 0 && <details ref={scopeControlsRef} className="absolute left-3 top-3 max-w-64 rounded border border-outline bg-surface/95 p-2 text-xs">
          <summary className="cursor-pointer">{grouping === "environment" ? "Environment groups" : "Asset types"} ({model.scopes.length})</summary>
          <p className="my-2 text-ink-secondary">{grouping === "environment" ? "Grouped by recorded provider, account and environment. Unknown fields stay unknown." : "Grouped by asset type. Proximity is a layout choice, not an access relationship."}</p>
          <input aria-label="Find a group" className="mb-2 w-full rounded border border-outline bg-background p-1" value={groupQuery} onChange={event => setGroupQuery(event.target.value)} placeholder="Filter groups" />
          <ul className="max-h-40 overflow-y-auto">{model.scopes.filter(group => group.label.toLowerCase().includes(groupQuery.toLowerCase())).slice(0, 20).map((group) => <li key={group.key}><button type="button" className="min-h-9 break-words py-1 text-left underline" onClick={() => enterScope(group.key)}>{group.label} · {group.count} loaded</button></li>)}</ul>
          <p className="mt-1 text-ink-secondary">Up to 20 matching groups from loaded evidence.</p>
          {!scopeKey && <details className="mt-2"><summary>Between groups ({model.connections.length})</summary><p>Dashed lines summarize recorded relationships, not proven access. {overviewConnections.length} group pairs shown.</p><ul className="max-h-32 overflow-y-auto">{overviewConnections.map(edge => <li key={`${edge.source}:${edge.target}`} className="mt-2">{groupByKey.get(edge.source)!.label} → {groupByKey.get(edge.target)!.label}: {edge.count}</li>)}</ul></details>}
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
          <details className="rounded-xl border border-outline bg-background/85 p-2 backdrop-blur">
            <summary className="cursor-pointer list-none text-[10px] uppercase tracking-[0.18em] text-ink-secondary [&::-webkit-details-marker]:hidden">
              Legend
            </summary>
            <div className="mt-2">
              <GraphLegend items={legendItems} embedded />
            </div>
          </details>
        </div>
        {!captureMode && (
        <div className="pointer-events-none absolute bottom-3 left-3 text-[10px] text-ink-tertiary">
          Scroll to zoom · drag to pan · select to investigate
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
