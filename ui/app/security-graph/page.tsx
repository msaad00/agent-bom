"use client";

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  ArrowRight,
  GitBranch,
  Loader2,
} from "lucide-react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError, userFacingApiErrorMessage } from "@/lib/api-errors";

function _classifyGraphErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}
import { PageLaneHeader } from "@/components/page-lane";
import { AttackPathCard } from "@/components/attack-path-card";
import { ExposurePathCommandCenter } from "@/components/exposure-path-command-center";
import { GraphEvidenceExportButton } from "@/components/graph-chrome";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { GraphEmptyState, GraphPanelSkeleton } from "@/components/graph-state-panels";
import {
  api,
  formatDate,
  type FixFirstGraphViewResponse,
  type FixFirstPathCard,
  type GraphSnapshot,
  type PostureResponse,
  type UnifiedGraphResponse,
} from "@/lib/api";
import {
  attackPathKey,
  buildFindingsHref,
  buildGraphInvestigationHref,
  buildSecurityGraphHref,
  descriptiveAttackPathTitle,
  investigationRootForAttackPath,
  matchesAttackPathFocus,
  rankedAttackPathRows,
  recommendedAttackPathActions,
  moveAttackPathSelection,
  toAttackCardNodes,
  toExposurePathFromAttackPath,
} from "@/lib/attack-paths";
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import { useCaptureMode } from "@/lib/use-capture-mode";

const ATTACK_PATH_QUEUE_LIMIT = 75;
const ATTACK_PATH_QUEUE_PAGE_SIZE = 12;
const FIX_FIRST_CARD_LIMIT = 12;

function SecurityGraphPageContent() {
  const searchParams = useSearchParams();
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [graphData, setGraphData] = useState<UnifiedGraphResponse | null>(null);
  const [fixFirstView, setFixFirstView] = useState<FixFirstGraphViewResponse | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [loadingSnapshots, setLoadingSnapshots] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [graphLoadError, setGraphLoadError] = useState<string | null>(null);
  const [apiErrorKind, setApiErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [selectedAttackPathKey, setSelectedAttackPathKey] = useState<string | null>(null);
  const [focusApplied, setFocusApplied] = useState(false);
  const [showAllSnapshots, setShowAllSnapshots] = useState(false);
  const [visibleAttackPathCount, setVisibleAttackPathCount] = useState(ATTACK_PATH_QUEUE_PAGE_SIZE);
  const [investigationFocusMode, setInvestigationFocusMode] = useState(true);
  const captureMode = useCaptureMode();

  const focus = useMemo(
    () => ({
      scanId: searchParams.get("scan") ?? "",
      cve: searchParams.get("cve") ?? "",
      packageName: searchParams.get("package") ?? "",
      agentName: searchParams.get("agent") ?? "",
    }),
    [searchParams],
  );

  const focusLabel = useMemo(() => {
    const parts = [focus.cve, focus.packageName, focus.agentName].filter(Boolean);
    return parts.length > 0 ? parts.join(" · ") : null;
  }, [focus.agentName, focus.cve, focus.packageName]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoadingSnapshots(true);
      try {
        const [snapshotList, postureData] = await Promise.all([
          api.getGraphSnapshots(25),
          api.getPosture().catch(() => null),
        ]);
        if (cancelled) return;
        setSnapshots(snapshotList);
        setPosture(postureData);
        const requestedScanId = focus.scanId;
        const initialScanId =
          requestedScanId && snapshotList.some((snapshot) => snapshot.scan_id === requestedScanId)
            ? requestedScanId
            : snapshotList[0]?.scan_id ?? "";
        setSelectedScanId(initialScanId);
        setApiError(null);
        setGraphLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setApiError(userFacingApiErrorMessage(error, "Failed to load graph snapshots"));
        setApiErrorKind(_classifyGraphErrorKind(error));
        setSnapshots([]);
        setGraphData(null);
        setFixFirstView(null);
        setGraphLoadError(null);
      } finally {
        if (!cancelled) setLoadingSnapshots(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [focus.scanId]);

  useEffect(() => {
    if (!selectedScanId) {
      setGraphData(null);
      setFixFirstView(null);
      setSelectedAttackPathKey(null);
      setGraphLoadError(null);
      return;
    }

    let cancelled = false;

    async function loadGraph() {
      setLoadingGraph(true);
      try {
        const [graph, view] = await Promise.all([
          api.getGraphAttackPaths({
            scanId: selectedScanId,
            limit: ATTACK_PATH_QUEUE_LIMIT,
          }),
          api.getFixFirstGraphView({
            scanId: selectedScanId,
            cve: focus.cve || undefined,
            packageName: focus.packageName || undefined,
            agentName: focus.agentName || undefined,
            limit: FIX_FIRST_CARD_LIMIT,
          }),
        ]);
        if (cancelled) return;
        setGraphData(graph);
        setFixFirstView(view);
        setApiError(null);
        setGraphLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setGraphData(null);
        setFixFirstView(null);
        setGraphLoadError(userFacingApiErrorMessage(error, "Failed to load security graph"));
        setApiErrorKind(_classifyGraphErrorKind(error));
      } finally {
        if (!cancelled) setLoadingGraph(false);
      }
    }

    void loadGraph();
    return () => {
      cancelled = true;
    };
  }, [focus.agentName, focus.cve, focus.packageName, selectedScanId]);

  const selectedSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );
  const displayedSnapshots = useMemo(
    () => (showAllSnapshots ? snapshots : snapshots.slice(0, 8)),
    [showAllSnapshots, snapshots],
  );

  const fixFirstCards = useMemo(() => fixFirstView?.cards ?? [], [fixFirstView?.cards]);

  const graphNodeById = useMemo(() => {
    const nodes = new Map((graphData?.nodes ?? []).map((node) => [node.id, node]));
    for (const card of fixFirstCards) {
      for (const node of card.nodes ?? []) {
        nodes.set(node.id, node);
      }
    }
    return nodes;
  }, [fixFirstCards, graphData?.nodes]);

  const cardByPathKey = useMemo(() => {
    const next = new Map<string, FixFirstPathCard>();
    for (const card of fixFirstCards) {
      next.set(attackPathKey(card.attack_path), card);
    }
    return next;
  }, [fixFirstCards]);

  const attackPaths = useMemo(
    () =>
      fixFirstCards.length > 0
        ? fixFirstCards.map((card) => card.attack_path)
        : [...(graphData?.attack_paths ?? [])].sort(
            (left, right) => right.composite_risk - left.composite_risk,
          ),
    [fixFirstCards, graphData?.attack_paths],
  );
  const visibleAttackPaths = useMemo(
    () => attackPaths.slice(0, Math.min(visibleAttackPathCount, attackPaths.length)),
    [attackPaths, visibleAttackPathCount],
  );
  const hiddenAttackPathCount = Math.max(0, attackPaths.length - visibleAttackPaths.length);

  const hasFocusContext = Boolean(focus.cve || focus.packageName || focus.agentName);
  const selectedAttackPath = useMemo(
    () =>
      selectedAttackPathKey
        ? attackPaths.find((path) => attackPathKey(path) === selectedAttackPathKey) ?? null
        : attackPaths[0] ?? null,
    [attackPaths, selectedAttackPathKey],
  );
  const investigationRoot = useMemo(
    () =>
      selectedAttackPath
        ? investigationRootForAttackPath(selectedAttackPath, graphNodeById, focus)
        : null,
    [focus, graphNodeById, selectedAttackPath],
  );
  const fullGraphHref = useMemo(() => {
    if (investigationRoot) {
      return buildGraphInvestigationHref({
        scanId: selectedScanId || undefined,
        agentName: focus.agentName || undefined,
        rootId: investigationRoot.id,
        rootLabel: investigationRoot.label,
      });
    }

    const params = new URLSearchParams();
    if (selectedScanId) params.set("scan", selectedScanId);
    if (focus.agentName) params.set("agent", focus.agentName);
    const query = params.toString();
    return query ? `/graph?${query}` : "/graph";
  }, [focus.agentName, investigationRoot, selectedScanId]);
  const resetFocusHref = useMemo(
    () => buildSecurityGraphHref({ scanId: selectedScanId || undefined }),
    [selectedScanId],
  );

  const selectedFixFirstCard = useMemo(
    () => (selectedAttackPath ? cardByPathKey.get(attackPathKey(selectedAttackPath)) ?? null : null),
    [cardByPathKey, selectedAttackPath],
  );
  const selectedExposurePath = useMemo(
    () =>
      selectedAttackPath
        ? selectedFixFirstCard?.exposure_path ??
          selectedAttackPath.exposure_path ??
          toExposurePathFromAttackPath(selectedAttackPath, graphNodeById, {
            scanId: selectedScanId || undefined,
            rank: selectedFixFirstCard?.rank,
          })
        : null,
    [graphNodeById, selectedAttackPath, selectedFixFirstCard, selectedScanId],
  );

  const selectedPathActions = useMemo(
    () =>
      selectedAttackPath
        ? recommendedAttackPathActions(selectedAttackPath, graphNodeById, { scanId: selectedScanId || undefined })
        : [],
    [graphNodeById, selectedAttackPath, selectedScanId],
  );

  const emptyGraphState = useMemo(() => {
    if (hasFocusContext) {
      return {
        title: "No attack paths matched the current focus",
        detail: `The persisted graph loaded successfully, but no exploit chain matched ${focusLabel ?? "the current filters"}. Clear the focus or widen the query to inspect the rest of this snapshot.`,
        suggestions: [
          "Clear focus to review every persisted path in this snapshot.",
          "Open the full graph to inspect broader topology.",
          "Review vulnerabilities before the next focused scan completes.",
        ],
      };
    }

    return {
      title: "No precomputed attack paths are available for this snapshot",
      detail:
        "The persisted graph loaded successfully, but it does not currently contain exploit chains for the selected scan.",
      suggestions: [
        "Run a fresh scan to refresh the persisted graph snapshot.",
        "Open the full graph to inspect inventory and findings that did persist.",
        "Check the vulnerabilities page if you need fix context before the next scan completes.",
      ],
    };
  }, [focusLabel, hasFocusContext]);

  const graphErrorState = useMemo(() => {
    const detail = graphLoadError ?? "The graph API did not return attack-path data for this snapshot.";
    return {
      title: "Cannot load attack paths for this snapshot",
      detail,
      suggestions: [
        "Retry the graph load after confirming the API is reachable.",
        "Open the full graph only after this error clears.",
        "Check API logs for the rejected or failed attack-path request.",
      ],
    };
  }, [graphLoadError]);

  const loadingGraphMessage = focusLabel
    ? `Loading paths for ${focusLabel}…`
    : "Loading exposure paths…";

  useEffect(() => {
    setFocusApplied(false);
    setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
  }, [focus.agentName, focus.cve, focus.packageName, selectedScanId]);

  useEffect(() => {
    if (!selectedAttackPathKey) return;
    const selectedIndex = attackPaths.findIndex((path) => attackPathKey(path) === selectedAttackPathKey);
    if (selectedIndex < 0 || selectedIndex < visibleAttackPathCount) return;
    const nextPageCount =
      Math.ceil((selectedIndex + 1) / ATTACK_PATH_QUEUE_PAGE_SIZE) *
      ATTACK_PATH_QUEUE_PAGE_SIZE;
    setVisibleAttackPathCount(Math.min(attackPaths.length, nextPageCount));
  }, [attackPaths, selectedAttackPathKey, visibleAttackPathCount]);

  useEffect(() => {
    if (attackPaths.length === 0) {
      setSelectedAttackPathKey(null);
      return;
    }
    if (!focusApplied && hasFocusContext) {
      const focusedPath =
        attackPaths.find((path) => matchesAttackPathFocus(path, graphNodeById, focus)) ?? attackPaths[0]!;
      setSelectedAttackPathKey(attackPathKey(focusedPath));
      setFocusApplied(true);
      return;
    }
    if (!selectedAttackPathKey) {
      setSelectedAttackPathKey(attackPathKey(attackPaths[0]!));
      return;
    }
    if (!attackPaths.some((path) => attackPathKey(path) === selectedAttackPathKey)) {
      setSelectedAttackPathKey(attackPathKey(attackPaths[0]!));
    }
  }, [attackPaths, focus, focusApplied, graphNodeById, hasFocusContext, selectedAttackPathKey]);

  function handleAttackPathQueueKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    setSelectedAttackPathKey((currentKey) =>
      moveAttackPathSelection(attackPaths, currentKey, event.key === "ArrowRight" ? 1 : -1),
    );
  }

  if (apiError && !loadingSnapshots && snapshots.length === 0) {
    const fallbackTitle = apiErrorKind === "network" ? "Cannot load the security graph" : undefined;
    return (
      <ApiOfflineState
        title={fallbackTitle}
        detail={apiError}
        kind={apiErrorKind}
      />
    );
  }

  return (
    <div className="space-y-4">
      <PageLaneHeader
        lane="command"
        title="Security graph"
        subtitle="Ranked attack paths from persisted graph evidence — tuned for CISO review, AppSec triage, and GRC evidence export."
        actions={
          <>
            <GraphEvidenceExportButton
              scanId={selectedScanId || undefined}
              filenamePrefix={selectedScanId ? `scan-${selectedScanId}-security-graph` : undefined}
            />
            <Link
              href={fullGraphHref}
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              Full graph
              <GitBranch className="h-4 w-4" />
            </Link>
            <Link
              href="/remediation"
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              Remediation
              <ArrowRight className="h-4 w-4" />
            </Link>
          </>
        }
      />

      <GraphLensSwitcher variant="compact" />

      {selectedExposurePath ? (
        <ExposurePathCommandCenter
          path={selectedExposurePath}
          actions={selectedFixFirstCard?.next_actions ?? selectedPathActions}
          scanId={selectedScanId || undefined}
        />
      ) : null}

      {graphData && selectedAttackPath && (
        <SecurityGraphInvestigation
          graph={graphData as UnifiedGraphData}
          attackPath={selectedAttackPath}
          focusMode={investigationFocusMode}
          onFocusModeChange={setInvestigationFocusMode}
          fullGraphHref={fullGraphHref}
          loading={loadingGraph}
        />
      )}

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-3">
              <div>
                <p className="text-[11px] uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">Snapshot</p>
                <h2 className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">
                  {selectedSnapshot ? `Scan ${selectedSnapshot.scan_id.slice(0, 8)}…` : "No graph snapshot yet"}
                </h2>
                {selectedSnapshot && (
                  <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
                    {formatDate(selectedSnapshot.created_at)} · {selectedSnapshot.node_count} nodes · {selectedSnapshot.edge_count} edges
                  </p>
                )}
              </div>
              {posture && (
                <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2">
                  <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Posture</p>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="font-mono text-xl font-semibold text-red-300">{posture.grade}</span>
                    <span className="font-mono text-sm text-[color:var(--foreground)]">{posture.score}</span>
                  </div>
                </div>
              )}
            </div>
            {loadingSnapshots && (
              <span className="mt-2 inline-flex items-center gap-2 text-xs text-sky-400">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                loading snapshots
              </span>
            )}
          </div>
          {fixFirstView && (
            <div className="flex flex-wrap gap-2 text-xs">
              <QuickStat label="Matched paths" value={String(fixFirstView.summary.matched_paths)} tone="blue" />
              <QuickStat label="Covered findings" value={String(fixFirstView.summary.covered_findings)} tone="amber" />
              <QuickStat label="Highest risk" value={fixFirstView.summary.highest_risk.toFixed(1)} tone="red" />
            </div>
          )}
        </div>

        {snapshots.length > 0 ? (
              <>
                <div className="mt-4 flex flex-wrap gap-2">
                  {displayedSnapshots.map((snapshot) => {
                    const selected = snapshot.scan_id === selectedScanId;
                    return (
                      <button
                        key={snapshot.scan_id}
                        type="button"
                        onClick={() => setSelectedScanId(snapshot.scan_id)}
                        className={`rounded-xl border px-3 py-2 text-left text-xs transition ${
                          selected
                            ? "border-emerald-700 bg-emerald-950/40 text-emerald-200"
                            : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                        }`}
                      >
                        <div className="font-mono">{snapshot.scan_id.slice(0, 8)}…</div>
                        <div className="mt-1 text-[11px] opacity-80">{snapshot.node_count} nodes</div>
                      </button>
                    );
                  })}
                </div>
                {snapshots.length > 8 && (
                  <button
                    type="button"
                    onClick={() => setShowAllSnapshots((current) => !current)}
                    className="mt-3 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                  >
                    {showAllSnapshots ? "Show recent snapshots" : `Show all ${snapshots.length} snapshots`}
                  </button>
                )}
              </>
            ) : (
              !loadingSnapshots && (
                <div className="mt-4">
                  <GraphEmptyState
                    title="No persisted graph snapshots yet"
                    detail="Run a scan first so the security graph can build historical attack-path views from persisted graph evidence."
                    suggestions={[
                      "Run a local scan with graph output enabled.",
                      "Confirm the graph persistence backend is enabled.",
                      "Open the full graph after the first snapshot appears.",
                    ]}
                    command="agent-bom scan -p . -f graph"
                  />
                </div>
              )
            )}

      </section>

      {loadingGraph ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <GraphPanelSkeleton
            title="Loading security graph"
            detail={loadingGraphMessage}
          />
        </section>
      ) : graphLoadError ? (
        <section className="rounded-3xl border border-red-900/60 bg-red-950/10 p-4">
          <GraphEmptyState
            title={graphErrorState.title}
            detail={graphErrorState.detail}
            suggestions={graphErrorState.suggestions}
            command="agent-bom serve --api"
          />
          <div className="mt-4 flex flex-wrap gap-3 border-t border-red-900/40 pt-4">
            <Link
              href={fullGraphHref}
              className="inline-flex items-center gap-2 rounded-full border border-red-900/60 bg-red-950/30 px-3 py-1.5 text-xs text-red-200 transition hover:border-red-700"
            >
              Retry in full graph
              <GitBranch className="h-3.5 w-3.5" />
            </Link>
            {hasFocusContext && (
              <Link
                href={resetFocusHref}
                className="inline-flex items-center gap-2 rounded-full border border-red-900/60 bg-red-950/30 px-3 py-1.5 text-xs text-red-200 transition hover:border-red-700"
              >
                Clear focus
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </section>
      ) : attackPaths.length === 0 ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <GraphEmptyState
            title={emptyGraphState.title}
            detail={emptyGraphState.detail}
            suggestions={emptyGraphState.suggestions}
            command="agent-bom scan -p . -f graph"
          />
          <div className="mt-4 flex flex-wrap gap-3 border-t border-[color:var(--border-subtle)] pt-4">
            <Link
              href={fullGraphHref}
              className="inline-flex items-center gap-2 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
            >
              Open full graph
              <GitBranch className="h-3.5 w-3.5" />
            </Link>
            <Link
              href={buildFindingsHref({ scanId: selectedScanId || undefined })}
              className="inline-flex items-center gap-2 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
            >
              Review findings
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            {hasFocusContext && (
              <Link
                href={resetFocusHref}
                className="inline-flex items-center gap-2 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
              >
                Clear focus
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </section>
      ) : (
        <>
          <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-[color:var(--foreground)]">
                  {attackPaths.length} ranked path{attackPaths.length !== 1 ? "s" : ""}
                </h2>
                {focusLabel && (
                  <p className="mt-1 text-xs text-emerald-300">Focused: {focusLabel}</p>
                )}
              </div>
              <div className="font-mono text-lg text-red-300">{attackPaths[0]!.composite_risk.toFixed(1)}</div>
            </div>

            <div
              className="mt-4 grid max-h-[28rem] max-w-full grid-cols-1 gap-2 overflow-y-auto pr-1 outline-none md:grid-cols-2 xl:grid-cols-3"
              tabIndex={0}
              onKeyDown={handleAttackPathQueueKeyDown}
              aria-label="Attack path queue"
            >
              {rankedAttackPathRows(visibleAttackPaths, fixFirstCards).map(({ path, card, rank, key }) => {
                const selectionKey = attackPathKey(path);
                const pathNodes = toAttackCardNodes(path, graphNodeById);
                if (pathNodes.length === 0) return null;
                const active = selectedAttackPath ? attackPathKey(selectedAttackPath) === selectionKey : false;
                const title = descriptiveAttackPathTitle(card?.title, pathNodes);
                return (
                  <div
                    key={key}
                    className={`min-w-0 rounded-2xl border bg-[color:var(--surface-elevated)] p-3 transition ${
                      active
                        ? "border-orange-400/70 ring-2 ring-orange-400/70 ring-offset-2 ring-offset-[color:var(--surface)]"
                        : "border-[color:var(--border-subtle)]"
                    }`}
                  >
                    <div className="mb-3 flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-[11px] uppercase tracking-[0.18em] text-orange-300">#{rank} fix first</div>
                        <div
                          title={title}
                          className="mt-1 text-sm font-semibold leading-5 text-[color:var(--foreground)] [overflow-wrap:anywhere]"
                        >
                          {title}
                        </div>
                      </div>
                      <div className="shrink-0 rounded-xl border border-red-900/60 bg-red-950/30 px-2.5 py-1 text-right">
                        <div className="text-[9px] font-semibold uppercase tracking-[0.14em] text-red-300/80">Path risk</div>
                        <div className="font-mono text-sm font-semibold leading-4 text-red-200">
                          {path.composite_risk.toFixed(1)}
                        </div>
                      </div>
                    </div>
                    <AttackPathCard
                      nodes={pathNodes}
                      riskScore={path.composite_risk}
                      captureMode={captureMode}
                      compact
                      showRiskBadge={false}
                      onClick={() => setSelectedAttackPathKey(selectionKey)}
                    />
                    {card && card.risk_reasons.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {card.risk_reasons.slice(0, 3).map((reason) => (
                          <span
                            key={`${card.id}-${reason.kind}`}
                            title={reason.detail}
                            className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-1 text-[11px] text-[color:var(--text-secondary)]"
                          >
                            {reason.label}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            {hiddenAttackPathCount > 0 && (
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-3">
                <p className="text-xs text-[color:var(--text-tertiary)]">
                  Showing {visibleAttackPaths.length} of {attackPaths.length} ranked paths.
                </p>
                <button
                  type="button"
                  onClick={() =>
                    setVisibleAttackPathCount((current) =>
                      Math.min(attackPaths.length, current + ATTACK_PATH_QUEUE_PAGE_SIZE),
                    )
                  }
                  className="rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                >
                  Show {Math.min(ATTACK_PATH_QUEUE_PAGE_SIZE, hiddenAttackPathCount)} more
                </button>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default function SecurityGraphPage() {
  return (
    <Suspense fallback={<div className="flex min-h-[40vh] items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-[color:var(--text-secondary)]" /></div>}>
      <SecurityGraphPageContent />
    </Suspense>
  );
}

function QuickStat({
  label,
  value,
  tone = "zinc",
}: {
  label: string;
  value: string;
  tone?: "zinc" | "red" | "amber" | "blue";
}) {
  const tones = {
    zinc: "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]",
    red: "border-red-900/60 bg-red-950/20 text-red-200",
    amber: "border-amber-900/60 bg-amber-950/20 text-amber-200",
    blue: "border-sky-900/60 bg-sky-950/20 text-sky-200",
  };
  return (
    <div className={`rounded-2xl border px-4 py-3 ${tones[tone]}`}>
      <div className="text-[11px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1 font-mono text-xl">{value}</div>
    </div>
  );
}
