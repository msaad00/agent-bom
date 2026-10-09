"use client";

import { AdvisoryFreshness } from "@/components/advisory-freshness";

import { investigationHref, investigationView } from "@/lib/investigation-url";
import { selectAttackPathQueue } from "@/lib/attack-path-queue";
import { GraphSnapshotReceipt } from "@/components/graph-snapshot-receipt";
import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  ArrowRight,
  GitBranch,
  Loader2,
} from "lucide-react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError, userFacingApiErrorMessage } from "@/lib/api-errors";
import { resolveSecurityGraphSurface } from "@/lib/security-graph-route";

function _classifyGraphErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}
import type { RankedPathRow } from "@/components/ranked-path-list";
import { AttackPathTechniqueChain } from "@/components/attack-path-technique-chain";
import { AttackPathCorrelationProof } from "@/components/attack-path-correlation-proof";
import { ExposurePathCommandCenter, type ExposurePathView } from "@/components/exposure-path-command-center";
import {
  InvestigationFilterDrawer,
  InvestigationPathWorkspace,
  InvestigationTools,
} from "@/components/investigation-path-workspace";
import { InvestigationExportButton } from "@/components/investigation-export-button";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { DeployGatePanel } from "@/components/deploy-gate-panel";
import { ExposurePathLens } from "@/components/exposure-path-lens";
import { GraphEmptyState, GraphPanelSkeleton } from "@/components/graph-state-panels";
import { GraphAnalysisStatusBanner, graphAnalysisStatusCopy } from "@/components/graph-analysis-status";
import { GraphCampaignPanel } from "@/components/graph-campaign-panel";
import {
  GraphCorrelationWorkflow,
  type GraphCorrelationOutcome,
} from "@/components/graph-correlation-workflow";
import { GraphPathQueueContinuation } from "@/components/graph-path-queue-continuation";
import { useAuthState } from "@/components/auth-provider";
import {
  GraphPresetControls,
  type InvestigationPresetFilters,
} from "@/components/graph-preset-controls";
import { InvestigationFilterChips } from "@/components/investigation-filter-chips";
import {
  InvestigationStepStrip,
  parseInvestigationStep,
  type InvestigationStep,
} from "@/components/investigation-step-strip";
import {
  api,
  formatDate,
  type FixFirstGraphViewResponse,
  type FixFirstPathCard,
  type GraphAttackCampaign,
  type GraphCorrelationRun,
  type GraphSnapshot,
  type PostureResponse,
  type UnifiedGraphResponse,
} from "@/lib/api";
import {
  attackPathKey,
  attackPathRoleChain,
  buildFindingsHref,
  buildGraphInvestigationHref,
  buildSecurityGraphHref,
  descriptiveAttackPathTitle,
  dedupeAttackPathsForPresentation,
  graphPathQueueCounts,
  investigationRootForAttackPath,
  labelsForAttackPathType,
  matchesAttackPathFocus,
  mergeAttackPathGraphPages,
  rankedAttackPathRows,
  recommendedAttackPathActions,
  toAttackCardNodes,
  toExposurePathFromAttackPath,
  withCanonicalExposurePresentation,
} from "@/lib/attack-paths";
import { FindingInvestigationContext } from "@/components/finding-investigation-context";
import { buildFindingAssetHref, withFindingContext } from "@/lib/finding-investigation-href";
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";
import { GraphSurface } from "@/app/graph/graph-surface";
import type { UnifiedGraphData, UnifiedNode } from "@/lib/graph-schema";
import { tonedChipClass } from "@/lib/toned-chip";
import { investigationEstateMode } from "@/lib/investigation-estate-mode";
import { useCaptureMode } from "@/lib/use-capture-mode";
import { useSelectedPathGraph } from "@/hooks/use-selected-path-graph";
import {
  buildCorrelationPathHref,
  buildCorrelationRemediationHref,
  completeDirectedHopCount,
  correlationOutcomeMatchesOutput,
  focusCorrelationPathTarget,
  latestCompletedCorrelation,
  selectInitialGraphSnapshot,
} from "@/lib/security-graph-focus";
import {
  collectPathEnvironments,
  filterAttackPathsForInvestigation,
  filterInvestigationQuestion,
} from "@/lib/investigation-path-filters";

const EMPTY_INVESTIGATION_FILTERS: InvestigationPresetFilters = {
  severity: null,
  layer: null,
  evidenceTier: null,
  environment: null,
};

/** First/next fetch size for GET /v1/graph/attack-paths (API offset paging). */
const ATTACK_PATH_FETCH_PAGE = 10;
const ATTACK_PATH_QUEUE_PAGE_SIZE = 10;
const FIX_FIRST_CARD_LIMIT = 10;
const DEFAULT_SNAPSHOT_CHIP_COUNT = 3;

function AttackPathInvestigationContent() {
  const captureMode = useCaptureMode();
  const searchParams = useSearchParams();
  const correlationCaptureMode = captureMode && searchParams.get("correlation") === "1";
  const requestedPathMode = searchParams.get("path");
  const requestedPathScanId = searchParams.get("scan");
  const focusedTopPathRef = useRef<string | null>(null);
  const router = useRouter();
  const pathname = usePathname();
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [latestCorrelationRun, setLatestCorrelationRun] = useState<GraphCorrelationRun | null>(null);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [currentEstateId, setCurrentEstateId] = useState("");
  const [graphData, setGraphData] = useState<UnifiedGraphResponse | null>(null);
  const [fixFirstView, setFixFirstView] = useState<FixFirstGraphViewResponse | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [loadingSnapshots, setLoadingSnapshots] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [loadingFixFirst, setLoadingFixFirst] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [graphLoadError, setGraphLoadError] = useState<string | null>(null);
  const [fixFirstLoadError, setFixFirstLoadError] = useState<string | null>(null);
  const [apiErrorKind, setApiErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [selectedAttackPathKey, setSelectedAttackPathKey] = useState<string | null>(null);
  const [focusApplied, setFocusApplied] = useState(false);
  const [showAllSnapshots, setShowAllSnapshots] = useState(false);
  const [visibleAttackPathCount, setVisibleAttackPathCount] = useState(ATTACK_PATH_QUEUE_PAGE_SIZE);
  const [loadingMorePaths, setLoadingMorePaths] = useState(false);
  const [morePathsError, setMorePathsError] = useState<string | null>(null);
  const pathPageRequest = useRef<AbortController | null>(null);
  const sharedSelectionScan = useRef<string | null>(null);
  const [investigationFocusMode, setInvestigationFocusMode] = useState(true);
  const [pathView, setPathView] = useState<ExposurePathView>(() => investigationView(searchParams.get("path_view")));
  const requestedQuestion = searchParams.get("question");
  const requestedSelectedPath = searchParams.get("selected_path");
  useEffect(() => setPathView(investigationView(searchParams.get("path_view"))), [searchParams]);
  const sharePathView = useCallback((view: ExposurePathView) => {
    setPathView(view);
    // Switching an already loaded representation must not navigate/remount
    // the workspace after its graph has scrolled into view.
    window.history.replaceState(null, "", investigationHref(pathname, searchParams.toString(), { path_view: view }));
  }, [pathname, searchParams]);
  const [investigationFilters, setInvestigationFilters] =
    useState<InvestigationPresetFilters>(EMPTY_INVESTIGATION_FILTERS);
  const [pinnedNodeId, setPinnedNodeId] = useState<string | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Partial<Record<InvestigationStep, boolean>>>(
    {},
  );
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);

  const focus = useMemo(
    () => ({
      scanId: searchParams.get("scan") ?? "",
      cve: searchParams.get("cve") ?? "",
      packageName: searchParams.get("package") ?? "",
      agentName: searchParams.get("agent") ?? "",
      nodeId: searchParams.get("node") ?? "",
      findingId: searchParams.get("finding") ?? "",
      traceId: searchParams.get("trace") ?? searchParams.get("runtime_trace_id") ?? "",
    }),
    [searchParams],
  );

  const investigationStep = parseInvestigationStep(searchParams.get("step"));
  const selectedScenarioId = searchParams.get("scenario");

  useEffect(() => {
    if (!selectedScenarioId || searchParams.get("state") === "current") return;
    const next = new URLSearchParams(searchParams.toString());
    next.set("state", "current");
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  }, [pathname, router, searchParams, selectedScenarioId]);

  const setInvestigationStep = useCallback(
    (next: InvestigationStep) => {
      const params = new URLSearchParams(searchParams.toString());
      if (next === "path") params.delete("step");
      else params.set("step", next);
      params.set("path_view", next === "impact" ? "graph" : "path");
      const query = params.toString();
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
      setCompletedSteps((current) => ({ ...current, [next]: true }));
      if (next === "fix") {
        setPathView("path");
      } else if (next === "impact") {
        setPathView("graph");
        setInvestigationFocusMode(true);
      } else {
        setPathView("path");
      }
    },
    [pathname, router, searchParams],
  );

  const selectSnapshot = useCallback(
    (scanId: string) => {
      setSelectedScanId(scanId);
      const params = new URLSearchParams(searchParams.toString());
      params.set("scan", scanId);
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  const openCorrelationPath = useCallback(
    (scanId: string) => {
      setSelectedScanId(scanId);
      setSelectedAttackPathKey(null);
      setFocusApplied(true);
      setInvestigationFocusMode(true);
      setPathView("path");
      setInvestigationFilters(EMPTY_INVESTIGATION_FILTERS);
      setSelectedCampaignId(null);
      setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
      router.push(buildCorrelationPathHref(pathname, searchParams, scanId), { scroll: false });
      window.requestAnimationFrame(() => {
        focusCorrelationPathTarget(document);
      });
    },
    [pathname, router, searchParams],
  );

  const handleStepHint = useCallback(
    (step: "expand" | "impact" | "fix") => {
      const lifecycleStep: InvestigationStep = step === "expand" ? "impact" : step;
      setCompletedSteps((current) => ({ ...current, path: true, [lifecycleStep]: true }));
      if (investigationStep === "path" && lifecycleStep === "impact") {
        setInvestigationStep("impact");
      }
    },
    [investigationStep, setInvestigationStep],
  );

  const focusLabel = useMemo(() => {
    const parts = [focus.nodeId, focus.cve, focus.packageName, focus.agentName].filter(Boolean);
    return parts.length > 0 ? parts.join(" · ") : null;
  }, [focus.agentName, focus.cve, focus.nodeId, focus.packageName]);
  const hasFocusContext = Boolean(
    focus.cve || focus.packageName || focus.agentName || focus.nodeId || focus.findingId,
  );

  useEffect(() => {
    // Pinning the already loaded snapshot into a shared path URL must not
    // unmount the workspace and discard its announcement or scroll target.
    const sharedScan = sharedSelectionScan.current;
    sharedSelectionScan.current = null;
    if (focus.scanId && sharedScan === focus.scanId) return;
    let cancelled = false;

    async function load() {
      setLoadingSnapshots(true);
      try {
        const [snapshotList, postureData, correlationList, currentScope] = await Promise.all([
          // windowDays: 0 keeps all retained snapshots visible (#4009).
          api.getGraphSnapshots(25, 0),
          api.getPosture().catch(() => null),
          api.listGraphCorrelations(20).catch(() => null),
          !focus.scanId || focus.scanId.startsWith("current-estate:") ? api.getInventorySummary() : Promise.resolve(null),
        ]);
        if (cancelled) return;
        setSnapshots(snapshotList);
        setCurrentEstateId(currentScope?.scan_id ?? "");
        setPosture(postureData);
        const latestCorrelation = latestCompletedCorrelation(correlationList?.items ?? []);
        setLatestCorrelationRun(latestCorrelation);
        const requestedScanId = focus.scanId;
        const initialScanId = selectInitialGraphSnapshot(
          snapshotList,
          requestedScanId,
          latestCorrelation,
          currentScope?.scan_id ?? focus.scanId,
        );
        setSelectedScanId(initialScanId);
        setApiError(null);
        setGraphLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setApiError(userFacingApiErrorMessage(error, "Failed to load graph snapshots"));
        setApiErrorKind(_classifyGraphErrorKind(error));
        setSnapshots([]);
        setLatestCorrelationRun(null);
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
      setFixFirstLoadError(null);
      return;
    }

    let cancelled = false;
    setMorePathsError(null);

    setGraphData(null);
    setFixFirstView(null);
    setGraphLoadError(null);
    setFixFirstLoadError(null);

    async function loadAttackPaths() {
      setLoadingGraph(true);
      setLoadingMorePaths(false);
      setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
      try {
        const graph = await api.getGraphAttackPaths({
          scanId: selectedScanId,
          offset: 0,
          limit: ATTACK_PATH_FETCH_PAGE,
        });
        if (cancelled) return;
        setGraphData(graph);
        setApiError(null);
        setGraphLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setGraphData(null);
        setGraphLoadError(userFacingApiErrorMessage(error, "Failed to load security graph"));
        setApiErrorKind(_classifyGraphErrorKind(error));
      } finally {
        if (!cancelled) setLoadingGraph(false);
      }
    }

    async function loadFixFirstEnrichment() {
      setLoadingFixFirst(true);
      try {
        const view = await api.getFixFirstGraphView({
          scanId: selectedScanId,
          cve: focus.cve || undefined,
          packageName: focus.packageName || undefined,
          agentName: focus.agentName || undefined,
          limit: FIX_FIRST_CARD_LIMIT,
        });
        if (cancelled) return;
        setFixFirstView(view);
        setFixFirstLoadError(null);
      } catch (error) {
        if (cancelled) return;
        setFixFirstView(null);
        setFixFirstLoadError(userFacingApiErrorMessage(error, "Fix guidance is unavailable"));
      } finally {
        if (!cancelled) setLoadingFixFirst(false);
      }
    }

    void loadAttackPaths();
    void loadFixFirstEnrichment();
    return () => {
      cancelled = true;
      pathPageRequest.current?.abort();
      pathPageRequest.current = null;
    };
  }, [focus.agentName, focus.cve, focus.findingId, focus.nodeId, focus.packageName, selectedScanId]);

  const selectedSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );
  // Stale/empty snapshots (0 persisted nodes) and unrelated older scans pile up
  // in a long-lived graph store and drown the real ones in the chip row.
  // Default to the current scan plus at most a couple of recent populated
  // snapshots; "show all" reveals every empty and older one on demand.
  const activeSnapshots = useMemo(
    () => snapshots.filter((snapshot) => snapshot.node_count > 0 || snapshot.scan_id === selectedScanId),
    [snapshots, selectedScanId],
  );
  const displayedSnapshots = useMemo(() => {
    if (showAllSnapshots) return snapshots;
    // Current scan first, then the most recent populated snapshots — never the
    // empty/unrelated ones up front.
    const current = activeSnapshots.filter((snapshot) => snapshot.scan_id === selectedScanId);
    const rest = activeSnapshots.filter((snapshot) => snapshot.scan_id !== selectedScanId);
    return [...current, ...rest].slice(0, DEFAULT_SNAPSHOT_CHIP_COUNT);
  }, [activeSnapshots, showAllSnapshots, selectedScanId, snapshots]);
  const hiddenSnapshotCount = Math.max(0, snapshots.length - displayedSnapshots.length);
  const estateMode = investigationEstateMode(selectedSnapshot?.node_count ?? 0, selectedScanId || undefined);

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

  const campaigns = useMemo<GraphAttackCampaign[]>(
    () => fixFirstView?.attack_campaigns ?? [],
    [fixFirstView?.attack_campaigns],
  );
  const selectedCampaign = useMemo(
    () => campaigns.find((campaign) => campaign.campaign_id === selectedCampaignId) ?? null,
    [campaigns, selectedCampaignId],
  );

  const allAttackPaths = useMemo(() => selectAttackPathQueue(
    graphData?.attack_paths,
    fixFirstCards.map((card) => card.attack_path),
    graphNodeById,
    hasFocusContext ? focus : {},
    selectedCampaign?.member_paths,
  ), [fixFirstCards, focus, graphData?.attack_paths, graphNodeById, hasFocusContext, selectedCampaign]);
  const relatedPackagePathsHref = useMemo(() => {
    if (!focus.findingId || !focus.nodeId || !focus.cve || allAttackPaths.length > 0) return null;
    const relatedFocus = { ...focus, findingId: "" };
    const hasRelatedPath = [...(graphData?.attack_paths ?? []), ...fixFirstCards.map(card => card.attack_path)]
      .some(path => matchesAttackPathFocus(path, graphNodeById, relatedFocus));
    if (!hasRelatedPath) return null;
    // A deliberate scope change, never an inferred association to this finding.
    const params = new URLSearchParams(searchParams.toString());
    params.delete("finding");
    params.set("related_finding", focus.findingId);
    return `${pathname}?${params.toString()}`;
  }, [allAttackPaths.length, fixFirstCards, focus, graphData?.attack_paths, graphNodeById, pathname, searchParams]);
  const presentationAttackPaths = useMemo(
    () => dedupeAttackPathsForPresentation(allAttackPaths, graphNodeById),
    [allAttackPaths, graphNodeById],
  );
  const attackPaths = useMemo(
    () => filterInvestigationQuestion(filterAttackPathsForInvestigation(presentationAttackPaths, graphNodeById, investigationFilters), graphNodeById, requestedQuestion),
    [graphNodeById, investigationFilters, presentationAttackPaths, requestedQuestion],
  );
  const pathEnvironments = useMemo(
    () => collectPathEnvironments(allAttackPaths, graphNodeById),
    [allAttackPaths, graphNodeById],
  );
  const visibleAttackPaths = useMemo(
    () => attackPaths.slice(0, Math.min(visibleAttackPathCount, attackPaths.length)),
    [attackPaths, visibleAttackPathCount],
  );
  const filtersNarrowQueue =
    Boolean(selectedCampaign?.member_paths?.length) ||
    Object.values(investigationFilters).some((value) => Boolean(value));
  const pathHasMoreFromApi = Boolean(graphData?.pagination?.has_more);
  const hiddenLoadedAttackPathCount = Math.max(0, attackPaths.length - visibleAttackPaths.length);

  const loadMoreAttackPaths = useCallback(async () => {
    if (hiddenLoadedAttackPathCount > 0) {
      setVisibleAttackPathCount((current) =>
        Math.min(attackPaths.length, current + ATTACK_PATH_QUEUE_PAGE_SIZE),
      );
      return;
    }
    if (!pathHasMoreFromApi || !selectedScanId || !graphData || pathPageRequest.current) return;
    const offset = graphData.pagination?.offset ?? 0;
    const limit = graphData.pagination?.limit ?? ATTACK_PATH_FETCH_PAGE;
    // Server has_more uses offset+limit < total; advance by the requested page size.
    const nextOffset = offset + limit;
    const controller = new AbortController();
    pathPageRequest.current = controller;
    setLoadingMorePaths(true);
    setMorePathsError(null);
    try {
      const nextPage = await api.getGraphAttackPaths({
        scanId: selectedScanId,
        offset: nextOffset,
        snapshotGeneration: graphData.snapshot_generation,
        limit: ATTACK_PATH_FETCH_PAGE,
      }, { signal: controller.signal });
      if (controller.signal.aborted) return;
      // Validate before scheduling a state update; preserve loaded evidence on mismatch.
      const merged = mergeAttackPathGraphPages(graphData, nextPage);
      setGraphData(merged);
      setVisibleAttackPathCount((current) => current + ATTACK_PATH_QUEUE_PAGE_SIZE);
    } catch (error) {
      if (!controller.signal.aborted) setMorePathsError(userFacingApiErrorMessage(error, "Failed to load more attack paths"));
    } finally {
      if (pathPageRequest.current === controller) {
        pathPageRequest.current = null;
        setLoadingMorePaths(false);
      }
    }
  }, [
    attackPaths.length,
    graphData,
    hiddenLoadedAttackPathCount,
    pathHasMoreFromApi,
    selectedScanId,
  ]);

  const queueContinuation = <GraphPathQueueContinuation graph={graphData} matches={attackPaths.length}
    pageSize={ATTACK_PATH_QUEUE_PAGE_SIZE} hiddenMatches={hiddenLoadedAttackPathCount} narrowed={filtersNarrowQueue || hasFocusContext}
    loading={loadingMorePaths} error={morePathsError} onMore={() => void loadMoreAttackPaths()} />;

  const rankedRows = useMemo<RankedPathRow[]>(
    () =>
      rankedAttackPathRows(visibleAttackPaths, fixFirstCards).flatMap(({ path, card, rank, key }) => {
        const pathNodes = toAttackCardNodes(path, graphNodeById);
        if (pathNodes.length === 0) return [];
        const row: RankedPathRow = {
          key,
          selectionKey: attackPathKey(path),
          rank,
          title: descriptiveAttackPathTitle(pathNodes),
          cve: path.vuln_ids[0] ?? null,
          riskScore: path.composite_risk,
          scoreLabel: card ? "Evidence priority" : "Queue score",
          nodeCount: path.hops.length,
          agents: labelsForAttackPathType(path, graphNodeById, "agent").length,
          roleChain: attackPathRoleChain(path, graphNodeById),
        };
        if (card?.rank_meta?.tool_capabilities?.length) {
          row.capabilityTags = card.rank_meta.tool_capabilities;
        }
        if (card?.rank_meta?.environments?.length) {
          row.environmentTags = card.rank_meta.environments;
        }
        return [row];
      }),
    [fixFirstCards, graphNodeById, visibleAttackPaths],
  );
  const pathQueueCounts = useMemo(
    () => graphPathQueueCounts(graphData, rankedRows.length),
    [graphData, rankedRows.length],
  );

  const selectedAttackPath = useMemo(
    () =>
      selectedAttackPathKey
        ? attackPaths.find((path) => attackPathKey(path) === selectedAttackPathKey) ?? null
        : attackPaths[0] ?? null,
    [attackPaths, selectedAttackPathKey],
  );
  useEffect(() => {
    if (requestedPathMode !== "top" || requestedPathScanId !== selectedScanId) {
      focusedTopPathRef.current = null;
      return;
    }
    const topPath = attackPaths[0];
    if (!topPath) return;
    const topPathKey = attackPathKey(topPath);
    const focusKey = `${selectedScanId}:${topPathKey}`;
    if (focusedTopPathRef.current === focusKey) return;
    if (selectedAttackPathKey !== topPathKey) {
      setSelectedAttackPathKey(topPathKey);
      return;
    }
    focusedTopPathRef.current = focusKey;
    const frame = window.requestAnimationFrame(() => {
      focusCorrelationPathTarget(document);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [attackPaths, requestedPathMode, requestedPathScanId, selectedAttackPathKey, selectedScanId]);
  const investigationRoot = useMemo(
    () =>
      selectedAttackPath
        ? investigationRootForAttackPath(selectedAttackPath, graphNodeById, focus)
        : null,
    [focus, graphNodeById, selectedAttackPath],
  );
  const fullGraphHref = useMemo(() => {
    if (investigationRoot) {
      return withFindingContext(buildGraphInvestigationHref({
        scanId: selectedScanId || undefined,
        agentName: focus.agentName || undefined,
        rootId: investigationRoot.id,
        rootLabel: investigationRoot.label,
      }), searchParams);
    }

    const params = new URLSearchParams();
    if (selectedScanId) params.set("scan", selectedScanId);
    if (focus.agentName) params.set("agent", focus.agentName);
    const query = params.toString();
    if (query) params.set("lens", "lineage");
    return withFindingContext(params.size > 0 ? `/security-graph?${params.toString()}` : "/security-graph?lens=lineage", searchParams);
  }, [focus.agentName, investigationRoot, selectedScanId, searchParams]);
  const resetFocusHref = useMemo(
    () => buildSecurityGraphHref({ scanId: selectedScanId || undefined }),
    [selectedScanId],
  );

  const selectedFixFirstCard = useMemo(
    () => (selectedAttackPath ? cardByPathKey.get(attackPathKey(selectedAttackPath)) ?? null : null),
    [cardByPathKey, selectedAttackPath],
  );
  const selectedPathGraph = useSelectedPathGraph({
    graph: graphData as UnifiedGraphData | null,
    path: selectedAttackPath,
    scanId: selectedScanId,
    enabled: pathView === "graph",
  });
  const selectedExposurePath = useMemo(
    () => {
      if (!selectedAttackPath) return null;
      const exposurePath = selectedFixFirstCard?.exposure_path ??
        toExposurePathFromAttackPath(selectedAttackPath, graphNodeById, {
          scanId: selectedScanId || undefined,
          rank: selectedFixFirstCard?.rank,
        });
      return withCanonicalExposurePresentation(exposurePath, graphNodeById);
    },
    [graphNodeById, selectedAttackPath, selectedFixFirstCard, selectedScanId],
  );

  const selectedPathActions = useMemo(() => {
    if (!selectedAttackPath) return [];
    const actions = selectedFixFirstCard?.next_actions
      ?? recommendedAttackPathActions(selectedAttackPath, graphNodeById, { scanId: selectedScanId || undefined });
    const finding = selectedFixFirstCard?.affected.finding_labels?.[0] ?? selectedAttackPath.vuln_ids[0];
    const packageNode = selectedAttackPath.hops
      .map((hop) => graphNodeById.get(hop))
      .find((node) => node?.entity_type === "package");
    return actions.map((action) => action.href.split("?", 1)[0] === "/remediation"
      ? { ...action, href: buildCorrelationRemediationHref(action.href, selectedScanId, finding, packageNode?.label) }
      : action);
  }, [graphNodeById, selectedAttackPath, selectedFixFirstCard, selectedScanId]);
  const correlationOutcome = useMemo<GraphCorrelationOutcome | null>(() => {
    if (
      !selectedAttackPath ||
      !correlationOutcomeMatchesOutput(selectedScanId, graphData?.scan_id, fixFirstView?.scan_id)
    ) return null;
    const labels = selectedFixFirstCard?.sequence_labels ?? selectedAttackPath.hops.map((hop) => graphNodeById.get(hop)?.label ?? hop);
    const packageNode = selectedAttackPath.hops
      .map((hop) => graphNodeById.get(hop))
      .find((node) => node?.entity_type === "package");
    const finding = selectedFixFirstCard?.affected.finding_labels?.[0] ?? selectedAttackPath.vuln_ids[0];
    const reasons = selectedFixFirstCard?.risk_reasons ?? [];
    const hopReceipts = selectedAttackPath.hop_evidence ?? [];
    const directedHopCount = completeDirectedHopCount(selectedAttackPath);
    if (directedHopCount === null) return null;
    const action = selectedFixFirstCard?.next_actions?.[0] ?? selectedPathActions[0];
    const actionIsRemediation = action?.href.split("?", 1)[0] === "/remediation";
    return {
      scanId: selectedScanId,
      summary: finding && packageNode?.label
        ? `${finding} in ${packageNode.label} appears on this correlated path. Inspect the evidence and conditions at each hop.`
        : "Review the recorded relationships and per-hop evidence for this selected path.",
      source: labels[0] ?? selectedAttackPath.source,
      target: labels.at(-1) ?? selectedAttackPath.target,
      finding,
      packageName: packageNode?.label,
      risk: selectedAttackPath.composite_risk,
      hops: directedHopCount,
      runtimeObserved: reasons.some((reason) => reason.kind === "runtime_observed") || hopReceipts.some((receipt) => receipt.runtime_observed_state === "observed"),
      runtimeBlocked: reasons.some((reason) => reason.kind === "runtime_blocked") || hopReceipts.some((receipt) => receipt.runtime_observed_state === "blocked"),
      action: action ? {
        title: actionIsRemediation
          ? `Open ${packageNode?.label ?? finding ?? "finding"} remediation`
          : action.title,
        href: actionIsRemediation
          ? buildCorrelationRemediationHref(action.href, selectedScanId, finding, packageNode?.label)
          : action.href,
      } : undefined,
    };
  }, [fixFirstView?.scan_id, graphData?.scan_id, graphNodeById, selectedAttackPath, selectedFixFirstCard, selectedPathActions, selectedScanId]);

  const showCorrelationOverview = searchParams.get("correlation") === "1"
    && latestCorrelationRun?.output_scan_id === selectedScanId
    && Boolean(correlationOutcome)
    && requestedPathMode !== "top"
    && (!hasFocusContext || correlationCaptureMode);

  const emptyGraphState = useMemo(() => {
    const analysis = graphData?.stats.analysis_status?.attack_path_fusion;
    const executionCopy = graphAnalysisStatusCopy(analysis);
    if (analysis?.status === "skipped" || analysis?.status === "failed") {
      return {
        title: executionCopy.label,
        detail: executionCopy.detail,
        suggestions: [
          "Run a fresh scan after reviewing the recorded analysis limit or failure.",
          "Open the full graph to inspect the inventory and findings that did persist.",
          "Do not treat this snapshot as proof that no attack paths exist.",
        ],
      };
    }
    if (analysis?.status === "limited") {
      return {
        title: "No paths in the retained partial result",
        detail: executionCopy.detail,
        suggestions: [
          "Review the recorded execution limits before relying on this result.",
          "Open the full graph to inspect topology outside the retained path set.",
          "Run a narrower or higher-capacity scan for complete path coverage.",
        ],
      };
    }
    if (hasFocusContext) {
      return {
        title: "No attack paths matched the current focus",
        detail: `No recorded path matched ${focusLabel ?? "the current filters"} in this snapshot. This does not establish whether the vulnerability is exploitable or whether another path exists.`,
        suggestions: [
          "Clear focus to review every persisted path in this snapshot.",
          "Open the full graph to inspect broader topology.",
          "Review the finding and its missing evidence before choosing a remediation.",
        ],
      };
    }

    return {
      title: "No precomputed attack paths are available for this snapshot",
      detail:
        "This snapshot has no recorded attack paths. Vulnerability presence, structural reachability, and exploitation are separate assessments.",
      suggestions: [
        "Run a fresh scan to refresh the persisted graph snapshot.",
        "Open the full graph to inspect inventory and findings that did persist.",
        "Check the vulnerabilities page if you need fix context before the next scan completes.",
      ],
    };
  }, [focusLabel, graphData?.stats.analysis_status, hasFocusContext]);

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
  }, [focus.agentName, focus.cve, focus.findingId, focus.nodeId, focus.packageName, selectedScanId]);

  useEffect(() => {
    setPinnedNodeId(focus.nodeId || null);
  }, [focus.nodeId]);

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
    if (requestedSelectedPath && attackPaths.some(path => attackPathKey(path) === requestedSelectedPath)) {
      setSelectedAttackPathKey(requestedSelectedPath);
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
  }, [attackPaths, focus, focusApplied, graphNodeById, hasFocusContext, requestedSelectedPath, selectedAttackPathKey]);

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
    <div className={captureMode ? "space-y-2" : "space-y-4"}>
      <header className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Investigation</h1>
        {captureMode ? undefined : (
          <div className="hidden flex-wrap items-center gap-2 sm:flex">
            <InvestigationExportButton path={selectedExposurePath} scanId={selectedScanId} />
            <Link
              href={fullGraphHref}
              className="sg-action"
            >
              Open lineage lens
              <GitBranch className="h-4 w-4" />
            </Link>
            <Link
              href="/remediation"
              className="sg-action"
            >
              Remediation
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          )}
      </header>

      <div role="group" aria-label="Investigation starting questions" className="flex flex-wrap gap-2">
        <button type="button" className="sg-action" aria-pressed={!requestedQuestion} onClick={() => router.replace(investigationHref(pathname, searchParams.toString(), { question: null, selected_path: null }), { scroll: false })}>All ranked paths</button>
        <button type="button" className="sg-action" aria-pressed={requestedQuestion === "credentials"} onClick={() => router.replace(investigationHref(pathname, searchParams.toString(), { question: "credentials", selected_path: null }), { scroll: false })}>Credential exposure</button>
        <button type="button" className="sg-action" aria-pressed={requestedQuestion === "critical"} onClick={() => router.replace(investigationHref(pathname, searchParams.toString(), { question: "critical", selected_path: null }), { scroll: false })}>Critical dependencies</button>
        <button type="button" className="sg-action" onClick={() => setInvestigationStep("impact")}>Potential blast radius</button>
      </div>
      {requestedQuestion && <p role="status" className="text-xs text-ink-secondary">Question filters apply to the loaded ranked paths. Load another page to widen this search; an empty page does not establish complete coverage.</p>}
      <GraphSnapshotReceipt snapshot={selectedSnapshot} scanId={selectedScanId} />
      <AdvisoryFreshness />
      {requestedSelectedPath && graphData && !allAttackPaths.some(path => attackPathKey(path) === requestedSelectedPath) && <p role="status" className="graph-callout-amber">The shared path is not in this loaded queue page. Load more paths or inspect its retained evidence scope; the currently shown path is a different result.</p>}

      <div className="hidden sm:block"><GraphLensSwitcher variant="compact" /></div>
      <details className="rounded-lg border border-outline bg-surface p-3 sm:hidden">
        <summary className="cursor-pointer text-sm">Graph lenses · Attack Paths</summary>
        <div className="mt-2"><GraphLensSwitcher variant="compact" /></div>
      </details>

      {searchParams.get("related_finding") ? (
        <p role="note" aria-label="Finding association" className="graph-callout-sky">
          Related package and advisory paths. This scope does not establish a link to the selected finding record.
        </p>
      ) : null}

      {selectedScenarioId ? (
        <div className="graph-callout-sky">
          Attack Paths remains observed-only. Open Estate, Cloud, Repository,
          Identity, or Lineage to compare this scenario's modeled state.
        </div>
      ) : null}

      {/* The loop is a control, not content: it rides in the toolbar row rather
          than owning a full-width band with an explanatory paragraph. The page
          stacked eight such bands above the graph, pushing the ranked paths —
          the reason the page exists — below the fold. */}
      {!captureMode ? (
        <div className="flex flex-wrap items-center justify-between gap-3 [&_nav]:relative [&_nav]:max-w-full [&_nav]:overflow-x-auto [&_ol]:flex-nowrap [&_li]:shrink-0">
          <InvestigationStepStrip
            step={investigationStep}
            onStepChange={setInvestigationStep}
            completed={completedSteps}
            stepHrefs={{
              owner: "/remediation#campaigns",
              fix: "/remediation#campaigns",
              verify: "/remediation#verification",
            }}
          />
          {pinnedNodeId ? (
            <span className="text-xs text-[color:var(--text-tertiary)]">
              Pinned {pinnedNodeId.slice(0, 12)}…
            </span>
          ) : null}
        </div>
      ) : null}

      {showCorrelationOverview ? (
        <GraphCorrelationWorkflow snapshots={snapshots} initialRun={latestCorrelationRun} outcome={correlationOutcome} onOpenSnapshot={openCorrelationPath} />
      ) : null}

      {loadingSnapshots || loadingGraph ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <GraphPanelSkeleton
            title="Loading security graph"
            detail={loadingGraphMessage}
          />
        </section>
      ) : graphLoadError ? (
        <section className="rounded-3xl border border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] p-4">
          <GraphEmptyState
            title={graphErrorState.title}
            detail={graphErrorState.detail}
            suggestions={graphErrorState.suggestions}
            command="agent-bom serve --api"
          />
          <div className="mt-4 flex flex-wrap gap-3 border-t border-red-900/40 pt-4">
            <Link
              href={fullGraphHref}
              className="sg-danger-chip"
            >
              Retry in full graph
              <GitBranch className="h-3.5 w-3.5" />
            </Link>
            {hasFocusContext && (
              <Link
                href={resetFocusHref}
                className="sg-danger-chip"
              >
                Clear focus
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </section>
      ) : allAttackPaths.length === 0 ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <div className="mb-4">
            <GraphAnalysisStatusBanner status={graphData?.stats.analysis_status?.attack_path_fusion} />
          </div>
          <GraphEmptyState
            title={pathHasMoreFromApi ? "No matching paths in loaded pages" : relatedPackagePathsHref ? "No path is linked to this finding record" : emptyGraphState.title}
            detail={pathHasMoreFromApi ? "Continue through the queue to check later pages against this focus. Unloaded paths remain unknown." : relatedPackagePathsHref
              ? "Paths match this package and advisory in the selected snapshot, but their evidence does not link the selected finding record. Open that broader context explicitly."
              : emptyGraphState.detail}
            suggestions={emptyGraphState.suggestions}
            command="agent-bom scan -p . -f graph"
          />
          {queueContinuation}
          <div className="mt-4 flex flex-wrap gap-3 border-t border-[color:var(--border-subtle)] pt-4">
            {focus.nodeId ? (
              <Link href={buildFindingAssetHref({ findingScanId: searchParams.get("finding_scan") || focus.scanId, nodeId: focus.nodeId, findingId: focus.findingId, scanId: selectedScanId })} className="sg-action">
                Inspect linked asset
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            ) : null}
            {relatedPackagePathsHref ? (
              <Link href={relatedPackagePathsHref} className="sg-action">
                Show related package and advisory paths
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            ) : null}
            <Link
              href={fullGraphHref}
              className="sg-filter-chip"
            >
              Open full graph
              <GitBranch className="h-3.5 w-3.5" />
            </Link>
            <Link
              href={buildFindingsHref({ scanId: selectedScanId || undefined })}
              className="sg-filter-chip"
            >
              Review findings
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            {hasFocusContext && (
              <Link
                href={resetFocusHref}
                className="sg-filter-chip"
              >
                Clear focus
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </section>
      ) : attackPaths.length === 0 ? (
        <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 space-y-4">
          <InvestigationFilterDrawer>
            <InvestigationFilterChips
              filters={investigationFilters}
              onChange={setInvestigationFilters}
              environments={pathEnvironments}
            />
            <GraphPresetControls
              filters={investigationFilters}
              onApply={setInvestigationFilters}
            />
          </InvestigationFilterDrawer>
          <GraphEmptyState
            title={pathHasMoreFromApi ? "No matching paths in loaded pages" : "No paths match the current investigation filters"}
            detail={pathHasMoreFromApi ? "Continue through the queue with these filters. Matches outside loaded pages are unknown." : "No loaded paths match. Clear severity, layer, evidence, or environment chips to widen the queue."}
            suggestions={[
              "Clear one filter chip at a time to widen the queue.",
              "Load a saved preset that matches this estate.",
              "Open the full graph for topology outside the filtered set.",
            ]}
          />
          <button
            type="button"
            onClick={() => setInvestigationFilters(EMPTY_INVESTIGATION_FILTERS)}
            className="rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          >
            Clear investigation filters
          </button>
          {queueContinuation}
        </section>
      ) : showCorrelationOverview ? null : (
        <InvestigationPathWorkspace
          rows={rankedRows}
          selectedKey={selectedAttackPath ? attackPathKey(selectedAttackPath) : null}
          onSelect={(key) => {
            sharedSelectionScan.current = focus.scanId === selectedScanId ? null : selectedScanId;
            setSelectedAttackPathKey(key);
            // This path is already loaded. Share its selection without a route
            // transition that can replace the workspace after it scrolls.
            window.history.replaceState(null, "", investigationHref(pathname, searchParams.toString(), { selected_path: key, path_view: "path", scan: selectedScanId }));
            setCompletedSteps((current) => ({ ...current, path: true }));
            setPathView("path");
          }}
          title={`${pathQueueCounts.renderedRows} shown · ${pathQueueCounts.returnedRows} loaded paths`}
          subtitle={`${pathQueueCounts.queueRows} from the path queue. ${pathQueueCounts.snapshotTotal} snapshot paths${pathQueueCounts.truncated ? "; more queue paths available" : ""}. Select a path to inspect.${
            loadingFixFirst
              ? " Ranked paths are ready; fix guidance is still loading."
              : fixFirstLoadError
                ? " Ranked paths are ready; fix guidance is temporarily unavailable."
                : graphData?.count_metadata?.source === "persisted_graph_paths"
                  ? " Ranked from persisted scan paths."
                  : graphData?.count_metadata?.source === "derived_graph_paths"
                    ? " Ranked from bounded graph traversal."
                    : ""
          } ${pathQueueCounts.materializedPaths} materialized · ${pathQueueCounts.derivedPaths} derived.${
            selectedCampaign
              ? ` Filtered to crown-jewel cluster “${selectedCampaign.crown_jewel_label || selectedCampaign.crown_jewel}”.`
              : ""
          }`}
          filters={
            <>
              <InvestigationFilterChips
                filters={investigationFilters}
                onChange={setInvestigationFilters}
                environments={pathEnvironments}
              />
              <GraphPresetControls
                filters={investigationFilters}
                onApply={setInvestigationFilters}
              />
              {focusLabel ? (
                <p className="text-xs text-emerald-700 dark:text-emerald-300">Focused: {focusLabel}</p>
              ) : null}
              {focus.traceId ? (
                <p className="text-xs text-sky-700 dark:text-sky-300">
                  Runtime trace pin: <span className="font-mono">{focus.traceId}</span>
                </p>
              ) : null}
            </>
          }
          queueFooter={queueContinuation}
          detail={
            selectedExposurePath ? (
              <ExposurePathCommandCenter
                title={selectedFixFirstCard?.title}
                path={selectedExposurePath}
                actions={selectedPathActions}
                scanId={selectedScanId || undefined}
                view={pathView}
                onViewChange={sharePathView}
                techniquesSlot={
                  selectedAttackPath ? (
                    <AttackPathCorrelationProof
                      path={selectedAttackPath}
                      riskReasons={selectedFixFirstCard?.risk_reasons}
                      nodes={selectedAttackPath.hops.map((id) => graphNodeById.get(id)).filter((node): node is UnifiedNode => Boolean(node))}
                    />
                  ) : null
                }
                detailsSlot={selectedAttackPath ? <AttackPathTechniqueChain path={selectedAttackPath} /> : null}
                graphSlot={
                  selectedAttackPath ? (
                    <div className="space-y-2">
                      {selectedPathGraph.message ? (
                        <div role="status" className="rounded-lg border border-border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">
                          {selectedPathGraph.message}
                          {selectedPathGraph.canRetry ? (
                            <button type="button" className="ml-2 font-medium text-foreground underline" onClick={selectedPathGraph.retry}>Retry graph</button>
                          ) : null}
                        </div>
                      ) : null}
                      {selectedPathGraph.loading ? <GraphPanelSkeleton title="Loading selected path" detail="Reading its nodes and relationships from this snapshot…" /> : null}
                      {selectedPathGraph.graph ? (
                        <SecurityGraphInvestigation
                          embedded
                          graph={selectedPathGraph.graph}
                          attackPath={selectedAttackPath}
                          focusMode={investigationFocusMode}
                          onFocusModeChange={setInvestigationFocusMode}
                          fullGraphHref={fullGraphHref}
                          loading={loadingGraph}
                          scanId={selectedScanId || undefined}
                          onPinnedNodeChange={setPinnedNodeId}
                          onStepHint={handleStepHint}
                        />
                      ) : null}
                    </div>
                  ) : null
                }
              />
            ) : (
              <GraphPanelSkeleton title="Selecting path" detail="Preparing observed graph evidence…" />
            )
          }
          sideRail={
            <GraphCampaignPanel
              campaigns={campaigns}
              selectedCampaignId={selectedCampaignId}
              onSelect={(campaign) => {
                setSelectedCampaignId((current) =>
                  current === campaign.campaign_id ? null : campaign.campaign_id,
                );
                setVisibleAttackPathCount(ATTACK_PATH_QUEUE_PAGE_SIZE);
              }}
            />
          }
        />
      )}

      <InvestigationTools
        scope={
        <div className="space-y-4">
          {!captureMode ? <div className="flex flex-wrap gap-2 sm:hidden">
            <InvestigationExportButton path={selectedExposurePath} scanId={selectedScanId} />
            <Link
              href={fullGraphHref}
              className="sg-action"
            >
              Open lineage lens
              <GitBranch className="h-4 w-4" />
            </Link>
            <Link
              href="/remediation"
              className="sg-action"
            >
              Remediation
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div> : null}
          {!showCorrelationOverview && (!captureMode || correlationCaptureMode) && snapshots.length > 0 ? (
            <GraphCorrelationWorkflow
              snapshots={snapshots}
              initialRun={latestCorrelationRun}
              outcome={correlationOutcome}
              onOpenSnapshot={openCorrelationPath}
            />
          ) : null}
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                Current scan evidence
              </p>
              <p className="mt-1 font-mono text-sm text-[color:var(--foreground)]">
                {selectedScanId.startsWith("current-estate:") ? "Current tenant estate" : selectedSnapshot ? selectedSnapshot.scan_id : "No scan selected"}
              </p>
              {selectedSnapshot ? <p className="mt-1 text-xs text-ink-tertiary">{formatDate(selectedSnapshot.created_at)} · {selectedSnapshot.node_count} nodes · {selectedSnapshot.edge_count} edges</p> : null}
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              {posture ? <QuickStat label="Posture" value={`${posture.grade} ${posture.score}`} tone="red" /> : null}
              {fixFirstView ? (
                <>
                  <QuickStat label="Matched paths" value={String(fixFirstView.summary.matched_paths)} tone="blue" />
                  <QuickStat label="Covered findings" value={String(fixFirstView.summary.covered_findings)} tone="amber" />
                  <QuickStat label="Highest risk" value={fixFirstView.summary.highest_risk.toFixed(1)} tone="red" />
                </>
              ) : null}
            </div>
          </div>

          {loadingSnapshots ? (
            <span className="inline-flex items-center gap-2 text-xs text-sky-400">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Loading scan evidence
            </span>
          ) : snapshots.length > 0 ? (
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                Manage snapshots
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                {currentEstateId && <button type="button" className="graph-chip-neutral" aria-pressed={selectedScanId === currentEstateId} onClick={() => selectSnapshot(currentEstateId)}>Current tenant estate</button>}
                {displayedSnapshots.map((snapshot) => {
                  const selected = snapshot.scan_id === selectedScanId;
                  return (
                    <button
                      key={snapshot.scan_id}
                      type="button"
                      onClick={() => selectSnapshot(snapshot.scan_id)}
                      className={`rounded-xl border px-3 py-2 text-left text-xs transition ${
                        selected
                          ? "border-emerald-700 bg-emerald-500/10 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-200"
                          : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                      }`}
                    >
                      <span className="block font-mono">{snapshot.scan_id.slice(0, 8)}…</span>
                      <span className="mt-1 block text-[11px] opacity-80">{snapshot.node_count} nodes</span>
                    </button>
                  );
                })}
              </div>
              {hiddenSnapshotCount > 0 || showAllSnapshots ? (
                <button
                  type="button"
                  onClick={() => setShowAllSnapshots((current) => !current)}
                  className="mt-3 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                >
                  {showAllSnapshots
                    ? "Show active snapshots"
                    : `Show all ${snapshots.length} snapshots (${hiddenSnapshotCount} empty or older)`}
                </button>
              ) : null}
            </div>
          ) : (
            <GraphEmptyState
              title="No persisted graph snapshots yet"
              detail="Run a scan first so Investigation can rank paths from persisted graph evidence."
              suggestions={[
                "Run a local scan with graph output enabled.",
                "Confirm the graph persistence backend is enabled.",
              ]}
              command="agent-bom scan -p . -f graph"
              actions={[{ label: "Run a scan", href: "/scan" }]}
            />
          )}

          {selectedSnapshot && estateMode.large ? (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[color:var(--border-subtle)] pt-3 text-xs text-[color:var(--text-secondary)]">
              <span>{estateMode.summary}. Use a focused lens before opening the full topology.</span>
              <div className="flex flex-wrap gap-3">
                <Link href={estateMode.clusteredHref} className="font-medium text-[color:var(--accent-mint)] hover:underline">
                  Explore clusters
                </Link>
                <Link href={estateMode.rawHref} className="font-medium text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:underline">
                  Open raw topology
                </Link>
              </div>
            </div>
          ) : null}
        </div>

        }
        deployment={!captureMode ? <DeployGatePanel scanId={selectedScanId || undefined} /> : undefined}
        exposure={<ExposurePathLens scanId={selectedScanId || undefined} />}
      />
    </div>
  );
}

function SecurityGraphPageContent() {
  const { session } = useAuthState();
  const searchParams = useSearchParams();
  return resolveSecurityGraphSurface(searchParams) === "attack-path"
    ? <><FindingInvestigationContext /><AttackPathInvestigationContent key={JSON.stringify(session)} /></>
    : <GraphSurface />;
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
    red: tonedChipClass("danger"),
    amber: tonedChipClass("warn"),
    blue: tonedChipClass("low"),
  };
  return (
    <div className={`rounded-2xl border px-4 py-3 ${tones[tone]}`}>
      <div className="text-[11px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1 font-mono text-xl">{value}</div>
    </div>
  );
}
