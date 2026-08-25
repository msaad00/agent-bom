"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  ArrowRight,
  GitBranch,
  Loader2,
  Rocket,
  Route,
} from "lucide-react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError, userFacingApiErrorMessage } from "@/lib/api-errors";
import { resolveSecurityGraphSurface } from "@/lib/security-graph-route";

function _classifyGraphErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}
import { PageLaneHeader } from "@/components/page-lane";
import type { RankedPathRow } from "@/components/ranked-path-list";
import { AttackPathTechniqueChain } from "@/components/attack-path-technique-chain";
import { ExposurePathCommandCenter, type ExposurePathView } from "@/components/exposure-path-command-center";
import {
  InvestigationFilterDrawer,
  InvestigationPathWorkspace,
} from "@/components/investigation-path-workspace";
import { GraphEvidenceExportButton } from "@/components/graph-chrome";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { DeployGatePanel } from "@/components/deploy-gate-panel";
import { ExposurePathLens } from "@/components/exposure-path-lens";
import { Collapsible } from "@/components/collapsible";
import { GraphEmptyState, GraphPanelSkeleton } from "@/components/graph-state-panels";
import { GraphAnalysisStatusBanner, graphAnalysisStatusCopy } from "@/components/graph-analysis-status";
import { GraphCampaignPanel } from "@/components/graph-campaign-panel";
import { GraphCompletenessBanner } from "@/components/graph-completeness-banner";
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
} from "@/lib/attack-paths";
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";
import { GraphSurface } from "@/app/graph/graph-surface";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import { tonedChipClass } from "@/lib/toned-chip";
import { investigationEstateMode } from "@/lib/investigation-estate-mode";
import { useCaptureMode } from "@/lib/use-capture-mode";
import {
  collectPathEnvironments,
  filterAttackPathsForInvestigation,
} from "@/lib/investigation-path-filters";

const EMPTY_INVESTIGATION_FILTERS: InvestigationPresetFilters = {
  severity: null,
  layer: null,
  evidenceTier: null,
  environment: null,
};

/** First/next fetch size for GET /v1/graph/attack-paths (API offset paging). */
const ATTACK_PATH_FETCH_PAGE = 25;
const ATTACK_PATH_QUEUE_PAGE_SIZE = 12;
const FIX_FIRST_CARD_LIMIT = 12;
const DEFAULT_SNAPSHOT_CHIP_COUNT = 3;

function AttackPathInvestigationContent() {
  const captureMode = useCaptureMode();
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
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
  const [investigationFocusMode, setInvestigationFocusMode] = useState(true);
  const [pathView, setPathView] = useState<ExposurePathView>("path");
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
    let cancelled = false;

    async function load() {
      setLoadingSnapshots(true);
      try {
        const [snapshotList, postureData] = await Promise.all([
          // windowDays: 0 keeps all retained snapshots visible (#4009).
          api.getGraphSnapshots(25, 0),
          api.getPosture().catch(() => null),
        ]);
        if (cancelled) return;
        setSnapshots(snapshotList);
        setPosture(postureData);
        const requestedScanId = focus.scanId;
        const initialScanId =
          requestedScanId && snapshotList.some((snapshot) => snapshot.scan_id === requestedScanId)
            ? requestedScanId
            : requestedScanId
              ? ""
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
      setFixFirstLoadError(null);
      return;
    }

    let cancelled = false;

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
    };
  }, [focus.agentName, focus.cve, focus.findingId, focus.nodeId, focus.packageName, selectedScanId]);

  const selectedSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );
  const requestedSnapshotMissing =
    !loadingSnapshots &&
    Boolean(focus.scanId) &&
    !snapshots.some((snapshot) => snapshot.scan_id === focus.scanId);
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

  // The attack-paths API remains the authoritative paginated occurrence queue.
  // Fix-first cards supply the evidence-calibrated presentation order for the
  // initial shortlist; append every non-enriched occurrence so this never caps
  // the global queue at FIX_FIRST_CARD_LIMIT.
  const allAttackPaths = useMemo(() => {
    const fromApi = [...(graphData?.attack_paths ?? [])].sort(
      (left, right) => right.composite_risk - left.composite_risk,
    );
    const fromFixFirst = fixFirstCards.map((card) => card.attack_path);
    const focusedApiPaths = fromApi.filter((path) => matchesAttackPathFocus(path, graphNodeById, focus));
    const focusedEnrichedPaths = fromFixFirst.filter((path) => matchesAttackPathFocus(path, graphNodeById, focus));
    const enriched = hasFocusContext ? focusedEnrichedPaths : fromFixFirst;
    const occurrences = hasFocusContext ? focusedApiPaths : fromApi;
    const enrichedKeys = new Set(enriched.map(attackPathKey));
    const base = [...enriched, ...occurrences.filter((path) => !enrichedKeys.has(attackPathKey(path)))];
    if (!selectedCampaign?.member_paths?.length) return base;
    const members = new Set(selectedCampaign.member_paths);
    return base.filter((path) => members.has(`${path.source}->${path.target}`));
  }, [fixFirstCards, focus, graphData?.attack_paths, graphNodeById, hasFocusContext, selectedCampaign]);
  const presentationAttackPaths = useMemo(
    () => dedupeAttackPathsForPresentation(allAttackPaths, graphNodeById),
    [allAttackPaths, graphNodeById],
  );
  const attackPaths = useMemo(
    () => filterAttackPathsForInvestigation(presentationAttackPaths, graphNodeById, investigationFilters),
    [graphNodeById, investigationFilters, presentationAttackPaths],
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
  const pathHasMoreFromApi = Boolean(graphData?.pagination?.has_more) && !filtersNarrowQueue;
  const hiddenLoadedAttackPathCount = Math.max(0, attackPaths.length - visibleAttackPaths.length);
  const hiddenAttackPathCount =
    hiddenLoadedAttackPathCount +
    (pathHasMoreFromApi
      ? Math.max(
          0,
          (graphData?.pagination?.total ?? attackPaths.length) - attackPaths.length,
        )
      : 0);

  const loadMoreAttackPaths = useCallback(async () => {
    if (hiddenLoadedAttackPathCount > 0) {
      setVisibleAttackPathCount((current) =>
        Math.min(attackPaths.length, current + ATTACK_PATH_QUEUE_PAGE_SIZE),
      );
      return;
    }
    if (!pathHasMoreFromApi || !selectedScanId || !graphData || loadingMorePaths) return;
    const offset = graphData.pagination?.offset ?? 0;
    const limit = graphData.pagination?.limit ?? ATTACK_PATH_FETCH_PAGE;
    // Server has_more uses offset+limit < total; advance by the requested page size.
    const nextOffset = offset + limit;
    setLoadingMorePaths(true);
    try {
      const nextPage = await api.getGraphAttackPaths({
        scanId: selectedScanId,
        offset: nextOffset,
        limit: ATTACK_PATH_FETCH_PAGE,
      });
      setGraphData((current) =>
        current ? mergeAttackPathGraphPages(current, nextPage) : nextPage,
      );
      setVisibleAttackPathCount((current) => current + ATTACK_PATH_QUEUE_PAGE_SIZE);
    } catch (error) {
      setGraphLoadError(userFacingApiErrorMessage(error, "Failed to load more attack paths"));
      setApiErrorKind(_classifyGraphErrorKind(error));
    } finally {
      setLoadingMorePaths(false);
    }
  }, [
    attackPaths.length,
    graphData,
    hiddenLoadedAttackPathCount,
    loadingMorePaths,
    pathHasMoreFromApi,
    selectedScanId,
  ]);

  const rankedRows = useMemo<RankedPathRow[]>(
    () =>
      rankedAttackPathRows(visibleAttackPaths, fixFirstCards).flatMap(({ path, card, rank, key }) => {
        const pathNodes = toAttackCardNodes(path, graphNodeById);
        if (pathNodes.length === 0) return [];
        const row: RankedPathRow = {
          key,
          selectionKey: attackPathKey(path),
          rank,
          title: descriptiveAttackPathTitle(card?.title, pathNodes),
          cve: path.vuln_ids[0] ?? null,
          riskScore: path.composite_risk,
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
    if (query) params.set("lens", "lineage");
    return params.size > 0 ? `/security-graph?${params.toString()}` : "/security-graph?lens=lineage";
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
      <PageLaneHeader
        lane="command"
        title="Investigation"
        subtitle="Evidence-linked attack paths for the selected finding or asset; switch to Estate for current-state topology."
        actions={
          captureMode ? undefined : (
          <>
            <GraphEvidenceExportButton
              scanId={selectedScanId || undefined}
              filenamePrefix={selectedScanId ? `scan-${selectedScanId}-security-graph` : undefined}
            />
            <Link
              href={fullGraphHref}
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              Open lineage lens
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
          )
        }
      />

      <GraphLensSwitcher variant="compact" />

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
        <div className="flex flex-wrap items-center justify-between gap-3">
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
              className="inline-flex items-center gap-2 rounded-full border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/30 px-3 py-1.5 text-xs text-red-700 dark:text-red-200 transition hover:border-red-700"
            >
              Retry in full graph
              <GitBranch className="h-3.5 w-3.5" />
            </Link>
            {hasFocusContext && (
              <Link
                href={resetFocusHref}
                className="inline-flex items-center gap-2 rounded-full border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/30 px-3 py-1.5 text-xs text-red-700 dark:text-red-200 transition hover:border-red-700"
              >
                Clear focus
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </section>
      ) : requestedSnapshotMissing ? (
        <section className="rounded-3xl border border-amber-500/30 bg-amber-500/5 p-4">
          <GraphEmptyState
            title="Snapshot unavailable for requested scan"
            detail={`No persisted graph snapshot exists for scan ${focus.scanId}. The investigation did not substitute evidence from a different scan.`}
            suggestions={[
              "Run or re-sync the requested scan with graph persistence enabled.",
              "Choose another scan under Evidence scope to investigate older evidence explicitly.",
              "Review the requested scan's findings while its graph snapshot is unavailable.",
            ]}
          />
          <div className="mt-4 flex flex-wrap gap-3 border-t border-amber-500/20 pt-4">
            <Link
              href={buildFindingsHref({ scanId: focus.scanId })}
              className="inline-flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-800 transition hover:border-amber-600 dark:text-amber-200"
            >
              Review requested scan findings
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <Link
              href="/security-graph"
              className="inline-flex items-center gap-2 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
            >
              Open latest snapshot
              <GitBranch className="h-3.5 w-3.5" />
            </Link>
          </div>
        </section>
      ) : allAttackPaths.length === 0 ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <div className="mb-4">
            <GraphAnalysisStatusBanner status={graphData?.stats.analysis_status?.attack_path_fusion} />
          </div>
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
            title="No paths match the current investigation filters"
            detail="Clear severity, layer, evidence, or environment chips to restore the ranked path queue."
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
        </section>
      ) : (
        <InvestigationPathWorkspace
          rows={rankedRows}
          selectedKey={selectedAttackPath ? attackPathKey(selectedAttackPath) : null}
          onSelect={(key) => {
            setSelectedAttackPathKey(key);
            setCompletedSteps((current) => ({ ...current, path: true }));
            setPathView("graph");
          }}
          title={`${pathQueueCounts.renderedRows} rendered · ${pathQueueCounts.returnedRows} returned · ${pathQueueCounts.snapshotTotal} snapshot paths${pathQueueCounts.truncated ? " · truncated" : ""}`}
          subtitle={`Select a path to focus its graph and evidence here.${
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
          queueFooter={
            hiddenAttackPathCount > 0 || loadingMorePaths ? (
              <div className="mt-4">
                <GraphCompletenessBanner
                  visibleCount={visibleAttackPaths.length}
                  omittedCount={Math.max(hiddenAttackPathCount, loadingMorePaths ? 1 : 0)}
                  loadMoreLabel={
                    loadingMorePaths
                      ? "Loading more paths…"
                      : `Show ${Math.min(ATTACK_PATH_QUEUE_PAGE_SIZE, Math.max(hiddenAttackPathCount, 1))} more`
                  }
                  onLoadMore={() => {
                    void loadMoreAttackPaths();
                  }}
                />
              </div>
            ) : null
          }
          detail={
            selectedExposurePath ? (
              <ExposurePathCommandCenter
                path={selectedExposurePath}
                actions={selectedFixFirstCard?.next_actions ?? selectedPathActions}
                scanId={selectedScanId || undefined}
                view={pathView}
                onViewChange={setPathView}
                techniquesSlot={
                  selectedAttackPath ? <AttackPathTechniqueChain path={selectedAttackPath} /> : null
                }
                graphSlot={
                  graphData && selectedAttackPath ? (
                    <SecurityGraphInvestigation
                      graph={graphData as UnifiedGraphData}
                      attackPath={selectedAttackPath}
                      focusMode={investigationFocusMode}
                      onFocusModeChange={setInvestigationFocusMode}
                      fullGraphHref={fullGraphHref}
                      loading={loadingGraph}
                      scanId={selectedScanId || undefined}
                      onPinnedNodeChange={setPinnedNodeId}
                      onStepHint={handleStepHint}
                    />
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

      <Collapsible
        title="Evidence scope"
        subtitle={selectedSnapshot
          ? `Current scan evidence · ${formatDate(selectedSnapshot.created_at)} · ${selectedSnapshot.node_count} nodes · ${selectedSnapshot.edge_count} edges`
          : "No persisted graph evidence selected."
        }
        icon={GitBranch}
        defaultOpen={false}
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                Current scan evidence
              </p>
              <p className="mt-1 font-mono text-sm text-[color:var(--foreground)]">
                {selectedSnapshot ? selectedSnapshot.scan_id : "No scan selected"}
              </p>
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
      </Collapsible>

      {!captureMode ? (
        <Collapsible
          title="Should I deploy?"
          subtitle="Check an agent, service, image, or package against the selected evidence scope."
          icon={Rocket}
          defaultOpen={false}
        >
          <DeployGatePanel scanId={selectedScanId || undefined} />
        </Collapsible>
      ) : null}

      <Collapsible
        title="Exposure paths"
        subtitle="Broader agent-native exposure analysis over the selected evidence scope."
        icon={Route}
        defaultOpen={false}
      >
        <ExposurePathLens scanId={selectedScanId || undefined} />
      </Collapsible>
    </div>
  );
}

function SecurityGraphPageContent() {
  const searchParams = useSearchParams();
  return resolveSecurityGraphSurface(searchParams) === "attack-path"
    ? <AttackPathInvestigationContent />
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
