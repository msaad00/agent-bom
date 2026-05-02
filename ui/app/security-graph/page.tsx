"use client";

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  GitBranch,
  Loader2,
  Route,
  Sparkles,
} from "lucide-react";

import { ApiOfflineState } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";

function _classifyGraphErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}
import { AttackPathCard } from "@/components/attack-path-card";
import { GraphEmptyState } from "@/components/graph-state-panels";
import { PostureGrade } from "@/components/posture-grade";
import {
  api,
  formatDate,
  type GraphSnapshot,
  type PostureResponse,
  type UnifiedGraphResponse,
} from "@/lib/api";
import {
  attackPathKey,
  attackPathSequenceLabels,
  buildSecurityGraphHref,
  labelsForAttackPathType,
  matchesAttackPathFocus,
  recommendedInteractionRiskActions,
  recommendedAttackPathActions,
  summarizeInteractionRisks,
  moveAttackPathSelection,
  toAttackCardNodes,
} from "@/lib/attack-paths";
import { EntityType } from "@/lib/graph-schema";

const ATTACK_PATH_ENTITY_TYPES = [
  EntityType.VULNERABILITY,
  EntityType.MISCONFIGURATION,
  EntityType.PACKAGE,
  EntityType.SERVER,
  EntityType.CONTAINER,
  EntityType.CLOUD_RESOURCE,
  EntityType.AGENT,
  EntityType.USER,
  EntityType.GROUP,
  EntityType.SERVICE_ACCOUNT,
  EntityType.CREDENTIAL,
  EntityType.TOOL,
];

function emptyGraphResponse(scanId: string): UnifiedGraphResponse {
  return {
    scan_id: scanId,
    tenant_id: "",
    created_at: "",
    nodes: [],
    edges: [],
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: 0,
      total_edges: 0,
      node_types: {},
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
    pagination: {
      total: 0,
      offset: 0,
      limit: 0,
      has_more: false,
    },
  };
}

function SecurityGraphPageContent() {
  const searchParams = useSearchParams();
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [graphData, setGraphData] = useState<UnifiedGraphResponse | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [loadingSnapshots, setLoadingSnapshots] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [apiErrorKind, setApiErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [selectedAttackPathKey, setSelectedAttackPathKey] = useState<string | null>(null);
  const [focusApplied, setFocusApplied] = useState(false);

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
      } catch (error) {
        if (cancelled) return;
        setApiError(error instanceof Error ? error.message : "Failed to load graph snapshots");
        setApiErrorKind(_classifyGraphErrorKind(error));
        setSnapshots([]);
        setGraphData(null);
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
      setSelectedAttackPathKey(null);
      return;
    }

    let cancelled = false;

    async function loadGraph() {
      setLoadingGraph(true);
      try {
        const graph = await api.getGraph({
          scanId: selectedScanId,
          entityTypes: ATTACK_PATH_ENTITY_TYPES,
          maxDepth: 6,
          limit: 1200,
        });
        if (cancelled) return;
        setGraphData(graph);
        setApiError(null);
      } catch (error) {
        if (cancelled) return;
        setGraphData(emptyGraphResponse(selectedScanId));
        setApiError(error instanceof Error ? error.message : "Failed to load security graph");
      } finally {
        if (!cancelled) setLoadingGraph(false);
      }
    }

    void loadGraph();
    return () => {
      cancelled = true;
    };
  }, [selectedScanId]);

  const selectedSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.scan_id === selectedScanId) ?? null,
    [snapshots, selectedScanId],
  );

  const graphNodeById = useMemo(
    () => new Map((graphData?.nodes ?? []).map((node) => [node.id, node])),
    [graphData?.nodes],
  );

  const attackPaths = useMemo(
    () =>
      [...(graphData?.attack_paths ?? [])].sort(
        (left, right) => right.composite_risk - left.composite_risk,
      ),
    [graphData?.attack_paths],
  );

  const hasFocusContext = Boolean(focus.cve || focus.packageName || focus.agentName);
  const resetFocusHref = useMemo(
    () => buildSecurityGraphHref({ scanId: selectedScanId || undefined }),
    [selectedScanId],
  );

  const selectedAttackPath = useMemo(
    () =>
      selectedAttackPathKey
        ? attackPaths.find((path) => attackPathKey(path) === selectedAttackPathKey) ?? null
        : attackPaths[0] ?? null,
    [attackPaths, selectedAttackPathKey],
  );

  const selectedPathAgents = useMemo(
    () =>
      selectedAttackPath
        ? labelsForAttackPathType(selectedAttackPath, graphNodeById, "agent")
        : [],
    [graphNodeById, selectedAttackPath],
  );

  const selectedPathSequence = useMemo(
    () =>
      selectedAttackPath
        ? attackPathSequenceLabels(selectedAttackPath, graphNodeById)
        : [],
    [graphNodeById, selectedAttackPath],
  );

  const selectedPathActions = useMemo(
    () =>
      selectedAttackPath
        ? recommendedAttackPathActions(selectedAttackPath, graphNodeById)
        : [],
    [graphNodeById, selectedAttackPath],
  );

  const interactionRiskSummary = useMemo(
    () => summarizeInteractionRisks(graphData?.interaction_risks ?? []),
    [graphData?.interaction_risks],
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

  const loadingGraphMessage = focusLabel
    ? `Loading attack-path candidates for ${focusLabel} from the persisted graph.`
    : "Loading attack-path candidates from the persisted graph.";

  useEffect(() => {
    setFocusApplied(false);
  }, [focus.agentName, focus.cve, focus.packageName, selectedScanId]);

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
    <div className="space-y-6">
      <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[radial-gradient(circle_at_top_left,rgba(16,185,129,0.08),transparent_34%),linear-gradient(180deg,var(--surface),var(--surface-elevated))] p-6 shadow-2xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-900/60 bg-emerald-950/30 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-emerald-300">
              <Route className="h-3.5 w-3.5" />
              Security graph
            </div>
            <h1 className="mt-4 text-3xl font-semibold tracking-tight text-[color:var(--foreground)]">
              Fix-first attack paths without dropping into the full graph canvas
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-7 text-[color:var(--text-secondary)]">
              This view keeps the highest-risk exploit chains explicit: what finding starts the path, which assets it reaches,
              which credentials and tools stay exposed, and where to jump next for evidence or remediation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Link
              href="/graph"
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              Open full lineage graph
              <GitBranch className="h-4 w-4" />
            </Link>
            <Link
              href="/remediation"
              className="inline-flex items-center gap-2 rounded-xl border border-emerald-800 bg-emerald-950/40 px-4 py-2 text-sm font-medium text-emerald-300 transition hover:bg-emerald-950/70"
            >
              Open remediation
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>

        <div className="mt-6 grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-[10px] uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">Snapshot</p>
                <h2 className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">
                  {selectedSnapshot ? `Scan ${selectedSnapshot.scan_id.slice(0, 8)}…` : "No persisted graph snapshot yet"}
                </h2>
                {selectedSnapshot && (
                  <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
                    Persisted {formatDate(selectedSnapshot.created_at)} · {selectedSnapshot.node_count} nodes · {selectedSnapshot.edge_count} edges
                  </p>
                )}
              </div>
              {loadingSnapshots && (
                <span className="inline-flex items-center gap-2 text-xs text-sky-400">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  loading snapshots
                </span>
              )}
            </div>

            {snapshots.length > 0 ? (
              <div className="mt-4 flex flex-wrap gap-2">
                {snapshots.slice(0, 8).map((snapshot) => {
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
            ) : (
              !loadingSnapshots && (
                <div className="mt-4 rounded-2xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5 text-sm text-[color:var(--text-secondary)]">
                  No persisted graph snapshots yet. Run a scan first so the security graph can build historical attack-path views.
                </div>
              )
            )}
          </div>

          <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            <p className="text-[10px] uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">Current pressure</p>
            {posture ? (
              <div className="mt-3">
                <PostureGrade
                  grade={posture.grade}
                  score={posture.score}
                  dimensions={posture.dimensions}
                  drilldown
                />
              </div>
            ) : (
              <div className="mt-4 rounded-2xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5 text-sm text-[color:var(--text-secondary)]">
                Posture scoring is unavailable for this snapshot.
              </div>
            )}
          </div>
        </div>
      </section>

      {loadingGraph ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-8 text-center text-sm text-[color:var(--text-secondary)]">
          <Loader2 className="mx-auto mb-3 h-6 w-6 animate-spin text-sky-400" />
          {loadingGraphMessage}
        </section>
      ) : attackPaths.length === 0 ? (
        <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <GraphEmptyState
            title={emptyGraphState.title}
            detail={emptyGraphState.detail}
            suggestions={emptyGraphState.suggestions}
          />
          <div className="mt-4 flex flex-wrap gap-3 border-t border-[color:var(--border-subtle)] pt-4">
            <Link
              href="/graph"
              className="inline-flex items-center gap-2 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
            >
              Open full graph
              <GitBranch className="h-3.5 w-3.5" />
            </Link>
            <Link
              href="/findings"
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
          <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-[10px] uppercase tracking-[0.2em] text-orange-400">Attack path queue</p>
                <h2 className="mt-1 text-lg font-semibold text-[color:var(--foreground)]">
                  {attackPaths.length} high-signal path{attackPaths.length !== 1 ? "s" : ""} in the selected snapshot
                </h2>
                <p className="mt-1 text-sm text-[color:var(--text-tertiary)]">
                  Focus one exploit chain at a time, then jump into the full graph only when you need broader topology.
                </p>
                <p className="mt-2 text-xs text-[color:var(--text-tertiary)]">
                  Keyboard: focus this queue and use ← / → to step through paths.
                </p>
                {focusLabel && (
                  <p className="mt-2 text-xs text-emerald-300">
                    Focused from dashboard context: {focusLabel}
                  </p>
                )}
                <div className="mt-3 flex flex-wrap gap-2">
                  <Link
                    href="/graph"
                    className="inline-flex items-center gap-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1 text-[11px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                  >
                    Full graph
                    <GitBranch className="h-3 w-3" />
                  </Link>
                  <Link
                    href="/findings"
                    className="inline-flex items-center gap-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1 text-[11px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                  >
                    Findings
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                  {hasFocusContext && (
                    <Link
                      href={resetFocusHref}
                      className="inline-flex items-center gap-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1 text-[11px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                    >
                      Clear focus
                      <ArrowRight className="h-3 w-3" />
                    </Link>
                  )}
                </div>
              </div>
              <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-3 text-sm text-[color:var(--text-secondary)]">
                <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Highest composite risk</div>
                <div className="mt-1 font-mono text-xl text-red-300">{attackPaths[0]!.composite_risk.toFixed(1)}</div>
              </div>
            </div>

            <div
              className="mt-4 flex gap-3 overflow-x-auto pb-1 outline-none"
              tabIndex={0}
              onKeyDown={handleAttackPathQueueKeyDown}
              aria-label="Attack path queue"
            >
              {attackPaths.slice(0, 8).map((path) => {
                const key = attackPathKey(path);
                const pathNodes = toAttackCardNodes(path, graphNodeById);
                if (pathNodes.length === 0) return null;
                const active = selectedAttackPath ? attackPathKey(selectedAttackPath) === key : false;
                return (
                  <div
                    key={key}
                    className={`min-w-[360px] rounded-2xl transition ${active ? "ring-2 ring-orange-400/70 ring-offset-2 ring-offset-zinc-950" : ""}`}
                  >
                    <AttackPathCard
                      nodes={pathNodes}
                      riskScore={path.composite_risk}
                      onClick={() => setSelectedAttackPathKey(key)}
                    />
                  </div>
                );
              })}
            </div>
          </section>

          {selectedAttackPath && (
            <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
              <div className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.2em] text-orange-400">Selected path</p>
                    <h2 className="mt-1 text-lg font-semibold text-[color:var(--foreground)]">
                      {selectedAttackPath.summary || "Credential-aware exploit chain"}
                    </h2>
                    <p className="mt-2 text-sm leading-6 text-[color:var(--text-secondary)]">
                      The graph already resolved this chain. Use it as the operator-facing shortlist before you branch into detailed evidence.
                    </p>
                  </div>
                  <div className="rounded-2xl border border-red-900/60 bg-red-950/20 px-4 py-3">
                    <div className="text-[10px] uppercase tracking-[0.18em] text-red-300">Composite risk</div>
                    <div className="mt-1 font-mono text-2xl text-red-200">{selectedAttackPath.composite_risk.toFixed(1)}</div>
                  </div>
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                  <QuickStat label="Hop count" value={String(Math.max(0, selectedAttackPath.hops.length - 1))} />
                  <QuickStat
                    label="Credentials exposed"
                    value={selectedAttackPath.credential_exposure.length > 0 ? String(selectedAttackPath.credential_exposure.length) : "none"}
                    tone={selectedAttackPath.credential_exposure.length > 0 ? "amber" : "zinc"}
                  />
                  <QuickStat
                    label="Tools reachable"
                    value={selectedAttackPath.tool_exposure.length > 0 ? String(selectedAttackPath.tool_exposure.length) : "none"}
                    tone={selectedAttackPath.tool_exposure.length > 0 ? "blue" : "zinc"}
                  />
                  <QuickStat
                    label="Findings in chain"
                    value={selectedAttackPath.vuln_ids.length > 0 ? String(selectedAttackPath.vuln_ids.length) : "none"}
                    tone={selectedAttackPath.vuln_ids.length > 0 ? "red" : "zinc"}
                  />
                </div>

                {selectedPathSequence.length > 0 && (
                  <div className="mt-4 rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
                    <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Path sequence</div>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      {selectedPathSequence.map((label, index) => (
                        <div key={`${label}-${index}`} className="flex items-center gap-2">
                          {index > 0 && <ArrowRight className="h-3.5 w-3.5 text-[color:var(--text-tertiary)]" />}
                          <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1 text-[11px] font-mono text-[color:var(--text-secondary)]">
                            {label}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mt-4 grid gap-4 lg:grid-cols-2">
                  <TagList
                    label="Findings"
                    tags={selectedAttackPath.vuln_ids}
                    emptyLabel="No linked findings"
                    hrefForTag={(tag) => `/findings?cve=${encodeURIComponent(tag)}`}
                  />
                  <TagList
                    label="Agents"
                    tags={selectedPathAgents}
                    emptyLabel="No agent hop resolved in this path"
                    hrefForTag={(tag) => `/agents?name=${encodeURIComponent(tag)}`}
                  />
                </div>

                <div className="mt-4 grid gap-4 lg:grid-cols-2">
                  <TagList label="Credentials" tags={selectedAttackPath.credential_exposure} emptyLabel="No credential exposure" />
                  <TagList label="Tools" tags={selectedAttackPath.tool_exposure} emptyLabel="No tool exposure" />
                </div>

                <div className="mt-4 text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                  Recommended next steps
                </div>
                <div className="mt-3 grid gap-3 lg:grid-cols-3">
                  {selectedPathActions.map((action) => (
                    <Link
                      key={action.title}
                      href={action.href}
                      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 transition hover:border-[color:var(--border-strong)]"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="text-sm font-medium text-[color:var(--foreground)]">{action.title}</div>
                        <ArrowRight className="h-4 w-4 text-emerald-300" />
                      </div>
                      <p className="mt-2 text-xs leading-5 text-[color:var(--text-tertiary)]">{action.detail}</p>
                    </Link>
                  ))}

                  <Link
                    href="/graph"
                    className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 transition hover:border-[color:var(--border-strong)]"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-medium text-[color:var(--foreground)]">Open full graph canvas</div>
                      <GitBranch className="h-4 w-4 text-[color:var(--text-secondary)]" />
                    </div>
                    <p className="mt-2 text-xs leading-5 text-[color:var(--text-tertiary)]">
                      Switch to the full lineage view when you need broader topology, filters, or neighboring assets.
                    </p>
                  </Link>
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
                  <div className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
                    <Sparkles className="h-4 w-4 text-sky-400" />
                    Interaction risks
                  </div>
                  <p className="mt-2 text-xs leading-5 text-[color:var(--text-tertiary)]">
                    Runtime interaction overlays show where agent behavior, tags, and control surfaces can expand blast radius.
                  </p>
                  {graphData?.interaction_risks?.length ? (
                    <div className="mt-4 space-y-3">
                      <div className="grid grid-cols-3 gap-3">
                        <QuickStat label="Patterns" value={String(interactionRiskSummary.total)} />
                        <QuickStat label="Agents touched" value={String(interactionRiskSummary.uniqueAgents)} tone="blue" />
                        <QuickStat label="Highest risk" value={interactionRiskSummary.highestRisk.toFixed(1)} tone="amber" />
                      </div>
                      {graphData.interaction_risks.slice(0, 3).map((risk) => (
                        <div key={`${risk.pattern}-${risk.risk_score}`} className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="text-sm font-medium text-[color:var(--foreground)]">{risk.pattern}</div>
                              <p className="mt-1 text-xs leading-5 text-[color:var(--text-tertiary)]">{risk.description}</p>
                              {risk.owasp_agentic_tag && (
                                <div className="mt-2 inline-flex rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-1 text-[10px] font-mono text-[color:var(--text-secondary)]">
                                  {risk.owasp_agentic_tag}
                                </div>
                              )}
                            </div>
                            <span className="rounded-full border border-sky-800 bg-sky-950/40 px-2 py-1 text-[10px] font-mono text-sky-300">
                              {risk.risk_score.toFixed(1)}
                            </span>
                          </div>
                          {risk.agents.length > 0 && (
                            <div className="mt-3 flex flex-wrap gap-2">
                              {risk.agents.slice(0, 4).map((agent) => (
                                <Link
                                  key={agent}
                                  href={`/agents?name=${encodeURIComponent(agent)}`}
                                  className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-1 text-[11px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                                >
                                  {agent}
                                </Link>
                              ))}
                            </div>
                          )}
                          {risk.owasp_agentic_tag && (
                            <div className="mt-3 flex flex-wrap gap-2">
                              <Link
                                href={`/compliance?q=${encodeURIComponent(risk.owasp_agentic_tag)}`}
                                className="rounded-full border border-emerald-900/70 bg-emerald-950/30 px-2 py-1 text-[11px] font-mono text-emerald-300 transition hover:border-emerald-700 hover:text-emerald-200"
                              >
                                {risk.owasp_agentic_tag}
                              </Link>
                            </div>
                          )}
                          <div className="mt-3 flex flex-wrap gap-2">
                            {recommendedInteractionRiskActions(risk).map((action) => (
                              <Link
                                key={`${risk.pattern}-${action.label}`}
                                href={action.href}
                                className="inline-flex items-center gap-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1 text-[11px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                              >
                                {action.label}
                                <ArrowRight className="h-3 w-3" />
                              </Link>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="mt-4 rounded-2xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 text-sm text-[color:var(--text-secondary)]">
                      No interaction risk overlays were recorded for this snapshot.
                    </div>
                  )}
                </div>

                <div className="rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
                  <div className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
                    <AlertTriangle className="h-4 w-4 text-orange-400" />
                    Operator notes
                  </div>
                  <ul className="mt-4 space-y-3 text-sm leading-6 text-[color:var(--text-secondary)]">
                    <li>Use this page when you want the fix-first shortlist, not the full topology explorer.</li>
                    <li>Persisted snapshots keep historical paths even when later scans deactivate or remove an entity.</li>
                    <li>Open the lineage graph when you need full neighbor context, pagination, or custom filtering.</li>
                  </ul>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <a
                      href="https://osv.dev/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-[color:var(--text-tertiary)] transition hover:text-[color:var(--text-secondary)]"
                    >
                      External OSV reference
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                </div>
              </div>
            </section>
          )}
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
      <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1 font-mono text-xl">{value}</div>
    </div>
  );
}

function TagList({
  label,
  tags,
  emptyLabel,
  hrefForTag,
}: {
  label: string;
  tags: string[];
  emptyLabel: string;
  hrefForTag?: (tag: string) => string;
}) {
  return (
    <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
      <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">{label}</div>
      {tags.length > 0 ? (
        <div className="mt-3 flex flex-wrap gap-2">
          {tags.map((tag) => (
            hrefForTag ? (
              <Link
                key={tag}
                href={hrefForTag(tag)}
                className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-1 text-[11px] font-mono text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
              >
                {tag}
              </Link>
            ) : (
              <span key={tag} className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-1 text-[11px] font-mono text-[color:var(--text-secondary)]">
                {tag}
              </span>
            )
          ))}
        </div>
      ) : (
        <div className="mt-3 text-sm text-[color:var(--text-secondary)]">{emptyLabel}</div>
      )}
    </div>
  );
}
