"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Loader2, Route } from "lucide-react";

import {
  api,
  type GraphExposureEntityRef,
  type GraphExposurePath,
  type GraphExposurePathsResponse,
} from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import {
  ExposurePathCommandCenter,
  type ExposurePathView,
} from "@/components/exposure-path-command-center";
import {
  exposurePathKey,
  normalizeExposureSeverity,
  pathDisplayTitle,
  pathSpanLabel,
  type ExposureEntityRef,
  type ExposureEntityRole,
  type ExposurePath,
} from "@/lib/exposure-path";
import { PageErrorState, PageEmptyState } from "@/components/states/page-state";
import { StatStrip } from "@/components/stat-strip";

const EXPOSURE_PATH_LIMIT = 25;

const KNOWN_ROLES = new Set<ExposureEntityRole>([
  "agent",
  "server",
  "package",
  "finding",
  "credential",
  "tool",
  "environment",
  "cluster",
  "unknown",
]);

function toRole(role: string): ExposureEntityRole {
  if (role === "vulnerability" || role === "misconfiguration") return "finding";
  const value = role.toLowerCase() as ExposureEntityRole;
  return KNOWN_ROLES.has(value) ? value : "unknown";
}

function toEntityRef(ref: GraphExposureEntityRef): ExposureEntityRef {
  return {
    id: ref.id,
    label: ref.label,
    role: toRole(ref.role),
    severity: ref.severity,
    riskScore: ref.riskScore,
  };
}

/** Map the MCP/REST ExposurePath payload onto the UI's shared ExposurePath shape. */
export function toUiExposurePath(path: GraphExposurePath): ExposurePath {
  const hops = path.hops.map(toEntityRef);
  const affectedAgents = hops.filter((hop) => hop.role === "agent").map((hop) => hop.label);
  const affectedServers = hops.filter((hop) => hop.role === "server").map((hop) => hop.label);
  return {
    id: path.id,
    rank: path.rank,
    label: path.label,
    summary: path.summary,
    riskScore: path.riskScore,
    severity: normalizeExposureSeverity(path.severity),
    source: toEntityRef(path.source),
    target: toEntityRef(path.target),
    hops,
    relationships: path.relationships.map((rel) => ({
      id: rel.id,
      source: rel.source,
      target: rel.target,
      relationship: rel.relationship,
      confidence: rel.confidence,
      direction: rel.direction,
      traversable: rel.traversable,
    })),
    nodeIds: path.nodeIds,
    edgeIds: path.edgeIds,
    findings: path.findings,
    affectedAgents,
    affectedServers,
    reachableTools: path.reachableTools,
    exposedCredentials: path.exposedCredentials,
    reachability: path.reachability,
    reachabilityBasis: path.reachabilityBasis,
    evidenceDimensions: path.evidenceDimensions,
    hopEvidence: path.hopEvidence,
    provenance: path.provenance,
  };
}

/**
 * ExposurePath lens for the security-graph page. Renders the agent-native
 * /v1/graph/exposure-paths queue (a distinct view from the ranked attack paths)
 * and reuses the shared ExposurePathCommandCenter Path/Graph/List rendering.
 */
export function ExposurePathLens({ scanId }: { scanId?: string | undefined }) {
  const [response, setResponse] = useState<GraphExposurePathsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [view, setView] = useState<ExposurePathView>("path");
  const [pageHistory, setPageHistory] = useState<(string | undefined)[]>([undefined]);
  const [pageIndex, setPageIndex] = useState(0);
  const requestSequence = useRef(0);
  const pinnedScan = useRef<string | undefined>(scanId);

  const load = useCallback(async (cursor?: string) => {
    const sequence = ++requestSequence.current;
    setLoading(true);
    setError(null);
    try {
      const data = await api.getGraphExposurePaths({
        scanId: pinnedScan.current || scanId || undefined,
        limit: EXPOSURE_PATH_LIMIT,
        ...(cursor ? { cursor } : {}),
      });
      if (sequence !== requestSequence.current) return;
      setResponse(data);
      pinnedScan.current = data.scan_id || scanId;
      setSelectedKey(null);
    } catch (err) {
      if (sequence !== requestSequence.current) return;
      setResponse(null);
      setError(userFacingApiErrorMessage(err, "Failed to load exposure paths"));
    } finally {
      if (sequence === requestSequence.current) setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    pinnedScan.current = scanId;
    setPageHistory([undefined]);
    setPageIndex(0);
    void load();
    return () => { requestSequence.current += 1; };
  }, [load, scanId]);

  const paths = useMemo(() => (response?.paths ?? []).map(toUiExposurePath), [response]);

  const selectedPath = useMemo(() => {
    if (paths.length === 0) return null;
    return paths.find((path) => exposurePathKey(path) === selectedKey) ?? paths[0]!;
  }, [paths, selectedKey]);

  const highestRisk = useMemo(
    () => paths.reduce((max, path) => Math.max(max, path.riskScore), 0),
    [paths],
  );

  if (loading) {
    return (
      <section
        aria-label="Exposure paths"
        className="flex items-center justify-center rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] py-12"
      >
        <Loader2 className="h-5 w-5 animate-spin text-[color:var(--text-tertiary)]" aria-hidden="true" />
        <span className="ml-2 text-xs text-[color:var(--text-secondary)]">Loading exposure paths…</span>
      </section>
    );
  }

  if (error) {
    return (
      <PageErrorState
        title="Cannot load exposure paths"
        detail={error}
        action={{ label: "Restart query", onClick: () => {
          pinnedScan.current = scanId;
          setPageHistory([undefined]);
          setPageIndex(0);
          void load();
        } }}
        data-testid="exposure-path-lens-error"
      />
    );
  }

  if (paths.length === 0) {
    return (
      <PageEmptyState
        icon={Route}
        title={response?.count_metadata?.total_is_lower_bound ? "No paths found within the analysis budget" : "No exposure paths recorded"}
        detail={
          response?.message ||
          "No exposure paths were recorded or derived. This does not establish that the snapshot's assets are safe."
        }
        suggestions={[
          "Run a fresh scan so the graph can rebuild exposure evidence.",
          "Inspect snapshot coverage and relationship evidence before drawing a safety conclusion.",
        ]}
        data-testid="exposure-path-lens-empty"
      />
    );
  }

  return (
    <section aria-label="Exposure paths" className="space-y-3" data-testid="exposure-path-lens">
      <StatStrip
        items={[
          { label: "Paths on this page", value: response?.count ?? paths.length },
          { label: response?.count_metadata?.total_is_lower_bound ? "At least in snapshot" : "Total in snapshot", value: response?.total ?? paths.length },
          { label: "Highest page priority", value: highestRisk.toFixed(1), accent: "critical" },
        ]}
      />
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[color:var(--text-secondary)]" aria-label="Exposure path pagination">
        <p role="status">
          Page {pageIndex + 1} · {paths.length} paths shown. {response?.count_metadata?.total_is_lower_bound
            ? "Analysis reached its node budget; the snapshot total is a lower bound."
            : "Path connections do not by themselves establish exploitation."}
        </p>
        <div className="flex gap-2">
          <button type="button" disabled={pageIndex === 0} className="rounded border border-[color:var(--border-subtle)] px-3 py-2 disabled:opacity-40" onClick={() => {
            const previous = pageIndex - 1;
            setPageIndex(previous);
            void load(pageHistory[previous]);
          }}>Previous paths</button>
          <button type="button" disabled={!response?.pagination?.next_cursor} className="rounded border border-[color:var(--border-subtle)] px-3 py-2 disabled:opacity-40" onClick={() => {
            const cursor = response?.pagination?.next_cursor;
            if (!cursor) return;
            setPageHistory([...pageHistory.slice(0, pageIndex + 1), cursor]);
            setPageIndex(pageIndex + 1);
            void load(cursor);
          }}>Next paths</button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
        <ul className="space-y-1.5" aria-label="Exposure path queue">
          {paths.map((path) => {
            const key = exposurePathKey(path);
            const active = selectedPath ? exposurePathKey(selectedPath) === key : false;
            return (
              <li key={key}>
                <button
                  type="button"
                  onClick={() => setSelectedKey(key)}
                  aria-pressed={active}
                  className={`w-full rounded-xl border px-3 py-2 text-left transition ${
                    active
                      ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)]"
                      : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] hover:border-[color:var(--border-strong)]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="min-w-0 truncate text-xs font-medium text-[color:var(--foreground)]">
                      {pathDisplayTitle(path)}
                    </span>
                    <span className="shrink-0 font-mono text-xs text-[color:var(--text-secondary)]">
                      {path.riskScore.toFixed(1)}
                    </span>
                  </div>
                  <div className="mt-0.5 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                    {String(path.severity)} · {pathSpanLabel(path.hops.length)} · {path.evidenceDimensions?.reachability.verdict ?? "reachability unknown"}
                  </div>
                </button>
              </li>
            );
          })}
        </ul>

        {selectedPath && (
          <ExposurePathCommandCenter
            path={selectedPath}
            scanId={response?.scan_id || scanId || undefined}
            view={view}
            onViewChange={setView}
          />
        )}
      </div>
    </section>
  );
}
