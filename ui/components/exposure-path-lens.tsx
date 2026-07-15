"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
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
    })),
    nodeIds: path.nodeIds,
    edgeIds: path.edgeIds,
    findings: path.findings,
    affectedAgents,
    affectedServers,
    reachableTools: path.reachableTools,
    exposedCredentials: path.exposedCredentials,
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

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getGraphExposurePaths({
        scanId: scanId || undefined,
        limit: EXPOSURE_PATH_LIMIT,
      });
      setResponse(data);
    } catch (err) {
      setResponse(null);
      setError(userFacingApiErrorMessage(err, "Failed to load exposure paths"));
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    void load();
  }, [load]);

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
        action={{ label: "Retry", onClick: () => void load() }}
        data-testid="exposure-path-lens-error"
      />
    );
  }

  if (paths.length === 0) {
    return (
      <PageEmptyState
        icon={Route}
        title="No exposure paths for this snapshot"
        detail={
          response?.message ||
          "No agent-to-vulnerability exposure path currently reaches a credential exposure or reachable tool in this scan."
        }
        suggestions={[
          "Run a fresh scan so the graph can rebuild exposure evidence.",
          "Lower the risk filter to inspect lower-risk exposure paths.",
        ]}
        data-testid="exposure-path-lens-empty"
      />
    );
  }

  return (
    <section aria-label="Exposure paths" className="space-y-3" data-testid="exposure-path-lens">
      <StatStrip
        items={[
          { label: "Exposure paths", value: response?.count ?? paths.length },
          { label: "Total in snapshot", value: response?.total ?? paths.length },
          { label: "Highest risk", value: highestRisk.toFixed(1), accent: "critical" },
        ]}
      />

      <div className="grid gap-3 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
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
                    {String(path.severity)} · {Math.max(0, path.hops.length - 1)} hops
                  </div>
                </button>
              </li>
            );
          })}
        </ul>

        {selectedPath && (
          <ExposurePathCommandCenter
            path={selectedPath}
            scanId={scanId || undefined}
            view={view}
            onViewChange={setView}
          />
        )}
      </div>
    </section>
  );
}
