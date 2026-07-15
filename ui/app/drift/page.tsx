"use client";

import { useEffect, useState } from "react";
import {
  Radar,
  AlertTriangle,
  CheckCircle2,
  GitBranch,
  Loader2,
} from "lucide-react";
import { api, formatDate } from "@/lib/api";
import type { DriftIncident } from "@/lib/api-types";
import {
  PageLoadingState,
  PageEmptyState,
} from "@/components/states/page-state";
import {
  ApiOfflineState,
  type ApiOfflineKind,
} from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";

function classifyApiErrorKind(err: unknown): ApiOfflineKind {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
      <div className="mb-1 flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-xs text-[var(--text-tertiary)]">{label}</span>
      </div>
      <p className="text-2xl font-bold text-[var(--foreground)]">{value}</p>
    </div>
  );
}

function scoreColor(score: number): string {
  return score >= 0.66
    ? "bg-red-500"
    : score >= 0.33
      ? "bg-amber-500"
      : "bg-emerald-500";
}

function IncidentCard({
  incident,
  onResolve,
}: {
  incident: DriftIncident;
  onResolve: (id: string) => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const pct = Math.round(Math.min(1, Math.max(0, incident.drift_score)) * 100);

  return (
    <div
      className={`rounded-xl border p-4 ${
        incident.resolved
          ? "border-[var(--border-subtle)] bg-[var(--surface)]/30 opacity-70"
          : "border-[var(--border-subtle)] bg-[var(--surface)]/50"
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <GitBranch className="h-4 w-4 text-[var(--text-tertiary)]" />
            <span className="font-mono text-sm font-semibold text-[var(--foreground)]">
              {incident.blueprint_id}
            </span>
            <span
              className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                incident.resolved
                  ? "bg-emerald-500/10 dark:bg-emerald-900/60 text-emerald-700 dark:text-emerald-300"
                  : incident.status === "review"
                    ? "bg-amber-500/10 dark:bg-amber-900/60 text-amber-700 dark:text-amber-300"
                    : "bg-red-500/10 dark:bg-red-900/60 text-red-700 dark:text-red-300"
              }`}
            >
              {incident.resolved
                ? "resolved"
                : incident.status.replace(/_/g, " ")}
            </span>
            {incident.occurrences > 1 && (
              <span className="rounded bg-[var(--surface-elevated)] px-2 py-0.5 text-xs text-[var(--text-secondary)]">
                ×{incident.occurrences}
              </span>
            )}
          </div>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            {incident.violation_count} violation
            {incident.violation_count !== 1 ? "s" : ""} ·{" "}
            {incident.warning_count} warning
            {incident.warning_count !== 1 ? "s" : ""} · first{" "}
            {formatDate(incident.first_detected_at)} · last{" "}
            {formatDate(incident.last_detected_at)}
          </p>
        </div>
        {!incident.resolved && (
          <button
            type="button"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await onResolve(incident.incident_id);
              } finally {
                setBusy(false);
              }
            }}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-400 hover:bg-emerald-500/20 disabled:opacity-50"
          >
            {busy ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5" />
            )}
            Resolve
          </button>
        )}
      </div>

      <div className="mt-3 flex items-center gap-3">
        <div className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--surface-elevated)]">
          <div
            className={`h-full ${scoreColor(incident.drift_score)} transition-all`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="font-mono text-xs text-[var(--text-secondary)]">
          drift {incident.drift_score.toFixed(2)}
        </span>
      </div>

      {incident.top_violations.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {incident.top_violations.slice(0, 8).map((v, i) => (
            <span
              key={i}
              className="rounded bg-[var(--surface-elevated)] px-2 py-0.5 font-mono text-xs text-[var(--text-secondary)]"
            >
              {(v.tool_name as string) || (v.type as string) || "violation"}
            </span>
          ))}
        </div>
      )}

      {incident.resolved && incident.resolved_by && (
        <p className="mt-2 text-xs text-[var(--text-tertiary)]">
          Resolved by {incident.resolved_by}
          {incident.resolved_at ? ` · ${formatDate(incident.resolved_at)}` : ""}
          {incident.resolution_note ? ` · ${incident.resolution_note}` : ""}
        </p>
      )}
    </div>
  );
}

export default function DriftPage() {
  const [incidents, setIncidents] = useState<DriftIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<ApiOfflineKind>("network");
  const [showResolved, setShowResolved] = useState(false);

  const load = (includeResolved: boolean) => {
    setLoading(true);
    void api
      .listDriftIncidents(includeResolved, 500)
      .then((r) => {
        setIncidents(r.incidents);
        setError(null);
      })
      .catch((e) => {
        setError(e?.message ?? "Failed to load drift incidents");
        setErrorKind(classifyApiErrorKind(e));
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load(showResolved);
  }, [showResolved]);

  const resolve = async (id: string) => {
    await api.resolveDriftIncident(id, "Resolved from drift cockpit");
    setIncidents((prev) =>
      showResolved
        ? prev.map((i) =>
            i.incident_id === id
              ? { ...i, resolved: true, status: "resolved" }
              : i,
          )
        : prev.filter((i) => i.incident_id !== id),
    );
  };

  if (loading && incidents.length === 0)
    return (
      <PageLoadingState
        title="Loading drift incidents"
        detail="Comparing live agent behavior against role/profile blueprints."
      />
    );
  if (error)
    return (
      <ApiOfflineState
        title="Drift data unavailable"
        detail={error}
        kind={errorKind}
      />
    );

  const open = incidents.filter((i) => !i.resolved);
  const maxScore = incidents.length
    ? Math.max(...incidents.map((i) => i.drift_score))
    : 0;
  const resolvedCount = incidents.filter((i) => i.resolved).length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Radar className="h-6 w-6 text-rose-400" />
          <div>
            <h1 className="text-2xl font-semibold text-[var(--foreground)]">Drift</h1>
            <p className="text-sm text-[var(--text-tertiary)]">
              Behavioral drift incidents where live agent activity diverged from
              its declared blueprint.
            </p>
          </div>
        </div>
        <label className="flex cursor-pointer items-center gap-2 text-xs text-[var(--text-secondary)]">
          <input
            type="checkbox"
            checked={showResolved}
            onChange={(e) => setShowResolved(e.target.checked)}
            className="accent-rose-500"
          />
          Show resolved
        </label>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard
          icon={AlertTriangle}
          label="Open incidents"
          value={String(open.length)}
          color={open.length ? "text-red-400" : "text-emerald-400"}
        />
        <StatCard
          icon={Radar}
          label="Total tracked"
          value={String(incidents.length)}
          color="text-rose-400"
        />
        <StatCard
          icon={GitBranch}
          label="Peak drift score"
          value={maxScore.toFixed(2)}
          color="text-amber-400"
        />
        <StatCard
          icon={CheckCircle2}
          label="Resolved"
          value={String(resolvedCount)}
          color="text-emerald-400"
        />
      </div>

      {incidents.length === 0 ? (
        <PageEmptyState
          title="No drift incidents"
          detail="Agents are operating within their declared blueprints. Incidents open automatically when runtime behavior diverges from an assigned role/profile blueprint."
          icon={CheckCircle2}
        />
      ) : (
        <div className="space-y-3">
          {[...incidents]
            .sort(
              (a, b) =>
                Number(a.resolved) - Number(b.resolved) ||
                b.drift_score - a.drift_score,
            )
            .map((incident) => (
              <IncidentCard
                key={incident.incident_id}
                incident={incident}
                onResolve={resolve}
              />
            ))}
        </div>
      )}
    </div>
  );
}
