"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Loader2, Network } from "lucide-react";

import { api, formatDate, type GraphCorrelationRun, type GraphSnapshot } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";

const DEFAULT_MAX_AGE_HOURS = 24 * 7;

export function GraphCorrelationWorkflow({
  snapshots,
  onOpenSnapshot,
}: {
  snapshots: GraphSnapshot[];
  onOpenSnapshot: (scanId: string) => void;
}) {
  const [selected, setSelected] = useState<string[]>([]);
  const [name, setName] = useState("Investigation correlation");
  const [maxAgeHours, setMaxAgeHours] = useState(DEFAULT_MAX_AGE_HOURS);
  const [allowStale, setAllowStale] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [run, setRun] = useState<GraphCorrelationRun | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const eligible = useMemo(
    () => snapshots.filter((snapshot) => snapshot.node_count > 0 && (snapshot.snapshot_kind ?? "scan") === "scan"),
    [snapshots],
  );

  useEffect(() => {
    if (!run || !["pending", "running"].includes(run.status)) return;
    const timer = window.setTimeout(() => {
      void api.getGraphCorrelation(run.correlation_id)
        .then(setRun)
        .catch((reason: unknown) => setError(userFacingApiErrorMessage(reason, "Failed to refresh correlation status")));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [run]);

  function toggle(scanId: string) {
    setSelected((current) =>
      current.includes(scanId)
        ? current.filter((value) => value !== scanId)
        : [...current, scanId].sort(),
    );
  }

  async function createCorrelation() {
    setSubmitting(true);
    setError(null);
    try {
      setRun(await api.createGraphCorrelation({
        name: name.trim(),
        scan_ids: selected,
        max_age_hours: maxAgeHours,
        allow_stale: allowStale,
      }));
    } catch (reason) {
      setError(userFacingApiErrorMessage(reason, "Failed to create graph correlation"));
    } finally {
      setSubmitting(false);
    }
  }

  const conflicts = run?.result_manifest.correlation_merge?.conflict_count ?? 0;
  const attackPaths = run?.result_manifest.output?.attack_path_count ?? 0;

  return (
    <section
      aria-label="Snapshot correlation"
      data-testid="graph-correlation-workflow"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
            <Network className="h-4 w-4 text-emerald-500" /> Correlate evidence snapshots
          </p>
          <p className="mt-1 max-w-3xl text-xs text-[color:var(--text-secondary)]">
            Join exact repository, image/SBOM, IaC, identity, MCP, and runtime receipts. Similar labels and mutable image tags never form joins.
          </p>
        </div>
        <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 dark:text-sky-300">
          2–32 immutable inputs
        </span>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-[minmax(0,1fr)_12rem]">
        <label className="text-xs font-medium text-[color:var(--text-secondary)]">
          Correlation name
          <input
            aria-label="Correlation name"
            value={name}
            maxLength={160}
            onChange={(event) => setName(event.target.value)}
            className="mt-1 w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-sm text-[color:var(--foreground)]"
          />
        </label>
        <label className="text-xs font-medium text-[color:var(--text-secondary)]">
          Maximum evidence age (hours)
          <input
            aria-label="Maximum evidence age (hours)"
            type="number"
            min={1}
            max={8760}
            value={maxAgeHours}
            onChange={(event) => {
              setMaxAgeHours(Number(event.target.value));
              setConfirmed(false);
            }}
            className="mt-1 w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-sm text-[color:var(--foreground)]"
          />
        </label>
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {snapshots.map((snapshot) => {
          const nested = (snapshot.snapshot_kind ?? "scan") !== "scan";
          const disabled = nested || snapshot.node_count < 1;
          return (
            <label
              key={snapshot.scan_id}
              className={`flex min-w-0 items-start gap-2 rounded-xl border p-3 text-xs ${
                selected.includes(snapshot.scan_id)
                  ? "border-emerald-500/50 bg-emerald-500/10"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface)]"
              } ${disabled ? "opacity-50" : "cursor-pointer"}`}
            >
              <input
                aria-label={snapshot.scan_id}
                type="checkbox"
                disabled={disabled}
                checked={selected.includes(snapshot.scan_id)}
                onChange={() => toggle(snapshot.scan_id)}
                className="mt-0.5"
              />
              <span className="min-w-0">
                <span className="block truncate font-mono text-[color:var(--foreground)]">{snapshot.scan_id}</span>
                <span className="mt-1 block text-[color:var(--text-tertiary)]">
                  {snapshot.node_count} nodes · {snapshot.edge_count} edges · {formatDate(snapshot.created_at)}
                </span>
                {nested ? <span className="mt-1 block text-amber-600 dark:text-amber-300">Nested correlation excluded in v1</span> : null}
              </span>
            </label>
          );
        })}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-[color:var(--text-secondary)]">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          I confirm the 7-day freshness bound ({maxAgeHours} hours)
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={allowStale} onChange={(event) => setAllowStale(event.target.checked)} />
          Allow stale inputs and label them stale
        </label>
        <button
          type="button"
          disabled={submitting || selected.length < 2 || selected.length > 32 || !confirmed || !name.trim() || maxAgeHours < 1 || maxAgeHours > 8760}
          onClick={() => void createCorrelation()}
          className="rounded-lg bg-emerald-600 px-3 py-2 font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? "Starting correlation…" : "Correlate selected evidence"}
        </button>
      </div>

      {error ? (
        <p role="alert" className="mt-3 flex items-center gap-2 text-xs text-red-600 dark:text-red-300">
          <AlertTriangle className="h-4 w-4" /> {error}
        </p>
      ) : null}

      {run ? (
        <div className="mt-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="flex items-center gap-2 font-medium text-[color:var(--foreground)]">
              {run.status === "complete" ? <CheckCircle2 className="h-4 w-4 text-emerald-500" /> : <Loader2 className="h-4 w-4 animate-spin text-sky-500" />}
              {run.correlation_id} · {run.status}
            </p>
            {run.output_scan_id ? (
              <button type="button" onClick={() => onOpenSnapshot(run.output_scan_id)} className="font-medium text-emerald-600 hover:underline dark:text-emerald-300">
                Open correlated snapshot
              </button>
            ) : null}
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {run.input_manifest.map((receipt) => (
              <div key={receipt.scan_id} className="rounded-lg border border-[color:var(--border-subtle)] p-2">
                <p className="truncate font-mono text-[color:var(--foreground)]">{receipt.scan_id}</p>
                <p className={receipt.freshness === "stale_allowed" ? "text-amber-600 dark:text-amber-300" : "text-emerald-600 dark:text-emerald-300"}>
                  {receipt.freshness ?? "receipt captured"}
                </p>
              </div>
            ))}
          </div>
          {run.status === "complete" ? (
            <div className="mt-3 flex flex-wrap gap-2 text-[color:var(--text-secondary)]">
              <span>{conflicts} conflicting field set{conflicts === 1 ? "" : "s"} retained</span>
              <span>·</span>
              <span>{attackPaths} confirmed attack paths</span>
              <span>·</span>
              <span>bounded analysis recorded</span>
            </div>
          ) : null}
        </div>
      ) : null}
      {eligible.length < 2 ? <p className="mt-3 text-xs text-amber-600 dark:text-amber-300">At least two populated scan snapshots are required.</p> : null}
    </section>
  );
}
