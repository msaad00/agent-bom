"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  Database,
  GitBranch,
  Loader2,
  Network,
  Search,
  ShieldCheck,
} from "lucide-react";

import { api, formatDate, type GraphCorrelationRun, type GraphSnapshot } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";

const DEFAULT_MAX_AGE_HOURS = 24 * 7;

const JOURNEY = [
  { label: "Connect", detail: "Sources", icon: Database },
  { label: "Discover", detail: "Inventory", icon: Search },
  { label: "Scan", detail: "Evidence", icon: ShieldCheck },
  { label: "Correlate", detail: "Exact IDs", icon: Network },
  { label: "Prioritize", detail: "Paths", icon: GitBranch },
  { label: "Enforce & verify", detail: "Runtime", icon: CheckCircle2 },
] as const;

function sourceLabel(sourceKinds: string[] | undefined, scanId: string): string {
  const value = `${sourceKinds?.join(" ") ?? ""} ${scanId}`.toLowerCase();
  if (value.includes("sbom") || value.includes("cyclonedx") || value.includes("image")) return "Image + SBOM";
  if (value.includes("repository") || value.includes("repo")) return "Repository";
  if (value.includes("kubernetes") || value.includes("iac")) return "Kubernetes IaC";
  if (value.includes("identity") || value.includes("permission")) return "Identity";
  if (value.includes("runtime") || value.includes("gateway")) return "Runtime";
  if (value.includes("mcp")) return "MCP config";
  return "Scan evidence";
}

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
    const eligibleIds = eligible.slice(0, 32).map((snapshot) => snapshot.scan_id).sort();
    setSelected((current) => {
      const retained = current.filter((scanId) => eligibleIds.includes(scanId));
      return retained.length > 0 ? retained : eligibleIds;
    });
  }, [eligible]);

  useEffect(() => {
    let active = true;
    void api.listGraphCorrelations(20)
      .then((result) => {
        if (!active) return;
        const latest = result.items.find((candidate) => candidate.status === "complete" && candidate.output_scan_id);
        if (latest) setRun(latest);
      })
      .catch(() => {
        // Reading prior runs is an enhancement. Keep the manual/API/CLI/MCP
        // path available without turning a transient history-read failure into
        // a false correlation failure.
      });
    return () => {
      active = false;
    };
  }, []);

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
  const isComplete = run?.status === "complete";
  const hasRuntimeReceipt = run?.input_manifest.some((receipt) => sourceLabel(receipt.source_kinds, receipt.scan_id) === "Runtime") ?? false;

  return (
    <section
      aria-label="Snapshot correlation"
      data-testid="graph-correlation-workflow"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
            <Network className="h-4 w-4 text-emerald-500" /> Continuous evidence journey
          </p>
          <p className="mt-1 max-w-3xl text-xs text-[color:var(--text-secondary)]">
            Connected sources produce immutable scan evidence; the latest completed correlation is selected automatically. Exact identifiers form joins—similar labels and mutable tags never do.
          </p>
        </div>
        <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 dark:text-sky-300">
          7-day freshness policy
        </span>
      </div>

      <ol aria-label="Evidence journey" className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
        {JOURNEY.map((step, index) => {
          const done = index < 3 ? eligible.length > 0 : index < 5 ? isComplete : isComplete && hasRuntimeReceipt;
          const StepIcon = step.icon;
          return (
            <li key={step.label} className="relative rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2.5">
              <div className="flex items-center gap-2">
                <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${done ? "bg-emerald-500/12 text-emerald-600 dark:text-emerald-300" : "bg-sky-500/10 text-sky-600 dark:text-sky-300"}`}>
                  <StepIcon className="h-3.5 w-3.5" />
                </span>
                <div className="min-w-0">
                  <p className="truncate text-xs font-semibold text-[color:var(--foreground)]">{step.label}</p>
                  <p className="truncate text-[10px] text-[color:var(--text-tertiary)]">{done ? "Complete" : step.detail}</p>
                </div>
              </div>
              {index < JOURNEY.length - 1 ? <ArrowRight className="absolute -right-2.5 top-4 z-10 hidden h-4 w-4 text-[color:var(--text-tertiary)] xl:block" aria-hidden="true" /> : null}
            </li>
          );
        })}
      </ol>

      {run ? (
        <div className="mt-4 rounded-xl border border-emerald-500/30 bg-[color:var(--surface)] p-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="flex items-center gap-2 font-semibold text-[color:var(--foreground)]">
                {isComplete ? <CheckCircle2 className="h-4 w-4 text-emerald-500" /> : <Loader2 className="h-4 w-4 animate-spin text-sky-500" />}
                {isComplete ? "Evidence correlation complete" : `Evidence correlation ${run.status}`}
              </p>
              <p className="mt-1 text-[10px] text-[color:var(--text-tertiary)]">
                {run.input_manifest.length} immutable source receipts · {run.max_age_hours}h bound · {run.allow_stale ? "stale inputs labeled" : "fresh inputs required"}
              </p>
            </div>
            {run.output_scan_id ? (
              <button type="button" onClick={() => onOpenSnapshot(run.output_scan_id)} className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 font-medium text-emerald-700 hover:bg-emerald-500/15 dark:text-emerald-300">
                Open correlated snapshot
              </button>
            ) : null}
          </div>
          <div
            aria-label="Correlation source receipt graph"
            data-testid="graph-correlation-receipt-dag"
            className="mt-3 grid items-center gap-3 lg:grid-cols-[minmax(0,1fr)_auto_minmax(13rem,0.32fr)]"
          >
            <div className="flex flex-wrap gap-2">
              {run.input_manifest.map((receipt) => (
                <div key={receipt.scan_id} className="min-w-[8.5rem] flex-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2">
                  <p className="font-medium text-[color:var(--foreground)]">{sourceLabel(receipt.source_kinds, receipt.scan_id)}</p>
                  <p className={receipt.freshness === "stale_allowed" ? "mt-1 text-[10px] text-amber-600 dark:text-amber-300" : "mt-1 text-[10px] text-emerald-600 dark:text-emerald-300"}>
                    {receipt.freshness === "stale_allowed" ? "Stale allowed" : "Fresh receipt"}
                  </p>
                </div>
              ))}
            </div>
            <ArrowRight className="hidden h-5 w-5 text-emerald-500 lg:block" aria-hidden="true" />
            <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3">
              <p className="flex items-center gap-2 font-semibold text-[color:var(--foreground)]">
                <Database className="h-4 w-4 text-emerald-500" /> Correlated snapshot
              </p>
              <p className="mt-2 text-[10px] text-[color:var(--text-secondary)]">
                {attackPaths} confirmed attack path{attackPaths === 1 ? "" : "s"}
              </p>
              <p className="mt-1 text-[10px] text-[color:var(--text-tertiary)]">{conflicts} conflict{conflicts === 1 ? "" : "s"} retained · bounded analysis</p>
            </div>
          </div>
          <details className="group mt-2 rounded-lg border border-[color:var(--border-subtle)]">
            <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-[10px] font-medium text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
              <span>Inspect signed source receipts</span>
              <ChevronDown className="h-3.5 w-3.5 transition group-open:rotate-180" />
            </summary>
            <div className="grid gap-2 border-t border-[color:var(--border-subtle)] p-2 sm:grid-cols-2">
              {run.input_manifest.map((receipt) => (
                <div key={receipt.scan_id} className="min-w-0 rounded-md bg-[color:var(--surface-elevated)] px-2.5 py-2 text-[10px]">
                  <p className="truncate font-mono text-[color:var(--foreground)]">{receipt.scan_id}</p>
                  <p className="mt-1 truncate font-mono text-[color:var(--text-tertiary)]">{receipt.digest ?? "digest pending"}</p>
                </div>
              ))}
            </div>
          </details>
        </div>
      ) : (
        <div className="mt-4 rounded-xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-4 py-3 text-xs text-[color:var(--text-secondary)]">
          {eligible.length >= 2 ? "No completed correlation yet. Create one with the API, CLI, MCP, or the custom workflow below." : "At least two populated scan snapshots are required."}
        </div>
      )}

      <details className="group mt-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2.5 text-xs font-medium text-[color:var(--foreground)] [&::-webkit-details-marker]:hidden">
          <span>Run custom correlation</span>
          <ChevronDown className="h-4 w-4 text-[color:var(--text-tertiary)] transition group-open:rotate-180" />
        </summary>
        <div className="border-t border-[color:var(--border-subtle)] p-3">
          <p className="mb-3 text-[10px] text-[color:var(--text-tertiary)]">Eligible fresh scan snapshots are preselected. Review the explicit policy before creating an immutable run.</p>
      <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_12rem]">
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

          {isComplete ? (
            <p className="mt-3 text-xs text-[color:var(--text-secondary)]">
              {conflicts} conflicting field set{conflicts === 1 ? "" : "s"} retained · {attackPaths} confirmed attack paths · bounded analysis recorded
            </p>
          ) : null}
        </div>
      </details>
    </section>
  );
}
