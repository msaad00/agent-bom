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
  { label: "Investigate", detail: "Paths", icon: GitBranch },
  { label: "Enforce", detail: "Opt-in", icon: CheckCircle2 },
] as const;

type EvidenceAge = "fresh" | "stale" | "future" | "unknown";

export type GraphCorrelationOutcome = {
  scanId: string;
  title: string;
  summary: string;
  source: string;
  target: string;
  finding?: string | undefined;
  packageName?: string | undefined;
  risk: number;
  hops: number;
  runtimeObserved: boolean;
  runtimeBlocked: boolean;
  action?: { title: string; href: string } | undefined;
};

type CorrelationAnalysisState =
  | "complete"
  | "limited"
  | "skipped"
  | "failed"
  | "in_progress"
  | "unavailable";

function correlationAnalysisState(run: GraphCorrelationRun): CorrelationAnalysisState {
  if (run.status === "pending" || run.status === "running") return "in_progress";
  if (run.status === "failed") return "failed";

  const bounds = run.result_manifest.analysis_bounds;
  if (!bounds || typeof bounds !== "object") return "unavailable";

  const relevant = [bounds.correlation_merge, bounds.attack_path_fusion];
  if (relevant.some((value) => !value || typeof value !== "object")) return "unavailable";

  const records = Object.values(bounds).filter(
    (value): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value),
  );
  const states = records.map((value) => typeof value.status === "string" ? value.status : "not_recorded");
  if (states.includes("failed")) return "failed";
  if (states.includes("skipped")) return "skipped";
  if (
    states.includes("limited") ||
    states.includes("not_recorded") ||
    records.some((value) => value.truncated === true)
  ) return "limited";
  return states.length > 0 && states.every((status) => status === "complete")
    ? "complete"
    : "unavailable";
}

function correlationAnalysisLabel(state: CorrelationAnalysisState): string {
  if (state === "complete") return "Analysis complete";
  if (state === "limited") return "Analysis limited — inspect bounds";
  if (state === "skipped") return "Analysis skipped — inspect bounds";
  if (state === "failed") return "Analysis failed";
  if (state === "in_progress") return "Analysis in progress";
  return "Analysis status unavailable";
}

function evidenceAge(createdAt: string | undefined, maxAgeHours: number, now = Date.now()): EvidenceAge {
  const observedAt = Date.parse(createdAt ?? "");
  if (!Number.isFinite(observedAt)) return "unknown";
  if (observedAt - now > 5 * 60 * 1000) return "future";
  return now - observedAt <= maxAgeHours * 60 * 60 * 1000 ? "fresh" : "stale";
}

function evidenceAgeLabel(age: EvidenceAge): string {
  if (age === "fresh") return "Fresh";
  if (age === "stale") return "Outside freshness bound";
  if (age === "future") return "Future timestamp rejected";
  return "Timestamp unavailable";
}

function freshnessBoundLabel(hours: number): string {
  return hours % 24 === 0
    ? `${hours / 24}-day freshness bound`
    : `${hours}-hour freshness bound`;
}

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
  initialRun = null,
  outcome = null,
  onOpenSnapshot,
}: {
  snapshots: GraphSnapshot[];
  initialRun?: GraphCorrelationRun | null;
  outcome?: GraphCorrelationOutcome | null;
  onOpenSnapshot: (scanId: string) => void;
}) {
  const [selected, setSelected] = useState<string[]>([]);
  const [name, setName] = useState("Investigation correlation");
  const [maxAgeHours, setMaxAgeHours] = useState(DEFAULT_MAX_AGE_HOURS);
  const [allowStale, setAllowStale] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [run, setRun] = useState<GraphCorrelationRun | null>(initialRun);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const eligible = useMemo(
    () => snapshots.filter((snapshot) => snapshot.node_count > 0 && (snapshot.snapshot_kind ?? "scan") === "scan"),
    [snapshots],
  );
  const selectable = useMemo(
    () => eligible.filter((snapshot) => {
      const age = evidenceAge(snapshot.created_at, maxAgeHours);
      return age === "fresh" || (allowStale && age === "stale");
    }),
    [allowStale, eligible, maxAgeHours],
  );

  useEffect(() => {
    const eligibleIds = selectable.slice(0, 32).map((snapshot) => snapshot.scan_id).sort();
    setSelected((current) => {
      const retained = current.filter((scanId) => eligibleIds.includes(scanId));
      return retained.length > 0 ? retained : eligibleIds;
    });
  }, [selectable]);

  useEffect(() => {
    if (!initialRun) return;
    setRun((current) =>
      !current || initialRun.created_at > current.created_at ? initialRun : current,
    );
  }, [initialRun]);

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
  const isFailed = run?.status === "failed";
  const hasRuntimeReceipt = run?.input_manifest.some((receipt) => sourceLabel(receipt.source_kinds, receipt.scan_id) === "Runtime") ?? false;
  const receiptCount = run?.input_manifest.length ?? 0;
  const journeyState = [
    { done: receiptCount > 0, detail: receiptCount > 0 ? `${receiptCount} sources` : "Add sources" },
    { done: run?.input_manifest.some((receipt) => (receipt.node_count ?? 0) > 0) ?? eligible.length > 0, detail: "Inventory" },
    { done: receiptCount >= 2, detail: receiptCount > 0 ? `${receiptCount} receipts` : "Evidence" },
    { done: isComplete, detail: isFailed ? "Failed" : run?.status ?? "Exact IDs" },
    { done: isComplete && attackPaths > 0, detail: isComplete ? `${attackPaths} paths` : "Paths" },
    { done: false, detail: hasRuntimeReceipt ? "Observed; block opt-in" : "Opt-in runtime" },
  ];
  const activeFreshnessBound = run?.max_age_hours ?? maxAgeHours;
  const staleReceiptCount = run?.input_manifest.filter((receipt) =>
    receipt.freshness === "stale_allowed" ||
    evidenceAge(receipt.created_at, run.max_age_hours) === "stale"
  ).length ?? 0;
  const analysisState = run ? correlationAnalysisState(run) : "unavailable";
  const analysisLabel = correlationAnalysisLabel(analysisState);
  const boundOutcome = run?.output_scan_id && outcome?.scanId === run.output_scan_id
    ? outcome
    : null;
  const resultIsVerified = isComplete && analysisState === "complete" && staleReceiptCount === 0;
  const evidenceState = staleReceiptCount > 0
    ? `${staleReceiptCount} stale source${staleReceiptCount === 1 ? "" : "s"} allowed`
    : "Fresh evidence";
  const zeroPathQualification = staleReceiptCount > 0
    ? "stale evidence was allowed"
    : analysisState === "limited"
      ? "analysis is limited"
      : analysisState === "skipped"
        ? "analysis was skipped"
        : analysisState === "failed"
          ? "analysis failed"
          : "analysis status is unavailable";

  return (
    <section
      aria-label="Snapshot correlation"
      data-testid="graph-correlation-workflow"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
            <Network className="h-4 w-4 text-emerald-500" /> Correlation result
          </p>
          <p className="mt-1 max-w-3xl text-xs text-[color:var(--text-secondary)]">
            The latest completed run is selected automatically. Review its outcome first; inspect source receipts and workflow mechanics when needed.
          </p>
        </div>
        <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 dark:text-sky-300">
          {freshnessBoundLabel(activeFreshnessBound)}
        </span>
      </div>

      <details className="group mt-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
        <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-xs font-medium text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
          <span>How evidence becomes an action</span>
          <ChevronDown className="h-4 w-4 transition group-open:rotate-180" />
        </summary>
      <ol aria-label="Evidence journey" className="grid grid-cols-2 gap-2 border-t border-[color:var(--border-subtle)] p-3 sm:grid-cols-3 xl:grid-cols-6">
        {JOURNEY.map((step, index) => {
          const state = journeyState[index]!;
          const done = state.done;
          const StepIcon = step.icon;
          return (
            <li key={step.label} className="relative rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2.5">
              <div className="flex items-center gap-2">
                <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${done ? "bg-emerald-500/12 text-emerald-600 dark:text-emerald-300" : "bg-sky-500/10 text-sky-600 dark:text-sky-300"}`}>
                  <StepIcon className="h-3.5 w-3.5" />
                </span>
                <div className="min-w-0">
                  <p className="text-xs font-semibold leading-4 text-[color:var(--foreground)]">{step.label}</p>
                  <p className="truncate text-[10px] text-[color:var(--text-tertiary)]">{done ? "Complete" : state.detail || step.detail}</p>
                </div>
              </div>
              {index < JOURNEY.length - 1 ? <ArrowRight className="absolute -right-2.5 top-4 z-10 hidden h-4 w-4 text-[color:var(--text-tertiary)] xl:block" aria-hidden="true" /> : null}
            </li>
          );
        })}
      </ol>
      </details>

      {run ? (
        <div
          data-testid="graph-correlation-decision"
          className={`mt-3 rounded-2xl border bg-[color:var(--surface)] p-3 text-[15px] sm:p-4 ${isFailed ? "border-red-500/35" : isComplete ? "border-emerald-500/35" : "border-sky-500/35"}`}
        >
          <div className="flex flex-col gap-3 sm:gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <p className="flex items-center gap-2 text-[15px] font-semibold uppercase tracking-[0.12em] text-emerald-700 dark:text-emerald-300">
                {isComplete ? <CheckCircle2 className="h-4 w-4" /> : isFailed ? <AlertTriangle className="h-4 w-4 text-red-500" /> : <Loader2 className="h-4 w-4 animate-spin text-sky-500" />}
                {isComplete
                  ? `${attackPaths} ${resultIsVerified ? "confirmed" : "retained"} path${attackPaths === 1 ? "" : "s"} across ${receiptCount} sources`
                  : isFailed ? "Correlation failed" : `Correlation ${run.status}`}
              </p>
              {isComplete && attackPaths > 0 && boundOutcome ? (
                <>
                  <h3 className="mt-2 text-lg font-semibold text-[color:var(--foreground)]">{boundOutcome.title}</h3>
                  <p className="mt-1 max-w-3xl text-[15px] text-[color:var(--text-secondary)]">{boundOutcome.summary}</p>
                  <p className="mt-2 text-[15px] font-medium text-[color:var(--foreground)]">{boundOutcome.source} → {boundOutcome.target}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 font-semibold text-red-700 dark:text-red-200">Risk {boundOutcome.risk.toFixed(1)}</span>
                    <span className="rounded-full border border-[color:var(--border-subtle)] px-2.5 py-1">{boundOutcome.hops} directed hops</span>
                    {boundOutcome.packageName ? <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-sky-700 dark:text-sky-200">{boundOutcome.packageName}</span> : null}
                    {boundOutcome.finding ? <span className="rounded-full border border-orange-500/30 bg-orange-500/10 px-2.5 py-1 text-orange-700 dark:text-orange-200">{boundOutcome.finding}</span> : null}
                    {boundOutcome.runtimeObserved ? <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-700 dark:text-emerald-200">Runtime observed</span> : null}
                    {boundOutcome.runtimeBlocked ? <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-700 dark:text-red-200">Runtime block verified</span> : null}
                  </div>
                </>
              ) : isComplete && attackPaths === 0 ? (
                <>
                  <h3 className="mt-2 text-lg font-semibold text-[color:var(--foreground)]">
                    {resultIsVerified
                      ? "No confirmed attack path in this correlation"
                      : `0 retained paths; ${zeroPathQualification}`}
                  </h3>
                  <p className="mt-1 text-[15px] text-[color:var(--text-secondary)]">Review exposure candidates and analysis limits before treating the result as absence of risk.</p>
                </>
              ) : isComplete ? (
                <p className="mt-2 text-[15px] text-[color:var(--text-secondary)]">Load this correlation&apos;s output to review its prioritized paths and evidence.</p>
              ) : isFailed ? (
                <>
                  <p className="mt-2 text-[15px] text-[color:var(--text-secondary)]">The run produced no selectable partial snapshot. Review the failure code, adjust the inputs, and retry.</p>
                  {run.failure_code ? <p className="mt-2 font-mono text-[11px] text-red-600 dark:text-red-300">Failure code: {run.failure_code}</p> : null}
                </>
              ) : <p className="mt-2 text-[15px] text-[color:var(--text-secondary)]">The evidence run is still processing.</p>}
              <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[15px] text-[color:var(--text-tertiary)]">
                <span>{evidenceState}</span>
                <span>{conflicts} conflict{conflicts === 1 ? "" : "s"}</span>
                <span>{analysisLabel}</span>
              </div>
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              {boundOutcome?.action && isComplete && attackPaths > 0 ? (
                <a data-testid="correlation-primary-action" href={boundOutcome.action.href} className="rounded-lg bg-emerald-600 px-3 py-2 font-semibold text-white hover:bg-emerald-500">{boundOutcome.action.title}</a>
              ) : null}
              {isComplete && attackPaths === 0 && run.output_scan_id ? (
                <a href={`/security-graph?lens=attack-path&scan=${encodeURIComponent(run.output_scan_id)}`} className="rounded-lg bg-emerald-600 px-3 py-2 font-semibold text-white hover:bg-emerald-500">
                  Review exposure candidates
                </a>
              ) : null}
              {isComplete && run.output_scan_id ? (
                <button data-testid="correlation-open-path" type="button" onClick={() => onOpenSnapshot(run.output_scan_id)} className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 font-semibold text-emerald-700 hover:bg-emerald-500/15 dark:text-emerald-300">
                  Open top path
                </button>
              ) : null}
            </div>
          </div>
          <details className="group mt-3 rounded-lg border border-[color:var(--border-subtle)]">
            <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-[15px] font-medium text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
              <span>Inspect source receipts · {receiptCount} sources · {conflicts} conflict{conflicts === 1 ? "" : "s"}</span>
              <ChevronDown className="h-3.5 w-3.5 transition group-open:rotate-180" />
            </summary>
            <div className="grid gap-2 border-t border-[color:var(--border-subtle)] p-2 sm:grid-cols-2">
              {run.input_manifest.map((receipt) => (
                <div key={receipt.scan_id} className="min-w-0 rounded-md bg-[color:var(--surface-elevated)] px-2.5 py-2 text-[10px]">
                  <p className="font-semibold text-[color:var(--foreground)]">{sourceLabel(receipt.source_kinds, receipt.scan_id)}</p>
                  <p className="truncate font-mono text-[color:var(--foreground)]">{receipt.scan_id}</p>
                  <p className="mt-1 truncate font-mono text-[color:var(--text-tertiary)]">{receipt.digest ?? "digest pending"}</p>
                  <p className="mt-1 text-[color:var(--text-secondary)]">{receipt.source_kinds?.join(", ") || "source kind unavailable"} · {receipt.node_count ?? 0} nodes · {receipt.edge_count ?? 0} edges</p>
                  <p className="mt-1 text-[color:var(--text-tertiary)]">Observed {formatDate(receipt.created_at ?? "")} · {evidenceAgeLabel(evidenceAge(receipt.created_at, run.max_age_hours))}</p>
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
          Run name
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
          const age = evidenceAge(snapshot.created_at, maxAgeHours);
          const disabled = nested || snapshot.node_count < 1 || age === "future" || age === "unknown" || (!allowStale && age === "stale");
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
                {!nested && snapshot.node_count > 0 ? (
                  <span className={`mt-1 block ${age === "fresh" ? "text-emerald-700 dark:text-emerald-300" : "text-amber-700 dark:text-amber-300"}`}>
                    {evidenceAgeLabel(age)}
                  </span>
                ) : null}
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
          I confirm the {freshnessBoundLabel(maxAgeHours)} ({maxAgeHours} hours)
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
