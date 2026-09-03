"use client";

import Link from "next/link";
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
import type { GraphAttackPath } from "@/lib/api-types";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import type { UnifiedNode } from "@/lib/graph-schema";

const DEFAULT_MAX_AGE_HOURS = 24 * 7;

const JOURNEY = [
  { label: "Source intake", detail: "Local + connected", icon: Database },
  { label: "Discover", detail: "Inventory", icon: Search },
  { label: "Scan", detail: "Evidence", icon: ShieldCheck },
  { label: "Correlate", detail: "Exact IDs", icon: Network },
  { label: "Investigate", detail: "Paths", icon: GitBranch },
  { label: "Enforce", detail: "Opt-in", icon: CheckCircle2 },
] as const;

type EvidenceAge = "fresh" | "stale" | "future" | "unknown";

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
  historyError = null,
  priorityPath = null,
  priorityNodes = [],
  priorityAction,
  onOpenSnapshot,
}: {
  snapshots: GraphSnapshot[];
  initialRun?: GraphCorrelationRun | null;
  historyError?: string | null;
  priorityPath?: GraphAttackPath | null;
  priorityNodes?: UnifiedNode[] | undefined;
  priorityAction?: { title: string; href: string } | undefined;
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
  const priorityNodeById = new Map(priorityNodes.map((node) => [node.id, node]));
  const priorityFinding = priorityPath?.vuln_ids?.[0] ?? "Priority path";
  const priorityTarget = priorityPath
    ? priorityNodeById.get(priorityPath.target)?.label || priorityPath.target
    : "priority target";
  const priorityRisk = priorityPath?.composite_risk;
  const priorityHopCount = priorityPath ? Math.max(priorityPath.hops.length - 1, 0) : 0;
  const freshReceiptCount = run?.input_manifest.filter((receipt) => receipt.freshness !== "stale_allowed").length ?? 0;
  const manifestDigest = run?.manifest_sha256 ? `sha256:${run.manifest_sha256.replace(/^sha256:/, "").slice(0, 12)}…` : "manifest pending";

  return (
    <section
      aria-label="Snapshot correlation"
      data-testid="graph-correlation-workflow"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-emerald-700 dark:text-emerald-300">
            <Network className="h-4 w-4" />
            {isComplete ? `Correlation complete · ${freshReceiptCount}/${receiptCount} fresh` : "Evidence journey"}
          </p>
          <h2 data-testid="correlation-outcome-heading" className="mt-1 text-xl font-semibold tracking-tight text-[color:var(--foreground)] sm:text-2xl">
            {isComplete
              ? `${receiptCount} independent evidence sources produced ${attackPaths} confirmed attack path${attackPaths === 1 ? "" : "s"}`
              : "Connect sources, scan once, and investigate the joined risk"}
          </h2>
          <p className="mt-2 max-w-4xl text-xs leading-5 text-[color:var(--text-secondary)]">
            {isComplete
              ? "Repository, image/SBOM, Kubernetes IaC, MCP, identity, and runtime evidence were joined by exact canonical identifiers. Similar labels and mutable tags were not used."
              : "Connected and local sources produce immutable scan evidence; the latest completed correlation is selected automatically. Exact identifiers form joins—similar labels and mutable tags never do."}
          </p>
        </div>
        <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 dark:text-sky-300">
          {freshnessBoundLabel(activeFreshnessBound)}
        </span>
      </div>

      <details className={`group mt-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] ${isComplete ? "" : "open"}`} open={!isComplete}>
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2.5 text-xs font-medium text-[color:var(--foreground)] [&::-webkit-details-marker]:hidden">
          <span>{isComplete ? "How this evidence was produced" : "Evidence journey"}</span>
          <ChevronDown className="h-4 w-4 text-[color:var(--text-tertiary)] transition group-open:rotate-180" />
        </summary>
        <ol aria-label="Evidence journey" className="grid grid-cols-2 gap-2 border-t border-[color:var(--border-subtle)] p-3 sm:grid-cols-3 xl:grid-cols-6">
          {JOURNEY.map((step, index) => {
            const state = journeyState[index]!;
            const done = state.done;
            const StepIcon = step.icon;
            return (
              <li key={step.label} className="relative rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2.5">
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

      {historyError ? (
        <div role="alert" className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-800 dark:text-amber-200">
          {historyError}
        </div>
      ) : run ? (
        <div className={`mt-4 rounded-xl border bg-[color:var(--surface)] p-3 text-xs ${isFailed ? "border-red-500/30" : isComplete ? "border-emerald-500/30" : "border-sky-500/30"}`}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="flex items-center gap-2 font-semibold text-[color:var(--foreground)]">
                {isComplete ? <CheckCircle2 className="h-4 w-4 text-emerald-500" /> : isFailed ? <AlertTriangle className="h-4 w-4 text-red-500" /> : <Loader2 className="h-4 w-4 animate-spin text-sky-500" />}
                {isComplete ? "Evidence correlation complete" : isFailed ? "Evidence correlation failed" : `Evidence correlation ${run.status}`}
              </p>
              <p className="mt-1 text-[11px] text-[color:var(--text-tertiary)]">
                Immutable output · exact canonical joins · no label or mutable-tag joins
              </p>
              {isFailed && run.failure_code ? <p className="mt-1 font-mono text-[10px] text-red-600 dark:text-red-300">Failure code: {run.failure_code}</p> : null}
            </div>
            <div className="flex flex-wrap gap-2">
              {priorityAction ? (
                <Link data-testid="correlation-primary-action" href={priorityAction.href} className="rounded-lg bg-emerald-600 px-3 py-2 font-semibold text-white transition hover:bg-emerald-500">
                  {priorityAction.title}
                </Link>
              ) : null}
              {run.output_scan_id ? (
                <button type="button" onClick={() => onOpenSnapshot(run.output_scan_id)} className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 font-medium text-emerald-700 hover:bg-emerald-500/15 dark:text-emerald-300">
                  Open correlated snapshot
                </button>
              ) : null}
            </div>
          </div>
          {isComplete ? <div
            aria-label="Correlation source receipt graph"
            data-testid="graph-correlation-receipt-dag"
            className="mt-3 grid items-center gap-3 lg:grid-cols-[minmax(0,1.15fr)_auto_minmax(11rem,0.42fr)_auto_minmax(14rem,0.68fr)]"
          >
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              {run.input_manifest.map((receipt) => (
                <div key={receipt.scan_id} className="min-w-0 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2">
                  <p className="truncate font-medium text-[color:var(--foreground)]">{sourceLabel(receipt.source_kinds, receipt.scan_id)}</p>
                  <p className={receipt.freshness === "stale_allowed" || evidenceAge(receipt.created_at, run.max_age_hours) === "stale" ? "mt-1 text-[10px] text-amber-700 dark:text-amber-300" : "mt-1 text-[10px] text-emerald-700 dark:text-emerald-300"}>
                    {receipt.freshness === "stale_allowed"
                      ? "Stale allowed at run"
                      : evidenceAge(receipt.created_at, run.max_age_hours) === "stale"
                        ? "Expired since run"
                        : "Fresh receipt"}
                  </p>
                </div>
              ))}
            </div>
            <ArrowRight className="hidden h-5 w-5 text-emerald-500 lg:block" aria-hidden="true" />
            <div className="rounded-xl border border-sky-500/35 bg-sky-500/10 p-3 text-center">
              <Network className="mx-auto h-5 w-5 text-sky-600 dark:text-sky-300" />
              <p className="mt-2 font-semibold text-[color:var(--foreground)]">Exact-ID correlation</p>
              <p className="mt-1 text-[10px] leading-4 text-[color:var(--text-secondary)]">
                {run.result_manifest.output?.node_count ?? 0} entities · {run.result_manifest.output?.edge_count ?? 0} relationships
              </p>
              <p className="mt-1 text-[10px] text-[color:var(--text-tertiary)]">
                {conflicts} conflict{conflicts === 1 ? "" : "s"} retained · bounded analysis
              </p>
            </div>
            <ArrowRight className="hidden h-5 w-5 text-emerald-500 lg:block" aria-hidden="true" />
            <div className="rounded-xl border border-red-500/35 bg-red-500/10 p-3">
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-red-700 dark:text-red-300">
                {attackPaths} confirmed attack path{attackPaths === 1 ? "" : "s"}
              </p>
              <p className="mt-1 text-sm font-semibold leading-5 text-[color:var(--foreground)]">
                {priorityFinding} can reach {priorityTarget}
              </p>
              <p className="mt-2 flex flex-wrap gap-x-2 text-[11px] text-[color:var(--text-secondary)]">
                <span>{typeof priorityRisk === "number" ? `Risk ${priorityRisk.toFixed(1)}` : "Risk ranked"}</span>
                {priorityHopCount > 0 ? <span>{priorityHopCount} hops</span> : null}
              </p>
            </div>
          </div> : null}
          {isComplete ? (
            <p className="mt-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-[11px] text-[color:var(--text-secondary)]">
              {run.max_age_hours}h freshness bound · analysis complete · manifest <span className="font-mono text-[color:var(--foreground)]">{manifestDigest}</span>
            </p>
          ) : null}
          <details className="group mt-2 rounded-lg border border-[color:var(--border-subtle)]">
            <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-[10px] font-medium text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
              <span>View signed receipt manifest</span>
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
