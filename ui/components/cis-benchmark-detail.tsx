"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Cloud,
  Copy,
  ExternalLink,
  ShieldAlert,
  Terminal,
  XCircle,
} from "lucide-react";

import { api } from "@/lib/api";
import type { CISBenchmarkCheck } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";

// Clouds the backend `build_cis_benchmark_check_rows` can emit, in the order
// we want them surfaced. The selector only shows clouds actually present in
// the fetched checks, so an estate without (say) Snowflake never shows it.
const CLOUD_LABELS: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  snowflake: "Snowflake",
  databricks: "Databricks",
};

function cloudLabel(cloud: string): string {
  return CLOUD_LABELS[cloud] ?? cloud.toUpperCase();
}

// The backend serves these rows from two paths (in-memory scan jobs and the
// columnar store). Both should emit flat array/boolean fields, but normalize
// defensively so a stringified `guardrails` or missing array never crashes a
// `.map` / `.includes` in render or filtering.
function normalizeCheck(check: CISBenchmarkCheck): CISBenchmarkCheck {
  return {
    ...check,
    guardrails: Array.isArray(check.guardrails) ? check.guardrails : [],
    resource_ids: Array.isArray(check.resource_ids) ? check.resource_ids : [],
    fix_cli: typeof check.fix_cli === "string" ? check.fix_cli : "",
    fix_console: typeof check.fix_console === "string" ? check.fix_console : "",
    requires_human_review: Boolean(check.requires_human_review),
    priority: typeof check.priority === "number" ? check.priority : Number(check.priority) || 0,
    remediation: check.remediation ?? {},
  };
}

function priorityLabel(priority: number): string {
  return priority > 0 ? `P${priority}` : "P—";
}

function statusBadge(status: string): { label: string; className: string; Icon: typeof CheckCircle } {
  switch (status) {
    case "pass":
      return { label: "Pass", className: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10", Icon: CheckCircle };
    case "fail":
      return { label: "Fail", className: "text-red-400 border-red-500/30 bg-red-500/10", Icon: XCircle };
    case "error":
      return { label: "Error", className: "text-orange-400 border-orange-500/30 bg-orange-500/10", Icon: AlertTriangle };
    case "not_applicable":
      return { label: "N/A", className: "text-zinc-500 border-zinc-700 bg-zinc-800/40", Icon: ChevronRight };
    default:
      return { label: status || "Unknown", className: "text-zinc-400 border-zinc-700 bg-zinc-800/40", Icon: ChevronRight };
  }
}

function severityClass(severity: string): string {
  switch (severity) {
    case "critical":
      return "text-red-300 border-red-500/40 bg-red-500/10";
    case "high":
      return "text-orange-300 border-orange-500/40 bg-orange-500/10";
    case "medium":
      return "text-yellow-300 border-yellow-500/40 bg-yellow-500/10";
    case "low":
      return "text-sky-300 border-sky-500/40 bg-sky-500/10";
    default:
      return "text-zinc-400 border-zinc-700 bg-zinc-800/40";
  }
}

const ALL = "all";
// Typed as string[] (not a literal tuple) so the generic FilterPills infers
// T = string and accepts the string state value.
const STATUS_OPTIONS: string[] = [ALL, "fail", "pass"];

function CopyableFixCli({ check }: { check: CISBenchmarkCheck }) {
  const [copied, setCopied] = useState(false);
  const cli = check.fix_cli;

  const onCopy = useCallback(async () => {
    if (!cli) return;
    try {
      await navigator.clipboard.writeText(cli);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard can be unavailable (insecure context / denied permission);
      // fail quietly rather than crash the drill-down.
      setCopied(false);
    }
  }, [cli]);

  if (!cli) {
    return (
      <div className="text-xs text-zinc-500">
        No copy-pasteable CLI fix — use the console path below.
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2 text-xs text-zinc-500">
        <Terminal className="h-3.5 w-3.5" />
        <span>Fix (CLI)</span>
        {check.requires_human_review ? (
          <span
            className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-300"
            data-testid="human-review-badge"
          >
            <ShieldAlert className="h-3 w-3" />
            Human review required
          </span>
        ) : null}
      </div>
      <div className="flex items-start gap-2">
        <pre className="flex-1 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200">
          <code>{cli}</code>
        </pre>
        <button
          type="button"
          onClick={onCopy}
          aria-label={
            check.requires_human_review
              ? "Copy fix command — requires human review before applying"
              : "Copy fix command"
          }
          title={
            check.requires_human_review
              ? "This fix can break production — review before applying"
              : "Copy to clipboard"
          }
          className={`mt-0.5 inline-flex items-center gap-1 rounded-md border px-2 py-1.5 text-xs transition-colors ${
            check.requires_human_review
              ? "border-amber-500/40 text-amber-300 hover:bg-amber-500/10"
              : "border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          }`}
        >
          <Copy className="h-3.5 w-3.5" />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {copied && check.requires_human_review ? (
        <div className="text-[11px] text-amber-400" role="status">
          Copied — review carefully before running; this change can affect production.
        </div>
      ) : null}
    </div>
  );
}

function CheckCard({ check }: { check: CISBenchmarkCheck }) {
  const [open, setOpen] = useState(check.status === "fail");
  const badge = statusBadge(check.status);
  const docs = check.remediation?.docs;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/60">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-zinc-400">{check.check_id}</span>
            <span className="text-sm font-medium text-zinc-100">{check.title}</span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${badge.className}`}>
              <badge.Icon className="h-3 w-3" />
              {badge.label}
            </span>
            <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium capitalize ${severityClass(check.severity)}`}>
              {check.severity}
            </span>
            <span className="rounded border border-zinc-700 bg-zinc-800/40 px-1.5 py-0.5 text-[11px] font-medium text-zinc-300">
              {priorityLabel(check.priority)}
            </span>
            {check.requires_human_review ? (
              <span className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-300">
                <ShieldAlert className="h-3 w-3" />
                Review
              </span>
            ) : null}
            {check.guardrails.map((g) => (
              <span
                key={g}
                className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[11px] font-medium text-cyan-300"
              >
                {g}
              </span>
            ))}
          </div>
        </div>
        {open ? <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-zinc-500" /> : <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-zinc-500" />}
      </button>
      {open ? (
        <div className="space-y-3 border-t border-zinc-800 px-4 py-3">
          {check.evidence ? <p className="text-xs text-zinc-400">{check.evidence}</p> : null}
          <CopyableFixCli check={check} />
          {check.fix_console ? (
            <div className="text-xs text-zinc-400">
              <span className="text-zinc-500">Console path: </span>
              <span className="text-zinc-200">{check.fix_console}</span>
            </div>
          ) : null}
          {docs ? (
            <a
              href={docs}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              Remediation docs
            </a>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function FilterPills<T extends string | number>({
  label,
  options,
  value,
  onChange,
  render,
}: {
  label: string;
  options: T[];
  value: T;
  onChange: (value: T) => void;
  render: (value: T) => string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[11px] uppercase tracking-wider text-zinc-600">{label}</span>
      {options.map((option) => (
        <button
          key={String(option)}
          type="button"
          onClick={() => onChange(option)}
          className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
            value === option ? "bg-zinc-800 text-zinc-100" : "text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300"
          }`}
        >
          {render(option)}
        </button>
      ))}
    </div>
  );
}

/**
 * Cloud CIS benchmark drill-down. Fetches tenant-scoped checks from
 * `GET /v1/cis/checks`, then filters client-side by cloud, status, priority,
 * and guardrail so every fetched check participates in the guardrails filter.
 * Each failed check exposes a copy-pasteable `fix_cli` (with a human-review
 * warning when applicable) or a console path, plus a remediation docs link.
 */
export function CISBenchmarkDetail() {
  const [checks, setChecks] = useState<CISBenchmarkCheck[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [cloud, setCloud] = useState<string>(ALL);
  const [status, setStatus] = useState<string>("fail");
  const [priority, setPriority] = useState<number>(-1);
  const [guardrail, setGuardrail] = useState<string>(ALL);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    // One page covers the full benchmark catalog (well under the 500 cap), so
    // every guardrails/priority filter sees all checks rather than a slice.
    api
      .listCisBenchmarkChecks({ limit: 500 })
      .then((response) => {
        if (cancelled) return;
        setChecks((response.checks ?? []).map(normalizeCheck));
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(userFacingApiErrorMessage(err, "Could not load cloud CIS benchmark checks."));
        setChecks(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const cloudOptions = useMemo(() => {
    const present = new Set((checks ?? []).map((c) => c.cloud));
    return [ALL, ...Object.keys(CLOUD_LABELS).filter((c) => present.has(c))];
  }, [checks]);

  const guardrailOptions = useMemo(() => {
    const present = new Set<string>();
    for (const c of checks ?? []) for (const g of c.guardrails) present.add(g);
    return [ALL, ...Array.from(present).sort()];
  }, [checks]);

  const priorityOptions = useMemo(() => {
    const present = new Set<number>();
    for (const c of checks ?? []) if (c.priority > 0) present.add(c.priority);
    return [-1, ...Array.from(present).sort((a, b) => a - b)];
  }, [checks]);

  const visible = useMemo(() => {
    return (checks ?? []).filter((c) => {
      if (cloud !== ALL && c.cloud !== cloud) return false;
      if (status !== ALL && c.status !== status) return false;
      if (priority >= 0 && c.priority !== priority) return false;
      if (guardrail !== ALL && !c.guardrails.includes(guardrail)) return false;
      return true;
    });
  }, [checks, cloud, status, priority, guardrail]);

  if (loading) {
    return (
      <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5" aria-busy="true">
        <SectionHeader />
        <p className="mt-3 text-sm text-zinc-500">Loading cloud CIS benchmark checks…</p>
      </section>
    );
  }

  if (error) {
    return (
      <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
        <SectionHeader />
        <div className="mt-3 flex items-start gap-2 rounded-xl border border-zinc-800 bg-zinc-950/70 p-4 text-sm text-zinc-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <span>{error}</span>
        </div>
      </section>
    );
  }

  const total = checks?.length ?? 0;
  if (total === 0) {
    return (
      <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
        <SectionHeader />
        <div className="mt-3 rounded-xl border border-zinc-800 bg-zinc-950/70 p-5 text-sm text-zinc-500">
          No cloud CIS benchmark checks yet. Run a cloud scan (AWS, Azure, GCP, Snowflake, or Databricks)
          to populate per-check remediation.
        </div>
      </section>
    );
  }

  return (
    <section id="cloud-cis-benchmarks" className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
      <SectionHeader count={total} />
      <div className="mt-4 flex flex-col gap-3 rounded-xl border border-zinc-800 bg-zinc-950/40 p-3 lg:flex-row lg:flex-wrap lg:items-center lg:gap-5">
        <FilterPills
          label="Cloud"
          options={cloudOptions}
          value={cloud}
          onChange={setCloud}
          render={(value) => (value === ALL ? "All" : cloudLabel(value))}
        />
        <FilterPills
          label="Status"
          options={STATUS_OPTIONS}
          value={status}
          onChange={setStatus}
          render={(value) => (value === ALL ? "All" : value === "fail" ? "Failing" : "Passing")}
        />
        <FilterPills
          label="Priority"
          options={priorityOptions}
          value={priority}
          onChange={setPriority}
          render={(value) => (value < 0 ? "All" : `P${value}`)}
        />
        <FilterPills
          label="Guardrail"
          options={guardrailOptions}
          value={guardrail}
          onChange={setGuardrail}
          render={(value) => (value === ALL ? "All" : value)}
        />
      </div>

      <div className="mt-4 space-y-2">
        {visible.length === 0 ? (
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-5 text-sm text-zinc-500">
            No checks match the current filters ({total} total).
          </div>
        ) : (
          <>
            <div className="text-xs text-zinc-500">
              {visible.length} of {total} checks shown
            </div>
            {visible.map((check) => (
              <CheckCard key={`${check.cloud}:${check.check_id}:${check.scan_id}`} check={check} />
            ))}
          </>
        )}
      </div>
    </section>
  );
}

function SectionHeader({ count }: { count?: number | undefined }) {
  return (
    <div className="flex items-center gap-2">
      <Cloud className="h-4 w-4 text-cyan-400" />
      <div>
        <h2 className="text-lg font-semibold text-zinc-100">Cloud CIS Benchmark Drill-down</h2>
        <p className="text-xs text-zinc-500">
          Failed AWS / Azure / GCP / Snowflake / Databricks checks behind CIS Controls v8, with fix guidance.
          {typeof count === "number" ? ` ${count} checks.` : null}
        </p>
      </div>
    </div>
  );
}

export default CISBenchmarkDetail;
