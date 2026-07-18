"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle, ChevronDown, ChevronRight, ShieldCheck, XCircle } from "lucide-react";

import { api } from "@/lib/api";
import type { Nist80053CatalogControl, Nist80053DrillResponse, Nist80053Family } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { isNotEvaluated, postureLabel, statusColor } from "@/components/compliance-status";
import { StatStrip, type StatStripItem } from "@/components/stat-strip";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { ICON_SIZE } from "@/lib/icon-sizes";

const ALL = "all";
const STATUS_OPTIONS: string[] = [ALL, "fail", "error", "warning", "pass"];

function statusBadge(status: string): { label: string; className: string; Icon: typeof CheckCircle } {
  switch (status) {
    case "pass":
      return { label: "Pass", className: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10", Icon: CheckCircle };
    case "fail":
      return { label: "Fail", className: "text-red-400 border-red-500/30 bg-red-500/10", Icon: XCircle };
    case "warning":
      return { label: "Warn", className: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10", Icon: AlertTriangle };
    case "error":
      return { label: "Error", className: "text-orange-400 border-orange-500/30 bg-orange-500/10", Icon: AlertTriangle };
    case "not_evaluated":
      return {
        label: "Not evaluated",
        className: "text-[color:var(--text-tertiary)] border-[color:var(--border-strong)] bg-[color:var(--surface-muted)]/40",
        Icon: ChevronRight,
      };
    default:
      return {
        label: status || "Unknown",
        className: "text-[color:var(--text-secondary)] border-[color:var(--border-strong)] bg-[color:var(--surface-muted)]/40",
        Icon: ChevronRight,
      };
  }
}

function nistFamily(controlId: string): string {
  return controlId.split("-", 1)[0] ?? controlId;
}

function FilterPills({
  options,
  value,
  onChange,
  render,
}: {
  options: string[];
  value: string;
  onChange: (value: string) => void;
  render: (value: string) => string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {options.map((option) => (
        <button
          key={option}
          type="button"
          onClick={() => onChange(option)}
          className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
            value === option
              ? "bg-[color:var(--surface-muted)] text-[color:var(--foreground)]"
              : "text-[color:var(--text-tertiary)] hover:bg-[color:var(--surface-muted)] hover:text-[color:var(--text-secondary)]"
          }`}
        >
          {render(option)}
        </button>
      ))}
    </div>
  );
}

function ControlList({ controls }: { controls: Nist80053CatalogControl[] }) {
  const columns: DataTableColumn<Nist80053CatalogControl>[] = [
    {
      key: "control_id",
      header: "Control",
      width: "10rem",
      cell: (c) => (
        <div className="min-w-0">
          <div className="font-mono text-xs font-medium text-[color:var(--foreground)]">{c.control_id}</div>
          <div className="truncate text-[11px] text-[color:var(--text-tertiary)]">{c.title ?? "Untitled control"}</div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "7rem",
      cell: (c) => {
        const badge = statusBadge(c.status);
        return (
          <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${badge.className}`}>
            <badge.Icon className="h-3 w-3" />
            {badge.label}
          </span>
        );
      },
    },
    {
      key: "findings",
      header: "Findings",
      align: "right",
      width: "5rem",
      cell: (c) => (
        <span className={c.findings > 0 ? "font-semibold text-[color:var(--foreground)]" : "text-[color:var(--text-tertiary)]"}>
          {c.findings}
        </span>
      ),
    },
    {
      key: "evidencing_checks",
      header: "Evidencing checks (vendor-asserted)",
      cell: (c) =>
        c.evidencing_checks.length === 0 ? (
          <span className="text-[11px] text-[color:var(--text-tertiary)]">—</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {c.evidencing_checks.map((check) => (
              <span
                key={check}
                className="rounded border border-[color:var(--border-strong)] bg-[color:var(--surface-muted)]/40 px-1.5 py-0.5 text-[11px] font-medium text-[color:var(--text-secondary)]"
              >
                {check}
              </span>
            ))}
          </div>
        ),
    },
    {
      key: "iso_27001_derived",
      header: "ISO 27001 Annex A (derived, IDs only)",
      cell: (c) =>
        c.iso_27001_derived.length === 0 ? (
          <span className="text-[11px] text-[color:var(--text-tertiary)]">—</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {c.iso_27001_derived.map((id) => (
              <span
                key={id}
                className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[11px] font-medium text-cyan-700 dark:text-cyan-300"
              >
                {id}
              </span>
            ))}
          </div>
        ),
    },
  ];

  return (
    <DataTable
      rows={controls}
      rowKey={(c) => c.control_id}
      columns={columns}
      maxHeight="20rem"
      caption="NIST SP 800-53 controls"
      empty="No controls match the current filters."
    />
  );
}

function FamilyGroup({
  family,
  controls,
}: {
  family: Nist80053Family;
  controls: Nist80053CatalogControl[];
}) {
  const [open, setOpen] = useState(false);
  const Chevron = open ? ChevronDown : ChevronRight;

  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-label={`${family.family} family — ${controls.length} evaluated of ${family.total} controls`}
        className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left"
      >
        <span className="flex min-w-0 items-center gap-2">
          <Chevron className={`${ICON_SIZE.sm} shrink-0 text-[color:var(--text-tertiary)]`} aria-hidden="true" />
          <span className="font-mono text-sm font-semibold text-[color:var(--foreground)]">{family.family}</span>
          <span className="text-xs text-[color:var(--text-tertiary)]">
            {family.evaluated} of {family.total} evaluated
          </span>
        </span>
        <span className="flex shrink-0 items-center gap-1.5 text-[11px]">
          {family.fail > 0 ? <span className="text-red-400">{family.fail} fail</span> : null}
          {family.warning > 0 ? <span className="text-yellow-400">{family.warning} warn</span> : null}
          {family.error > 0 ? <span className="text-orange-400">{family.error} error</span> : null}
          {family.pass > 0 ? <span className="text-emerald-400">{family.pass} pass</span> : null}
        </span>
      </button>
      {open ? (
        <div className="border-t border-[color:var(--border-subtle)] p-3">
          <ControlList controls={controls} />
        </div>
      ) : null}
    </div>
  );
}

/**
 * NIST SP 800-53 Rev 5 catalog drill: vendor-asserted per-control status,
 * evidencing checks, and ISO 27001 Annex A attribution (by ID only), grouped
 * by family for scale over the ~1000-control catalog. Fetches its own data
 * from `GET /v1/compliance/nist-800-53` (the same summary the `/v1/compliance`
 * `nist_800_53_catalog` line reports — one source of truth), so the exec
 * buckets shown here always reconcile with the headline elsewhere on the page.
 * Defaults to evaluated controls only; `include_not_evaluated` is an explicit
 * opt-in toggle so the full catalog is never dumped by default.
 */
export function Nist80053CatalogDetail() {
  const [drill, setDrill] = useState<Nist80053DrillResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>(ALL);
  const [includeNotEvaluated, setIncludeNotEvaluated] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    void api
      .getNist80053Catalog(includeNotEvaluated ? { include_not_evaluated: true } : {})
      .then((response) => {
        if (cancelled) return;
        setDrill(response);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(userFacingApiErrorMessage(err, "Could not load the NIST SP 800-53 catalog drill."));
        setDrill(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [includeNotEvaluated]);

  const visibleControls = useMemo(() => {
    if (!drill) return [];
    if (statusFilter === ALL) return drill.controls;
    return drill.controls.filter((c) => c.status === statusFilter);
  }, [drill, statusFilter]);

  const grouped = useMemo(() => {
    if (!drill) return [];
    const byFamily = new Map<string, Nist80053CatalogControl[]>();
    for (const control of visibleControls) {
      const fam = nistFamily(control.control_id);
      const bucket = byFamily.get(fam) ?? [];
      bucket.push(control);
      byFamily.set(fam, bucket);
    }
    const familyMeta = new Map(drill.families.map((f) => [f.family, f]));
    return Array.from(byFamily.entries())
      .filter(([, controls]) => controls.length > 0)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([family, controls]) => ({
        family: familyMeta.get(family) ?? {
          family,
          total: controls.length,
          evaluated: controls.length,
          pass: 0,
          fail: 0,
          warning: 0,
          error: 0,
          not_evaluated: 0,
        },
        controls,
      }));
  }, [drill, visibleControls]);

  if (loading) {
    return (
      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5" aria-busy="true">
        <Header />
        <p className="mt-3 text-sm text-[color:var(--text-tertiary)]">Loading NIST SP 800-53 catalog…</p>
      </section>
    );
  }

  if (error) {
    return (
      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5">
        <Header />
        <div className="mt-3 flex items-start gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 text-sm text-[color:var(--text-secondary)]">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <span>{error}</span>
        </div>
      </section>
    );
  }

  if (!drill) return null;

  const { summary } = drill;
  const noData = isNotEvaluated(drill.status) && summary.evaluated === 0;

  const execItems: StatStripItem[] = [
    {
      label: "Score",
      value: noData ? "—" : `${drill.score}%`,
    },
    { label: "Evaluated", value: summary.evaluated.toLocaleString() },
    { label: "Not evaluated", value: summary.not_evaluated.toLocaleString() },
    { label: "Error", value: summary.error, accent: summary.error > 0 ? "warn" : "neutral" },
    { label: "Coverage", value: `${summary.coverage_pct}%` },
  ];

  return (
    <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5">
      <Header status={drill.status} />
      <StatStrip items={execItems} className="mt-3" data-testid="nist-800-53-exec-strip" />

      {noData ? (
        <div className="mt-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5 text-sm text-[color:var(--text-tertiary)]">
          No NIST SP 800-53 controls have been evaluated yet. Run scans that map CVE/CWE findings or cloud CIS
          checks to populate this catalog.
        </div>
      ) : (
        <>
          <div className="mt-4 flex flex-col gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3 lg:flex-row lg:flex-wrap lg:items-center lg:justify-between lg:gap-3">
            <FilterPills
              options={STATUS_OPTIONS}
              value={statusFilter}
              onChange={setStatusFilter}
              render={(value) => (value === ALL ? "All" : statusBadge(value).label)}
            />
            <button
              type="button"
              onClick={() => setIncludeNotEvaluated((v) => !v)}
              className="shrink-0 rounded-md border border-[color:var(--border-strong)] px-2.5 py-1 text-xs font-medium text-[color:var(--text-secondary)] transition-colors hover:bg-[color:var(--surface-muted)]"
            >
              {includeNotEvaluated
                ? `Showing not-evaluated (${summary.not_evaluated.toLocaleString()})`
                : "Show not-evaluated controls"}
            </button>
          </div>

          <div className="mt-4 space-y-2">
            {grouped.length === 0 ? (
              <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5 text-sm text-[color:var(--text-tertiary)]">
                No controls match the current filters.
              </div>
            ) : (
              grouped.map(({ family, controls }) => (
                <FamilyGroup key={family.family} family={family} controls={controls} />
              ))
            )}
          </div>
        </>
      )}
    </section>
  );
}

function Header({ status }: { status?: string | undefined }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-cyan-400" />
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold text-[color:var(--foreground)]">NIST SP 800-53 Rev 5</h2>
            {status ? (
              <span
                className={`text-xs font-medium ${statusColor(status)}`}
                data-testid="nist-800-53-status"
              >
                {postureLabel(status)}
              </span>
            ) : null}
          </div>
          <p className="text-xs text-[color:var(--text-tertiary)]">
            Vendor-asserted catalog scoring — check→control mapping and ISO 27001 attribution are curated, not an
            authority-published crosswalk.
          </p>
        </div>
      </div>
    </div>
  );
}

export default Nist80053CatalogDetail;
