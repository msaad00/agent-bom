"use client";

import { useEffect, useMemo, useState } from "react";
import { Layers, Loader2, ShieldAlert } from "lucide-react";

import { api } from "@/lib/api";
import type { NistCatalogControl, NistCatalogDrill } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { Collapsible } from "@/components/collapsible";
import { isNotEvaluated, postureLabel, StatusIcon, statusColor } from "@/components/compliance-status";

type StatusFilter = "all" | "fail" | "warning" | "error" | "pass";

const STATUS_LABEL: Record<string, string> = {
  pass: "Pass",
  fail: "Fail",
  warning: "Warn",
  error: "Error",
  not_evaluated: "Not evaluated",
};

const FILTER_TABS: { key: StatusFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "fail", label: "Fail" },
  { key: "warning", label: "Warn" },
  { key: "error", label: "Error" },
  { key: "pass", label: "Pass" },
];

/** One compact honest bucket tile — value renders as its own node so the count
 *  is always legible and reconciles 1:1 with the API summary. */
function BucketTile({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: "success" | "warn" | "danger" | "error" | "neutral";
}) {
  const color =
    accent === "success"
      ? "text-[color:var(--status-success)]"
      : accent === "warn"
        ? "text-[color:var(--status-warn)]"
        : accent === "danger"
          ? "text-[color:var(--status-danger)]"
          : accent === "error"
            ? "text-[color:var(--status-warn)]"
            : "text-[color:var(--foreground)]";
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
      <div className={`text-lg font-semibold tabular-nums ${color}`}>{value}</div>
      <div className="text-[11px] uppercase tracking-wide text-[color:var(--text-tertiary)]">{label}</div>
    </div>
  );
}

function ControlStatusBadge({ status }: { status: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <StatusIcon status={status} className="h-3.5 w-3.5" />
      <span className={`text-xs font-medium ${statusColor(status)}`}>{STATUS_LABEL[status] ?? status}</span>
    </span>
  );
}

/**
 * Catalog-backed NIST SP 800-53 Rev 5 posture — exec line (score over evaluated,
 * coverage, honest evaluated/not_evaluated/ERROR buckets) drilling to the
 * engineer view (family rollup, per-control evidencing checks, ISO-27001-by-id
 * derived). Consumes `/v1/compliance/nist-800-53`, so every number reconciles
 * 1:1 with the `/v1/compliance` line, the CLI narrative, and the MCP tool (one
 * shared scorer). Scale-aware over the full ~1000-control catalog: the drill
 * leads with a family rollup and lists evaluated controls only until the reader
 * opts into the full catalog — never a mile-long not_evaluated tower.
 */
export function ComplianceNistCatalog() {
  const [drill, setDrill] = useState<NistCatalogDrill | null>(null);
  const [fullControls, setFullControls] = useState<NistCatalogControl[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [familyFilter, setFamilyFilter] = useState<string | null>(null);
  const [showFullCatalog, setShowFullCatalog] = useState(false);
  const [loadingFull, setLoadingFull] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void api
      .getComplianceNist80053()
      .then((d) => {
        if (!cancelled) setDrill(d);
      })
      .catch((err) => {
        if (!cancelled) setError(userFacingApiErrorMessage(err, "NIST 800-53 catalog posture is unavailable."));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleToggleFullCatalog = () => {
    const next = !showFullCatalog;
    setShowFullCatalog(next);
    if (next && !fullControls) {
      setLoadingFull(true);
      void api
        .getComplianceNist80053({ includeNotEvaluated: true })
        .then((d) => setFullControls(d.controls))
        .catch(() => setShowFullCatalog(false))
        .finally(() => setLoadingFull(false));
    }
  };

  const baseControls = useMemo<NistCatalogControl[]>(
    () => (showFullCatalog && fullControls ? fullControls : (drill?.controls ?? [])),
    [showFullCatalog, fullControls, drill],
  );

  const visibleControls = useMemo(() => {
    return baseControls.filter((c) => {
      const matchesStatus = statusFilter === "all" || c.status === statusFilter;
      const matchesFamily = !familyFilter || c.control_id.split("-", 1)[0] === familyFilter;
      return matchesStatus && matchesFamily;
    });
  }, [baseControls, statusFilter, familyFilter]);

  if (loading) {
    return (
      <div
        className="flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 text-sm text-[color:var(--text-tertiary)]"
        data-testid="nist-catalog-loading"
      >
        <Loader2 className="h-4 w-4 animate-spin" /> Loading NIST 800-53 catalog posture…
      </div>
    );
  }

  if (error || !drill) {
    return (
      <div
        className="flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 text-sm text-[color:var(--text-tertiary)]"
        data-testid="nist-catalog-error"
      >
        <ShieldAlert className="h-4 w-4 text-[color:var(--status-warn)]" />
        {error ?? "NIST 800-53 catalog posture is unavailable."}
      </div>
    );
  }

  const s = drill.summary;
  const noData = isNotEvaluated(drill.status) || s.evaluated === 0;
  const isoControls = drill.iso_27001_derived.controls;

  return (
    <div
      className="space-y-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 elev-1"
      data-testid="nist-catalog-panel"
    >
      {/* Exec line */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Layers className="h-4 w-4 text-[color:var(--accent)]" />
            <h3 className="text-sm font-semibold text-[color:var(--foreground)]">{drill.framework_label}</h3>
            <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-[color:var(--text-tertiary)]">
              Vendor-asserted
            </span>
          </div>
          <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
            Full catalog scored independently over evidenced checks —{" "}
            {noData ? (
              "no NIST-mapped evidence yet; connect a cloud account or run a scan to evaluate controls."
            ) : (
              <>
                {s.pass.toLocaleString()} of {s.evaluated.toLocaleString()} evaluated controls passing across{" "}
                {s.catalog_size.toLocaleString()} controls.
              </>
            )}
          </p>
        </div>
        <div className="flex items-center gap-1.5 self-start whitespace-nowrap">
          <StatusIcon status={drill.status} className="h-4 w-4" />
          <span className={`text-sm font-semibold ${statusColor(drill.status)}`}>{postureLabel(drill.status)}</span>
        </div>
      </div>

      {/* Honest bucket strip — reconciles 1:1 with the API summary. */}
      <div
        className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8"
        data-testid="nist-catalog-buckets"
      >
        <BucketTile label="Score" value={noData ? "—" : `${s.score}%`} />
        <BucketTile label="Coverage" value={`${s.coverage_pct}%`} />
        <BucketTile label="Evaluated" value={s.evaluated.toLocaleString()} />
        <BucketTile label="Pass" value={s.pass.toLocaleString()} accent="success" />
        <BucketTile label="Fail" value={s.fail.toLocaleString()} accent="danger" />
        <BucketTile label="Warn" value={s.warning.toLocaleString()} accent="warn" />
        <BucketTile label="Error" value={s.error.toLocaleString()} accent="error" />
        <BucketTile label="Not eval." value={s.not_evaluated.toLocaleString()} accent="neutral" />
      </div>

      {/* Engineer drill */}
      <Collapsible
        title="Control drill (engineer view)"
        subtitle="Family rollup · evidencing checks · ISO 27001 by id"
        defaultOpen={false}
      >
        <div className="space-y-4">
          {/* Family rollup — scale-aware entry over the full catalog. */}
          <div className="overflow-x-auto" data-testid="nist-catalog-families">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[color:var(--text-tertiary)]">
                  <th className="px-2 py-1 font-medium">Family</th>
                  <th className="px-2 py-1 text-right font-medium">Evaluated</th>
                  <th className="px-2 py-1 text-right font-medium">Pass</th>
                  <th className="px-2 py-1 text-right font-medium">Fail</th>
                  <th className="px-2 py-1 text-right font-medium">Error</th>
                  <th className="px-2 py-1 text-right font-medium">Not eval.</th>
                </tr>
              </thead>
              <tbody>
                {drill.families
                  .filter((f) => f.evaluated > 0 || familyFilter === f.family)
                  .map((f) => {
                    const active = familyFilter === f.family;
                    return (
                      <tr
                        key={f.family}
                        onClick={() => setFamilyFilter(active ? null : f.family)}
                        className={`cursor-pointer border-t border-[color:var(--border-subtle)] transition-colors hover:bg-[color:var(--surface-muted)] ${
                          active ? "bg-[color:var(--accent-soft)]" : ""
                        }`}
                      >
                        <td className="px-2 py-1 font-mono font-medium text-[color:var(--foreground)]">{f.family}</td>
                        <td className="px-2 py-1 text-right tabular-nums text-[color:var(--text-secondary)]">
                          {f.evaluated}/{f.total}
                        </td>
                        <td className="px-2 py-1 text-right tabular-nums text-[color:var(--status-success)]">{f.pass}</td>
                        <td className="px-2 py-1 text-right tabular-nums text-[color:var(--status-danger)]">{f.fail}</td>
                        <td className="px-2 py-1 text-right tabular-nums text-[color:var(--status-warn)]">{f.error}</td>
                        <td className="px-2 py-1 text-right tabular-nums text-[color:var(--text-tertiary)]">
                          {f.not_evaluated}
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
            {familyFilter ? (
              <button
                type="button"
                onClick={() => setFamilyFilter(null)}
                className="mt-1 text-[11px] font-medium text-[color:var(--accent)] hover:underline"
              >
                Clear {familyFilter} filter
              </button>
            ) : null}
          </div>

          {/* Controls toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5">
              {FILTER_TABS.map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  onClick={() => setStatusFilter(tab.key)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                    statusFilter === tab.key
                      ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                      : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={handleToggleFullCatalog}
              className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors ${
                showFullCatalog
                  ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                  : "border-[color:var(--border-subtle)] text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
              }`}
            >
              {loadingFull ? "Loading full catalog…" : showFullCatalog ? "Evaluated only" : "Show full catalog"}
            </button>
            <span className="text-[11px] text-[color:var(--text-tertiary)]">
              {visibleControls.length} shown
              {showFullCatalog ? ` of ${s.catalog_size.toLocaleString()}` : ` of ${s.evaluated.toLocaleString()} evaluated`}
            </span>
          </div>

          {/* Controls list */}
          <div className="max-h-[24rem] overflow-y-auto rounded-lg border border-[color:var(--border-subtle)]" data-testid="nist-catalog-controls">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[color:var(--surface-elevated)]">
                <tr className="text-left text-[color:var(--text-tertiary)]">
                  <th className="px-2 py-1.5 font-medium">Control</th>
                  <th className="px-2 py-1.5 font-medium">Status</th>
                  <th className="px-2 py-1.5 font-medium">Evidencing checks</th>
                  <th className="px-2 py-1.5 font-medium">ISO 27001 (derived)</th>
                </tr>
              </thead>
              <tbody>
                {visibleControls.map((c) => (
                  <tr key={c.control_id} className="border-t border-[color:var(--border-subtle)] align-top">
                    <td className="px-2 py-1.5">
                      <div className="font-mono font-medium text-[color:var(--foreground)]">{c.control_id}</div>
                      {c.title ? (
                        <div className="text-[11px] text-[color:var(--text-tertiary)]">{c.title}</div>
                      ) : null}
                    </td>
                    <td className="px-2 py-1.5 whitespace-nowrap">
                      <ControlStatusBadge status={c.status} />
                    </td>
                    <td className="px-2 py-1.5">
                      {c.evidencing_checks.length ? (
                        <div className="flex flex-wrap gap-1">
                          {c.evidencing_checks.map((ck) => (
                            <span
                              key={ck}
                              className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-1.5 py-0.5 font-mono text-[10px] text-[color:var(--text-secondary)]"
                            >
                              {ck}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[color:var(--text-tertiary)]">—</span>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      {c.iso_27001_derived.length ? (
                        <div className="flex flex-wrap gap-1">
                          {c.iso_27001_derived.map((iso) => (
                            <span
                              key={iso}
                              className="rounded border border-[color:var(--border-subtle)] px-1.5 py-0.5 font-mono text-[10px] text-[color:var(--text-tertiary)]"
                            >
                              {iso}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[color:var(--text-tertiary)]">—</span>
                      )}
                    </td>
                  </tr>
                ))}
                {visibleControls.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-2 py-6 text-center text-[color:var(--text-tertiary)]">
                      No controls match the current filters.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>

          {/* ISO attribution — by identifier only, labeled derived from crosswalk. */}
          <div
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3"
            data-testid="nist-catalog-iso"
          >
            <div className="text-[11px] font-semibold uppercase tracking-wide text-[color:var(--text-tertiary)]">
              ISO/IEC 27001 (derived by id from crosswalk)
            </div>
            {isoControls.length ? (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {isoControls.map((iso) => (
                  <span
                    key={iso}
                    className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-1.5 py-0.5 font-mono text-[10px] text-[color:var(--text-secondary)]"
                  >
                    {iso}
                  </span>
                ))}
              </div>
            ) : (
              <p className="mt-1 text-[11px] text-[color:var(--text-tertiary)]">
                No ISO Annex A controls implicated (no failing NIST controls).
              </p>
            )}
            <p className="mt-2 text-[10px] leading-relaxed text-[color:var(--text-tertiary)]">{drill.iso_27001_derived.note}</p>
          </div>
        </div>
      </Collapsible>
    </div>
  );
}
