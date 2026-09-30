"use client";

import type { ScanResult } from "@/lib/api";

const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const count = (value: unknown): number | null =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
const label = (value: unknown, fallback: string) => typeof value === "string" && value.trim() ? value.slice(0, 500) : fallback;

/** File metadata is reported evidence, never an authenticated collection receipt. */
export function LocalReportEvidence({ report }: { report: ScanResult }) {
  const run = record(report.scan_run) ? report.scan_run : {};
  const scopes = Array.isArray(run.scopes) ? run.scopes.filter(record) : [];
  const issues = Array.isArray(run.issues) ? run.issues.filter(record) : [];
  const requested = count(run.requested_scope_count);
  const complete = count(run.complete_scope_count);
  const incomplete = count(run.incomplete_scope_count);
  const countsPresent = [run.requested_scope_count, run.complete_scope_count, run.incomplete_scope_count].some((value) => value !== undefined);
  const countsConsistent = requested !== null && complete !== null && incomplete !== null && complete + incomplete === requested;
  const scopeGap = scopes.some((scope) => scope.requested !== false && scope.status !== "complete");
  const issueGap = issues.some((issue) => issue.affects_coverage === true);
  const malformedDetails = (run.scopes !== undefined && (!Array.isArray(run.scopes) || run.scopes.some((scope) => !record(scope))))
    || (run.issues !== undefined && (!Array.isArray(run.issues) || run.issues.some((issue) => !record(issue))));
  const inconsistent = malformedDetails || (countsPresent && !countsConsistent)
    || (run.outcome === "complete" && ((incomplete ?? 0) > 0 || scopeGap || issueGap));
  const title = inconsistent ? "Collection metadata inconsistent"
    : run.outcome === "complete" ? "Collection complete"
    : run.outcome === "partial" ? "Collection partial"
    : run.outcome === "failed" ? "Collection failed" : "Collection coverage unknown";
  const captured = report.scan_timestamp ?? report.generated_at;
  const timestamp = typeof captured === "string" ? new Date(captured) : null;
  const sources = Array.isArray(report.scan_sources) ? report.scan_sources.filter((source) => typeof source === "string") : [];

  return (
    <section aria-label="Imported collection evidence" className="rounded-xl border border-outline bg-surface p-4 text-sm [overflow-wrap:anywhere]">
      <h2 className="font-semibold">{title}</h2>
      <p className="mt-1 text-ink-secondary">Reported by this file; provenance and freshness have not been verified by the control plane.</p>
      <p className="mt-2 text-ink-secondary">{countsConsistent
        ? `${complete} of ${requested} requested scopes complete · ${incomplete} incomplete`
        : "Scope denominator unavailable or inconsistent."}</p>
      <p className="mt-2 font-medium text-amber-800 dark:text-amber-300">An empty finding list is not a clean security verdict. Collection status covers only the requested scope.</p>
      <details className="mt-3 border-t border-outline pt-3">
        <summary className="cursor-pointer font-medium">Collection details · {scopes.length} scope records · {issues.length} issues</summary>
        <div className="mt-3 space-y-2 text-xs text-ink-secondary">
          <p>Captured: {timestamp && !Number.isNaN(timestamp.getTime()) ? timestamp.toLocaleString() : "Not reported or invalid"}</p>
          <p>Sources: {sources.length ? sources.slice(0, 20).map((source) => source.slice(0, 100)).join(", ") : "Not reported"}</p>
          {sources.length > 20 ? <p>Showing 20 of {sources.length} source labels. Review the original file for the remainder.</p> : null}
          {scopes.slice(0, 20).map((scope, index) => <p key={index}>
            {label(scope.name, "Unnamed scope")}: {label(scope.status, "unknown")}{scope.requested === false ? " (not requested)" : ""}
          </p>)}
          {scopes.length > 20 ? <p>Showing 20 of {scopes.length} scope records. Review the original file for the remainder.</p> : null}
          {issues.slice(0, 5).map((issue, index) => <p key={index}>{label(issue.code, "Collection issue")}: {label(issue.message, "No detail reported")}</p>)}
          {issues.length > 5 ? <p>Showing 5 of {issues.length} issues. Review the original file for the remainder.</p> : null}
          <p>Preview is browser-local. No graph snapshot or control-plane records were created by this import.</p>
        </div>
      </details>
    </section>
  );
}
