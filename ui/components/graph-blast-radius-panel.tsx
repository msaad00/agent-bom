"use client";

import { Loader2, Radar } from "lucide-react";
import type { BlastRadiusState } from "@/lib/graph-blast-investigation";
import { prettifyReachabilityType } from "@/lib/graph-reachability";

export function BlastRadiusPanel({
  summary,
  loading,
  error,
  onClear,
}: {
  summary: BlastRadiusState | null;
  loading: boolean;
  error: string | null;
  onClear: () => void;
}) {
  return (
    <div className="mt-3 rounded-2xl border border-violet-500/30 bg-violet-500/10 p-3 text-xs text-foreground">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Radar className="mt-0.5 h-4 w-4 text-violet-700 dark:text-violet-300" />
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-violet-700 dark:text-violet-300">
              Blast radius
            </p>
            <p className="mt-1 text-sm font-medium text-foreground">
              {summary
                ? `${summary.completeness?.complete === true ? "" : "At least "}${summary.affectedCount} upstream related node${summary.affectedCount === 1 ? "" : "s"} connected to ${summary.rootLabel}`
                : loading ? "Computing blast radius" : "Blast radius unavailable"}
            </p>
            {summary && (
              <p className="mt-1 text-[11px] text-ink-secondary">
                Reverse-dependency reach · up to {summary.maxDepthReached} hop
                {summary.maxDepthReached === 1 ? "" : "s"}. Graph relationships do not establish compromise.
              </p>
            )}
            {summary && (
              <p className="mt-1 text-[11px] text-ink-secondary">
                {summary.visibleRelatedCount} related nodes shown on this bounded map. Collection coverage is unknown.
                {summary.completeness?.complete !== true && " The related-node count is a lower bound; more may exist beyond the traversal limits."}
              </p>
            )}
            {error && (
              <p className="mt-1 text-[11px] text-amber-800 dark:text-amber-200">{error}</p>
            )}
            {loading && (
              <p className="mt-1 flex items-center gap-1 text-[11px] text-violet-700 dark:text-violet-200">
                <Loader2 className="h-3 w-3 animate-spin" />
                Tracing upstream graph connections
              </p>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="graph-chip-violet"
        >
          Return to summary
        </button>
      </div>

      {summary && Object.keys(summary.countsByType).length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-xs text-ink-secondary">Related nodes by type ({Object.keys(summary.countsByType).length})</summary>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {Object.entries(summary.countsByType)
              .sort((left, right) => right[1] - left[1])
              .map(([type, count]) => (
                <span
                  key={type}
                  className="rounded border border-violet-400/20 bg-violet-500/10 px-1.5 py-0.5 text-[10px] text-foreground"
                >
                  {prettifyReachabilityType(type)}: {count}
                </span>
              ))}
          </div>
        </details>
      )}

      {summary && summary.affectedCount === 0 && (
        <p className="mt-2 text-ink-secondary">
          No upstream nodes returned within this traversal scope.
        </p>
      )}
    </div>
  );
}
