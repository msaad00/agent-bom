"use client";

import { useMemo } from "react";
import type { GraphHistorySnapshot } from "@/lib/api";

export type DriftScrubberPair = {
  oldScanId: string;
  newScanId: string;
};

function changeTotal(summary: GraphHistorySnapshot["diff_summary"] | undefined): number {
  if (!summary) return 0;
  return (
    (summary.nodes_added ?? 0) +
    (summary.nodes_removed ?? 0) +
    (summary.nodes_changed ?? 0) +
    (summary.edges_added ?? 0) +
    (summary.edges_removed ?? 0)
  );
}

function criticalPill(summary: GraphHistorySnapshot["diff_summary"] | undefined): boolean {
  if (!summary) return false;
  return (summary.nodes_removed ?? 0) + (summary.edges_removed ?? 0) > 0 || (summary.nodes_changed ?? 0) >= 3;
}

/**
 * Scan-pair scrubber for the Asset Drift lens.
 * Threshold = "what changed" (honest adjacent diffs), not SLA claims.
 */
export function GraphDriftTimeline({
  snapshots,
  selected,
  onSelect,
  loading = false,
}: {
  snapshots: GraphHistorySnapshot[];
  selected: DriftScrubberPair | null;
  onSelect: (pair: DriftScrubberPair) => void;
  loading?: boolean;
}) {
  const pairs = useMemo(() => {
    const items: Array<{
      oldScanId: string;
      newScanId: string;
      summary: GraphHistorySnapshot["diff_summary"];
      createdAt: string;
    }> = [];
    for (const snapshot of snapshots) {
      const baseline = snapshot.diff_baseline_scan_id;
      if (!baseline) continue;
      items.push({
        oldScanId: baseline,
        newScanId: snapshot.scan_id,
        summary: snapshot.diff_summary,
        createdAt: snapshot.created_at ?? "",
      });
    }
    return items;
  }, [snapshots]);

  if (loading) {
    return (
      <div
        data-testid="graph-drift-timeline"
        className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-xs text-[color:var(--text-tertiary)]"
      >
        Loading drift history…
      </div>
    );
  }

  if (pairs.length === 0) {
    return (
      <div
        data-testid="graph-drift-timeline"
        className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-xs text-[color:var(--text-tertiary)]"
      >
        No adjacent scan pairs yet. Run another scan to compare what changed.
      </div>
    );
  }

  return (
    <div
      data-testid="graph-drift-timeline"
      className="space-y-2 rounded-xl border border-orange-500/25 bg-orange-500/5 p-3"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-orange-800 dark:text-orange-200">
          Drift timeline
        </p>
        <p className="text-[11px] text-[color:var(--text-tertiary)]">
          Threshold = what changed between adjacent snapshots
        </p>
      </div>
      <div className="flex gap-2 overflow-x-auto pb-1">
        {pairs.map((pair) => {
          const active =
            selected?.oldScanId === pair.oldScanId && selected?.newScanId === pair.newScanId;
          const total = changeTotal(pair.summary);
          const critical = criticalPill(pair.summary);
          return (
            <button
              key={`${pair.oldScanId}->${pair.newScanId}`}
              type="button"
              onClick={() =>
                onSelect({ oldScanId: pair.oldScanId, newScanId: pair.newScanId })
              }
              className={`min-w-[9.5rem] shrink-0 rounded-lg border px-3 py-2 text-left transition ${
                active
                  ? "border-orange-400/70 bg-orange-500/15 ring-1 ring-orange-400/50"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] hover:border-orange-400/40"
              }`}
            >
              <div className="font-mono text-[11px] text-[color:var(--foreground)]">
                {pair.newScanId.slice(0, 8)}…
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-1">
                {critical ? (
                  <span className="rounded border border-red-500/40 bg-red-500/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-red-700 dark:text-red-200">
                    Critical
                  </span>
                ) : (
                  <span className="rounded border border-[color:var(--border-subtle)] px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
                    Changed
                  </span>
                )}
                <span className="font-mono text-[10px] text-[color:var(--text-secondary)]">
                  {total} Δ
                </span>
              </div>
              <div className="mt-1 text-[10px] text-[color:var(--text-tertiary)]">
                vs {pair.oldScanId.slice(0, 8)}…
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
