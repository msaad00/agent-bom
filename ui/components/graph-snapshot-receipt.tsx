"use client";

import Link from "next/link";
import type { GraphSnapshot } from "@/lib/api";

/** Metadata for the selected snapshot, never a claim about upstream freshness. */
export function GraphSnapshotReceipt({ snapshot }: { snapshot: GraphSnapshot | null }) {
  const captured = snapshot?.created_at ? new Date(snapshot.created_at) : null;
  return (
    <details className="rounded-xl border border-outline bg-surface px-4 py-3 text-xs" aria-label="Graph snapshot evidence">
      <summary className="cursor-pointer font-medium text-foreground">Snapshot evidence <span className="ml-2 font-normal text-ink-secondary">Scope, provenance &amp; assessment limits</span></summary>
      <div className="mt-3 grid gap-3 text-ink-secondary sm:grid-cols-2">
        <div className="min-w-0 space-y-1">
          <p>Source: {snapshot?.snapshot_kind === "scan" ? "Scan snapshot" : snapshot?.snapshot_kind === "correlation" ? "Correlated evidence" : "Source kind not reported"}</p>
          <p className="break-all">Snapshot ID: {snapshot?.scan_id || "Unavailable"}</p>
          <p>Captured: {captured && !Number.isNaN(captured.getTime()) ? captured.toLocaleString() : "Unavailable"}</p>
          {snapshot?.snapshot_kind === "scan" ? <Link className="inline-block py-2 font-medium text-foreground underline underline-offset-4" href={`/findings?scan=${encodeURIComponent(snapshot.scan_id)}`}>Review findings for this snapshot</Link> : null}
        </div>
        <div className="space-y-2">
          <p>Loaded scope describes the graph response, not assessment coverage. Expand a neighborhood or adjust filters to investigate a bounded set of relationships.</p>
          <p>The capture time does not establish upstream freshness. Recorded relationships and available authority do not prove execution, exploitation, or a successful control.</p>
          <p>Inspect each relationship’s evidence and missing assessments before taking action.</p>
        </div>
      </div>
    </details>
  );
}
