"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { buildFindingReturnHref } from "@/lib/finding-investigation-href";

/** Navigation provenance is not a claim that this graph proves the finding. */
export function FindingInvestigationContext() {
  const params = useSearchParams();
  const href = buildFindingReturnHref(params);
  if (!href) return null;
  const finding = params.get("finding") || params.get("related_finding");
  const sourceScan = params.get("finding_scan") || params.get("scan");
  const changedSnapshot = sourceScan && params.get("scan") && sourceScan !== params.get("scan");
  return (
    <aside aria-label="Finding investigation context" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-outline bg-surface p-3 text-sm">
      <div className="min-w-0 space-y-1">
        <p className="font-medium">Finding context <code className="break-all text-xs">{finding}</code></p>
        {sourceScan && <p className="break-all text-xs text-ink-secondary">Source snapshot: {sourceScan}</p>}
        <p className="text-xs text-ink-secondary">Graph relationships require their own evidence; this link preserves your finding selection.</p>
        {changedSnapshot && <p role="note" className="text-xs text-ink-secondary">Viewing a different graph snapshot. Return opens the original finding snapshot.</p>}
      </div>
      <Link href={href} className="shrink-0 rounded-lg border border-outline px-3 py-2 text-emerald-800 dark:text-emerald-300">Return to finding</Link>
    </aside>
  );
}
