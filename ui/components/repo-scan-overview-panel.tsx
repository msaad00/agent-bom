"use client";

import Link from "next/link";
import { FolderTree, GitBranch, Info } from "lucide-react";

import type { ScanResult } from "@/lib/api-types";
import {
  deriveRepoSurfaceEvidence,
  repoGraphHref,
  repoInventoryStats,
} from "@/lib/repo-scan-overview";

export function RepoScanOverviewPanel({
  scanId,
  repoUrl,
  result,
}: {
  scanId: string;
  repoUrl: string;
  result: ScanResult;
}) {
  const surfaces = deriveRepoSurfaceEvidence(result);
  const foundCount = surfaces.filter((surface) => surface.state === "found").length;
  const stats = repoInventoryStats(result);

  return (
    <section
      className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4"
      data-testid="repo-scan-overview"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
            Repo overview
          </p>
          <h2 className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">Static inventory from this clone</h2>
          <p className="mt-1 break-all font-mono text-xs text-[color:var(--text-secondary)]">{repoUrl}</p>
          <p className="mt-2 max-w-2xl text-xs text-[color:var(--text-tertiary)]">
            Public URLs need no token. Private repos use a server-side{" "}
            <code className="text-[color:var(--text-secondary)]">AGENT_BOM_REPO_SCAN_TOKEN</code> or a local{" "}
            <code className="text-[color:var(--text-secondary)]">--project</code> path — static parse only, not dynamic
            app testing.
          </p>
        </div>
        <Link
          href={repoGraphHref(scanId)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/40 bg-emerald-950/30 px-3 py-1.5 text-xs font-medium text-emerald-200 hover:border-emerald-500/50"
        >
          <GitBranch className="h-3.5 w-3.5" />
          Open folder graph
        </Link>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Mini label="Surfaces with evidence" value={String(foundCount)} />
        <Mini label="Directories" value={stats.directories != null ? String(stats.directories) : "—"} />
        <Mini label="Packages" value={stats.packages != null ? String(stats.packages) : "—"} />
        <Mini label="Lockfiles" value={stats.lockfiles != null ? String(stats.lockfiles) : "—"} />
      </div>

      <div className="mt-4">
        <div className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
          <FolderTree className="h-3 w-3" />
          Surface coverage
        </div>
        <div className="flex flex-wrap gap-1.5">
          {surfaces.map((surface) => (
            <span
              key={surface.id}
              title={surface.detail}
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] ${
                surface.state === "found"
                  ? "border-emerald-600/40 bg-emerald-500/10 text-emerald-100"
                  : "border-dashed border-[color:var(--border-subtle)] text-[color:var(--text-tertiary)]"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  surface.state === "found" ? "bg-emerald-400" : "bg-[color:var(--border-strong)]"
                }`}
                aria-hidden
              />
              {surface.label}
            </span>
          ))}
        </div>
        <p className="mt-2 flex items-start gap-1.5 text-[11px] text-[color:var(--text-tertiary)]">
          <Info className="mt-0.5 h-3 w-3 shrink-0" />
          Solid chips have evidence in this result. Dashed chips are in the catalog but produced no signal on this clone.
        </p>
      </div>
    </section>
  );
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
      <p className="text-[10px] uppercase tracking-wide text-[color:var(--text-tertiary)]">{label}</p>
      <p className="mt-0.5 font-mono text-sm font-semibold text-[color:var(--foreground)]">{value}</p>
    </div>
  );
}
