"use client";

import Link from "next/link";
import { CheckCircle2, Download, FolderTree, GitBranch, Info } from "lucide-react";

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
  artifactLabel,
  onDownloadArtifact,
}: {
  scanId: string;
  repoUrl: string;
  result: ScanResult;
  artifactLabel: string;
  onDownloadArtifact: () => void;
}) {
  const surfaces = deriveRepoSurfaceEvidence(result);
  const foundCount = surfaces.filter(
    (surface) => surface.state === "found" || surface.state === "findings" || surface.state === "clean",
  ).length;
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
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Mini label="Surfaces with evidence" value={String(foundCount)} />
        <Mini label="Directories" value={stats.directories != null ? String(stats.directories) : "—"} />
        <Mini label="Packages" value={stats.packages != null ? String(stats.packages) : "—"} />
        <Mini label="Lockfiles" value={stats.lockfiles != null ? String(stats.lockfiles) : "—"} />
      </div>

      <div className="mt-4" aria-labelledby="repo-evidence-journey-heading">
        <h3 id="repo-evidence-journey-heading" className="text-xs font-semibold text-[color:var(--foreground)]">
          Repository evidence journey
        </h3>
        <ol className="mt-2 grid gap-2 md:grid-cols-3">
          <li className="flex min-h-16 items-center gap-2 rounded-lg border border-emerald-600/30 bg-emerald-500/10 px-3 py-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-300" />
            <div>
              <p className="text-xs font-semibold text-[color:var(--foreground)]">1. Scan complete</p>
              <p className="text-[10px] text-[color:var(--text-secondary)]">Static evidence collected</p>
            </div>
          </li>
          <li className="flex min-h-16 items-center rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
            <button
              type="button"
              onClick={onDownloadArtifact}
              className="inline-flex items-center gap-2 text-left text-xs font-semibold text-cyan-800 transition hover:text-cyan-600 dark:text-cyan-200 dark:hover:text-cyan-100"
            >
              <Download className="h-4 w-4 shrink-0" />
              Download {artifactLabel}
            </button>
          </li>
          <li className="flex min-h-16 items-center rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
            <Link
              href={repoGraphHref(scanId)}
              className="inline-flex items-center gap-2 text-xs font-semibold text-emerald-700 transition hover:text-emerald-600 dark:text-emerald-200 dark:hover:text-emerald-100"
            >
              <GitBranch className="h-4 w-4 shrink-0" />
              Explore repository context graph
            </Link>
          </li>
        </ol>
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
              title={[surface.detail, surface.statusDetail].filter(Boolean).join(" — ")}
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] ${
                surface.state === "found" || surface.state === "findings" || surface.state === "clean"
                  ? "border-emerald-600/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-100"
                  : surface.state === "failed"
                    ? "border-red-600/40 bg-red-500/10 text-red-700 dark:text-red-200"
                    : surface.state === "skipped"
                      ? "border-amber-600/40 bg-amber-500/10 text-amber-700 dark:text-amber-200"
                  : "border-dashed border-[color:var(--border-subtle)] text-[color:var(--text-tertiary)]"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  surface.state === "found" || surface.state === "findings" || surface.state === "clean"
                    ? "bg-emerald-400"
                    : surface.state === "failed"
                      ? "bg-red-400"
                      : surface.state === "skipped"
                        ? "bg-amber-400"
                        : "bg-[color:var(--border-strong)]"
                }`}
                aria-hidden
              />
              {surface.label}
              {surface.id === "sast" && surface.state !== "idle" && (
                <span className="font-mono uppercase tracking-wide">{surface.state}</span>
              )}
            </span>
          ))}
        </div>
        <p className="mt-2 flex items-start gap-1.5 text-[11px] text-[color:var(--text-tertiary)]">
          <Info className="mt-0.5 h-3 w-3 shrink-0" />
          Solid chips have evidence in this result. SAST reports its execution outcome explicitly; skipped and failed are
          never shown as clean. Dashed chips are catalog entries that produced no signal on this clone.
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
