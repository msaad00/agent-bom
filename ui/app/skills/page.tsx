"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  FileWarning,
  HelpCircle,
  Loader2,
  ScrollText,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";

import { api } from "@/lib/api";
import type {
  SkillsScanFileReport,
  SkillsScanFileStatus,
  SkillsScanReport,
} from "@/lib/api";
import { ApiError } from "@/lib/api-errors";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { Drawer } from "@/components/drawer";
import { PageLaneHeader } from "@/components/page-lane";
import { PaginationBar } from "@/components/pagination-bar";
import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";

// Headless equivalents (§11 human + headless parity) — the page is the human
// surface; these run the SAME shared scanner from the CLI / an agent / CI.
const HEADLESS_CLI = "agent-bom skills scan <path>";
const HEADLESS_API = "POST /v1/skills/scan";
const FILE_PAGE_SIZE = 25;

type StatusChipMeta = {
  label: string;
  icon: typeof CheckCircle2;
  chip: string;
};

// Four-way, theme-safe status chips. `pending` (unsigned/unreviewed) and
// `unavailable` are explicit neutral states — never rendered as an implied pass.
const STATUS_META: Record<SkillsScanFileStatus, StatusChipMeta> = {
  malicious: {
    label: "Malicious",
    icon: ShieldX,
    chip: "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]",
  },
  suspicious: {
    label: "Suspicious",
    icon: ShieldAlert,
    chip: "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
  },
  pending: {
    label: "Pending review",
    icon: HelpCircle,
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]",
  },
  unavailable: {
    label: "Unavailable",
    icon: HelpCircle,
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]",
  },
  clean: {
    label: "Clean",
    icon: ShieldCheck,
    chip: "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
  },
};

const PROVENANCE_META: Record<
  string,
  { label: string; chip: string }
> = {
  verified: {
    label: "Verified",
    chip: "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
  },
  unsigned: {
    label: "Unsigned",
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]",
  },
  bundle_found_but_invalid: {
    label: "Invalid signature",
    chip: "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]",
  },
  missing: {
    label: "Missing",
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]",
  },
};

// Filter facets, worst-first so a scan of many files surfaces risk at the top.
const STATUS_ORDER: SkillsScanFileStatus[] = [
  "malicious",
  "suspicious",
  "pending",
  "unavailable",
  "clean",
];

function fileName(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1] || path;
}

function StatusChip({ status }: { status: SkillsScanFileStatus }) {
  const meta = STATUS_META[status] ?? STATUS_META.pending;
  const Icon = meta.icon;
  return (
    <span
      data-testid="skill-status"
      data-status={status}
      className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${meta.chip}`}
    >
      <Icon className="h-3 w-3" aria-hidden="true" />
      {meta.label}
    </span>
  );
}

function ProvenanceChip({ status }: { status: string }) {
  const meta = PROVENANCE_META[status] ?? {
    label: status,
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]",
  };
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${meta.chip}`}
    >
      {meta.label}
    </span>
  );
}

function SummaryStat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2">
      <div className={`text-lg font-semibold tabular-nums ${tone ?? "text-[color:var(--foreground)]"}`}>
        {value}
      </div>
      <div className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
        {label}
      </div>
    </div>
  );
}

function FileDrawer({ file, onClose }: { file: SkillsScanFileReport; onClose: () => void }) {
  const findings = file.audit?.findings ?? [];
  return (
    <Drawer
      open
      onClose={onClose}
      eyebrow="Skill file"
      title={fileName(file.path)}
      subtitle={file.path}
      headerAside={<StatusChip status={file.status} />}
      ariaLabel={`Skill scan detail for ${file.path}`}
    >
      <div className="space-y-5">
        <section className="grid grid-cols-2 gap-3">
          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
            <div className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
              Content verdict
            </div>
            <div className="mt-1 text-sm font-medium text-[color:var(--foreground)]">
              {file.trust.content_verdict}
            </div>
          </div>
          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
            <div className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
              Handling
            </div>
            <div className="mt-1 text-sm font-medium text-[color:var(--foreground)]">
              {file.trust.review_verdict}
            </div>
          </div>
        </section>

        <section>
          <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            Provenance
          </h3>
          <div className="mt-2 space-y-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[color:var(--text-secondary)]">Status</span>
              <ProvenanceChip status={file.provenance.status} />
            </div>
            {file.provenance.signer ? (
              <div className="flex items-center justify-between gap-2">
                <span className="text-[color:var(--text-secondary)]">Signer</span>
                <span className="font-mono text-[color:var(--foreground)] [overflow-wrap:anywhere]">
                  {file.provenance.signer}
                </span>
              </div>
            ) : null}
            {file.provenance.sha256 ? (
              <div className="flex items-start justify-between gap-2">
                <span className="text-[color:var(--text-secondary)]">SHA-256</span>
                <span className="font-mono text-[10px] text-[color:var(--text-tertiary)] [overflow-wrap:anywhere]">
                  {file.provenance.sha256}
                </span>
              </div>
            ) : null}
          </div>
        </section>

        {file.credential_env_vars.length > 0 ? (
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
              Credential references ({file.credential_env_vars.length})
            </h3>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {file.credential_env_vars.map((cred) => (
                <span
                  key={cred}
                  className="inline-flex items-center rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-1.5 py-0.5 font-mono text-[11px] text-[color:var(--text-secondary)]"
                >
                  {cred}
                </span>
              ))}
            </div>
          </section>
        ) : null}

        <section>
          <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            Findings ({findings.length})
          </h3>
          {findings.length === 0 ? (
            <p className="mt-2 text-xs text-[color:var(--text-tertiary)]">
              No behavioural findings for this file.
            </p>
          ) : (
            <ul className="mt-2 space-y-2">
              {findings.map((finding, idx) => (
                <li
                  key={`${finding.category}-${idx}`}
                  className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                      {finding.severity} · {finding.category}
                    </span>
                  </div>
                  <p className="mt-1 text-sm font-medium text-[color:var(--foreground)]">{finding.title}</p>
                  <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)] [overflow-wrap:anywhere]">
                    {finding.detail}
                  </p>
                  {finding.recommendation ? (
                    <p className="mt-2 text-xs leading-5 text-[color:var(--text-tertiary)] [overflow-wrap:anywhere]">
                      <span className="font-medium text-[color:var(--text-secondary)]">Fix:</span>{" "}
                      {finding.recommendation}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </Drawer>
  );
}

export default function SkillsPage() {
  const [report, setReport] = useState<SkillsScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [targets, setTargets] = useState(".");
  const [scanning, setScanning] = useState(false);
  const [scanNotice, setScanNotice] = useState<string | null>(null);
  const [scanDisabled, setScanDisabled] = useState(false);

  const [statusFilter, setStatusFilter] = useState<SkillsScanFileStatus | "all">("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<SkillsScanFileReport | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .getSkillsScan()
      .then(setReport)
      .catch((e) => setError(userFacingApiErrorMessage(e, "Skills scan could not be loaded")))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const runScan = useCallback(() => {
    const entries = targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (entries.length === 0) return;
    // A path with a filename extension is treated as a file; everything else a
    // directory. The backend resolves either the same way, so this is cosmetic.
    const files = entries.filter((e) => /\.[^./]+$/.test(fileName(e)));
    const directories = entries.filter((e) => !files.includes(e));

    setScanning(true);
    setScanNotice(null);
    setScanDisabled(false);
    api
      .runSkillsScan({ directories, files })
      .then((r) => {
        setReport(r);
        setStatusFilter("all");
        setPage(1);
        setScanNotice(`Scanned ${r.summary.files_scanned} file(s).`);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.status === 400) {
          // Server-side path scans are disabled on this deployment. Point the
          // operator at the headless equivalent instead of leaking server config.
          setScanDisabled(true);
        } else {
          setScanNotice(userFacingApiErrorMessage(e, "Skills scan failed"));
        }
      })
      .finally(() => setScanning(false));
  }, [targets]);

  const files = useMemo(() => report?.files ?? [], [report]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of files) counts[f.status] = (counts[f.status] ?? 0) + 1;
    return counts;
  }, [files]);

  const filteredFiles = useMemo(() => {
    const q = query.trim().toLowerCase();
    return files.filter((f) => {
      if (statusFilter !== "all" && f.status !== statusFilter) return false;
      if (q && !f.path.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [files, statusFilter, query]);

  useEffect(() => setPage(1), [statusFilter, query]);

  const totalPages = Math.max(1, Math.ceil(filteredFiles.length / FILE_PAGE_SIZE));
  const visibleFiles = useMemo(
    () => filteredFiles.slice((page - 1) * FILE_PAGE_SIZE, page * FILE_PAGE_SIZE),
    [filteredFiles, page],
  );

  const scanForm = (
    <div className="flex flex-wrap items-center gap-2">
      <label htmlFor="skill-targets" className="sr-only">
        Scan targets
      </label>
      <input
        id="skill-targets"
        value={targets}
        onChange={(e) => setTargets(e.target.value)}
        placeholder="Paths (relative to scan root)"
        className="h-9 w-56 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 text-sm text-[color:var(--foreground)] outline-none focus:border-[color:var(--border-strong)]"
      />
      <button
        type="button"
        onClick={runScan}
        disabled={scanning}
        data-testid="skills-scan-button"
        className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-[color:var(--accent)] bg-[color:var(--accent)] px-3 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-60"
      >
        {scanning ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <ScrollText className="h-4 w-4" aria-hidden="true" />}
        Scan
      </button>
    </div>
  );

  if (loading) {
    return (
      <PageLoadingState
        data-testid="skills-loading"
        title="Loading skills scan…"
        detail="Reading this tenant's most recent skill/instruction trust results."
      />
    );
  }

  if (error) {
    return (
      <PageErrorState
        data-testid="skills-error"
        title="Skills scan could not be loaded"
        detail={error}
        suggestions={["Confirm you are signed in with read access.", "The same scan is available headless."]}
        command={`${HEADLESS_CLI}   # or ${HEADLESS_API}`}
        action={{ label: "Retry", onClick: load }}
      />
    );
  }

  const hasData = (report?.summary.files_scanned ?? 0) > 0;

  return (
    <div className="space-y-5">
      <PageLaneHeader
        lane="ai-estate"
        title="Skills"
        subtitle="Scan agent skill/instruction files for behavioural risk and signing provenance. Same shared scanner as the CLI and MCP."
        actions={scanForm}
      />

      {scanDisabled ? (
        <div
          data-testid="skills-scan-disabled"
          className="rounded-lg border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] px-3 py-2 text-xs leading-5 text-[color:var(--status-warn)]"
        >
          Server-side path scans are disabled on this deployment. Run the scan locally with the CLI:{" "}
          <code className="font-mono text-[color:var(--foreground)]">{HEADLESS_CLI}</code>
        </div>
      ) : null}

      {scanNotice ? (
        <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs text-[color:var(--text-secondary)]">
          {scanNotice}
        </div>
      ) : null}

      {!hasData ? (
        <PageEmptyState
          data-testid="skills-empty"
          icon={FileWarning}
          title="No skills scanned yet"
          detail="Trigger a scan of your skill/instruction files to see per-file trust verdicts and signing provenance."
          command={`${HEADLESS_CLI}   # or ${HEADLESS_API}`}
        />
      ) : (
        <>
          {/* Summary — reconciled against the table below (one source of truth). */}
          <section
            data-testid="skills-summary"
            className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6"
          >
            <SummaryStat label="Files scanned" value={report?.summary.files_scanned ?? 0} />
            <SummaryStat
              label="Malicious"
              value={report?.summary.malicious_status_files ?? 0}
              tone="text-[color:var(--status-danger)]"
            />
            <SummaryStat
              label="Suspicious"
              value={report?.summary.suspicious_status_files ?? 0}
              tone="text-[color:var(--status-warn)]"
            />
            <SummaryStat label="Pending" value={report?.summary.pending_status_files ?? 0} />
            <SummaryStat
              label="Clean"
              value={report?.summary.clean_files ?? 0}
              tone="text-[color:var(--status-success)]"
            />
            <SummaryStat label="Findings" value={report?.summary.findings ?? 0} />
          </section>

          {/* Filter toolbar — status facets with live counts + path search. */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setStatusFilter("all")}
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ${
                statusFilter === "all"
                  ? "border-[color:var(--accent)] bg-[color:var(--accent)]/15 text-[color:var(--foreground)]"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-secondary)]"
              }`}
            >
              All
              <span className="tabular-nums text-[color:var(--text-tertiary)]">{files.length}</span>
            </button>
            {STATUS_ORDER.filter((s) => (statusCounts[s] ?? 0) > 0).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setStatusFilter(s)}
                data-testid={`skills-filter-${s}`}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ${
                  statusFilter === s
                    ? "border-[color:var(--accent)] bg-[color:var(--accent)]/15 text-[color:var(--foreground)]"
                    : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-secondary)]"
                }`}
              >
                {STATUS_META[s].label}
                <span className="tabular-nums text-[color:var(--text-tertiary)]">{statusCounts[s]}</span>
              </button>
            ))}
            <div className="relative ml-auto">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[color:var(--text-tertiary)]"
                aria-hidden="true"
              />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by path"
                aria-label="Filter by path"
                className="h-8 w-48 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] pl-8 pr-3 text-xs text-[color:var(--foreground)] outline-none focus:border-[color:var(--border-strong)]"
              />
            </div>
          </div>

          {/* Dense table — one row per file; open a row for provenance + findings. */}
          <div className="overflow-x-auto rounded-lg border border-[color:var(--border-subtle)]">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-left text-[11px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
                  <th className="px-3 py-2 font-medium">Skill file</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Content</th>
                  <th className="px-3 py-2 font-medium">Provenance</th>
                  <th className="px-3 py-2 text-right font-medium">Findings</th>
                </tr>
              </thead>
              <tbody>
                {visibleFiles.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-3 py-6 text-center text-xs text-[color:var(--text-tertiary)]">
                      No files match this filter.
                    </td>
                  </tr>
                ) : (
                  visibleFiles.map((file) => (
                    <tr
                      key={file.path}
                      data-testid="skills-row"
                      onClick={() => setSelected(file)}
                      className="cursor-pointer border-b border-[color:var(--border-subtle)] last:border-0 hover:bg-[color:var(--surface-muted)]"
                    >
                      <td className="max-w-0 px-3 py-2">
                        <div className="truncate font-medium text-[color:var(--foreground)]">
                          {fileName(file.path)}
                        </div>
                        <div className="truncate text-[11px] text-[color:var(--text-tertiary)]">{file.path}</div>
                      </td>
                      <td className="px-3 py-2">
                        <StatusChip status={file.status} />
                      </td>
                      <td className="px-3 py-2 text-[color:var(--text-secondary)]">
                        {file.trust.content_verdict}
                      </td>
                      <td className="px-3 py-2">
                        <ProvenanceChip status={file.provenance.status} />
                      </td>
                      <td className="px-3 py-2 text-right tabular-nums text-[color:var(--text-secondary)]">
                        {file.audit?.findings?.length ?? 0}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {filteredFiles.length > 0 ? (
            <PaginationBar
              page={page}
              totalPages={totalPages}
              totalItems={filteredFiles.length}
              itemLabel="files"
              onPrevious={() => setPage((current) => Math.max(1, current - 1))}
              onNext={() => setPage((current) => Math.min(totalPages, current + 1))}
            />
          ) : null}
        </>
      )}

      <p className="text-[11px] text-[color:var(--text-tertiary)]">
        Headless equivalent: <code className="text-[color:var(--text-secondary)]">{HEADLESS_CLI}</code> ·{" "}
        <code className="text-[color:var(--text-secondary)]">{HEADLESS_API}</code>
      </p>

      {selected ? <FileDrawer file={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}
