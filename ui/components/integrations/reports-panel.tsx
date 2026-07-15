"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Download, FileDown, Loader2, Play } from "lucide-react";

import { api, formatDate, type ReportJobRecord, type ReportSort } from "@/lib/api";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import {
  Field,
  INPUT_CLASS,
  InlineNotice,
  PanelButton,
  PanelIntro,
  Pill,
  errorMessage,
} from "@/components/integrations/panel-kit";

const SORTS: ReportSort[] = ["effective_reach", "cvss", "severity", "ordinal"];
const SEVERITIES = ["", "critical", "high", "medium", "low"];

function statusTone(status: string): "success" | "warn" | "danger" | "neutral" {
  if (status === "done") return "success";
  if (status === "failed" || status === "cancelled") return "danger";
  if (status === "pending" || status === "running") return "warn";
  return "neutral";
}

function isTerminal(status: string): boolean {
  return status === "done" || status === "failed" || status === "cancelled";
}

export function ReportsPanel() {
  // No server-side list endpoint exists for reports, so we track the jobs
  // created in this session and poll each until it reaches a terminal state.
  const [jobs, setJobs] = useState<ReportJobRecord[]>([]);
  const [sort, setSort] = useState<ReportSort>("effective_reach");
  const [severity, setSeverity] = useState("");
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "error" | "info"; text: string } | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);
  // Latest committed jobs, so the interval callback never reads a stale closure.
  const jobsRef = useRef<ReportJobRecord[]>([]);
  jobsRef.current = jobs;

  const poll = useCallback(async () => {
    const pending = jobsRef.current.filter((j) => !isTerminal(j.status));
    if (pending.length === 0) return;
    const fresh = await Promise.all(
      pending.map((j) => api.getReportJob(j.job_id).catch(() => null)),
    );
    setJobs((cur) => cur.map((c) => fresh.find((f) => f && f.job_id === c.job_id) ?? c));
  }, []);

  useEffect(() => {
    pollRef.current = window.setInterval(() => void poll(), 2500);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [poll]);

  const create = async () => {
    setCreating(true);
    setNotice(null);
    try {
      const job = await api.createReportJob({
        format: "ndjson",
        sort,
        severity: severity || null,
      });
      setJobs((prev) => [job, ...prev]);
      setNotice({ tone: "success", text: "Report export queued." });
    } catch (err) {
      setNotice({ tone: "error", text: errorMessage(err) });
    } finally {
      setCreating(false);
    }
  };

  const download = async (job: ReportJobRecord) => {
    if (!job.download_token) {
      setNotice({ tone: "error", text: "Download token unavailable for this report." });
      return;
    }
    setDownloadingId(job.job_id);
    setNotice(null);
    try {
      const blob = await api.downloadReportArtifact(job.job_id, job.download_token);
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `findings-${job.job_id.slice(0, 8)}.ndjson.gz`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (err) {
      setNotice({ tone: "error", text: errorMessage(err) });
    } finally {
      setDownloadingId(null);
    }
  };

  const columns: DataTableColumn<ReportJobRecord>[] = [
    {
      key: "job",
      header: "Job",
      cell: (j) => <span className="font-mono text-xs text-[color:var(--foreground)]">{j.job_id.slice(0, 8)}…</span>,
    },
    { key: "sort", header: "Sort", cell: (j) => <Pill tone="neutral">{j.sort}</Pill> },
    {
      key: "severity",
      header: "Severity",
      cell: (j) => (j.severity ? <Pill tone="neutral">{j.severity}</Pill> : <span className="text-[color:var(--text-tertiary)]">all</span>),
    },
    {
      key: "status",
      header: "Status",
      cell: (j) => (
        <Pill tone={statusTone(j.status)}>
          {j.status !== "done" && !isTerminal(j.status) ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : null}
          {j.status}
        </Pill>
      ),
    },
    {
      key: "rows",
      header: "Rows",
      align: "right",
      cell: (j) => (
        <span className="font-mono tabular-nums text-[color:var(--text-secondary)]">
          {j.row_count != null ? j.row_count.toLocaleString() : "—"}
        </span>
      ),
    },
    {
      key: "created",
      header: "Created",
      cell: (j) => <span className="text-xs text-[color:var(--text-tertiary)]">{formatDate(j.created_at)}</span>,
    },
    {
      key: "actions",
      header: "",
      align: "right",
      cell: (j) => (
        <div className="flex justify-end">
          {j.status === "done" ? (
            <PanelButton
              tone="primary"
              disabled={downloadingId === j.job_id}
              onClick={() => void download(j)}
              data-testid={`report-download-${j.job_id.slice(0, 8)}`}
            >
              {downloadingId === j.job_id ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5" />
              )}
              Download
            </PanelButton>
          ) : j.status === "failed" ? (
            <span className="text-xs text-[color:var(--severity-critical)]">{j.error ?? "failed"}</span>
          ) : (
            <span className="text-xs text-[color:var(--text-tertiary)]">working…</span>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <PanelIntro
        title="Reports"
        description="Queue an async findings export (gzipped NDJSON) streamed from the hub, then poll and download. Exports are quota-enforced per tenant; the download token is sent via header, never in the URL."
      />

      <form
        className="space-y-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <div className="grid gap-4 md:grid-cols-3">
          <Field label="Format">
            <select className={INPUT_CLASS} value="ndjson" disabled data-testid="report-format-select">
              <option value="ndjson">NDJSON (gzip)</option>
            </select>
          </Field>
          <Field label="Sort">
            <select
              className={INPUT_CLASS}
              value={sort}
              onChange={(e) => setSort(e.target.value as ReportSort)}
              data-testid="report-sort-select"
            >
              {SORTS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Severity filter">
            <select
              className={INPUT_CLASS}
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              data-testid="report-severity-select"
            >
              {SEVERITIES.map((s) => (
                <option key={s || "all"} value={s}>
                  {s || "all severities"}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <PanelButton tone="primary" type="submit" disabled={creating} data-testid="report-create-submit">
          {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          Queue export
        </PanelButton>
      </form>

      {notice ? <InlineNotice tone={notice.tone} data-testid="report-notice">{notice.text}</InlineNotice> : null}

      <DataTable
        rows={jobs}
        rowKey={(j) => j.job_id}
        columns={columns}
        maxHeight="28rem"
        caption="Report export jobs created this session"
        empty={
          <span className="inline-flex items-center gap-2">
            <FileDown className="h-4 w-4" /> No exports yet. Queue one above to generate a downloadable findings report.
          </span>
        }
        data-testid="reports-table"
      />
    </div>
  );
}
