"use client";

import { useState, type ChangeEvent } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  FileUp,
  GitBranch,
  Loader2,
  PlayCircle,
  Send,
  ShieldAlert,
} from "lucide-react";

import { api, type TraceIngestResponse } from "@/lib/api";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { TraceExplorerPanel } from "@/components/trace-explorer-panel";
import { HitlApprovalQueuePanel } from "@/components/hitl-approval-queue-panel";

const SAMPLE_PAYLOAD = JSON.stringify(
  {
    resourceSpans: [
      {
        scopeSpans: [
          {
            spans: [
              {
                name: "adk.tool.call",
                attributes: [
                  { key: "tool.name", value: { stringValue: "query_db" } },
                  { key: "mcp.server", value: { stringValue: "sqlite-mcp" } },
                  { key: "package.name", value: { stringValue: "sqlite-utils" } },
                ],
              },
            ],
          },
        ],
      },
    ],
  },
  null,
  2,
);

export default function TracesPage() {
  const { counts } = useDeploymentContext();
  const [mode, setMode] = useState<"explorer" | "queue" | "ingest">("explorer");
  const [payload, setPayload] = useState(SAMPLE_PAYLOAD);
  const [result, setResult] = useState<TraceIngestResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tracesUnavailable = counts ? !counts.has_traces : false;

  async function submit() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.ingestTraces(JSON.parse(payload)));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  const handleFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onerror = () => setError("Failed to read trace export.");
    reader.onload = () => {
      if (typeof reader.result === "string") {
        setPayload(reader.result);
        setError(null);
      }
    };
    reader.readAsText(file);
    event.target.value = "";
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 rounded-3xl border border-[var(--border-subtle)] bg-[var(--background)]/70 p-6 shadow-2xl shadow-black/20 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-3xl">
          <p className="text-[11px] uppercase tracking-[0.22em] text-emerald-400">Trace review</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[var(--foreground)]">Runtime tool-call correlation</h1>
          <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
            {tracesUnavailable
              ? "Trace ingest is not enabled for this estate yet. Use the explorer when gateway traffic exists, or paste OTLP JSON to validate correlation."
              : "Explore blocked and observed tool calls joined to the same findings and compliance controls surfaced in triage."}{" "}
            Production collectors send OTLP JSON to <code className="rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[var(--foreground)]">POST /v1/traces</code>.
          </p>
          <div className="mt-4 inline-flex rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)]/70 p-1">
            <button
              type="button"
              onClick={() => setMode("explorer")}
              className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs ${
                mode === "explorer" ? "bg-emerald-600 text-white" : "text-[var(--text-secondary)] hover:text-[var(--foreground)]"
              }`}
            >
              <GitBranch className="h-3.5 w-3.5" />
              Explorer
            </button>
            <button
              type="button"
              onClick={() => setMode("queue")}
              className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs ${
                mode === "queue" ? "bg-emerald-600 text-white" : "text-[var(--text-secondary)] hover:text-[var(--foreground)]"
              }`}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Approval queue
            </button>
            <button
              type="button"
              onClick={() => setMode("ingest")}
              className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs ${
                mode === "ingest" ? "bg-emerald-600 text-white" : "text-[var(--text-secondary)] hover:text-[var(--foreground)]"
              }`}
            >
              <FileUp className="h-3.5 w-3.5" />
              OTLP ingest
            </button>
          </div>
        </div>
        <div className="grid gap-3 text-xs text-[var(--text-secondary)] sm:grid-cols-2 lg:w-[360px]">
          <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 p-4">
            <div className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Input</div>
            <div className="mt-2 text-sm text-[var(--foreground)]">OTLP JSON export</div>
            <div className="mt-1 text-[var(--text-tertiary)]">Paste, upload, or send directly from a collector.</div>
          </div>
          <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 p-4">
            <div className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Output</div>
            <div className="mt-2 text-sm text-[var(--foreground)]">Flagged tool calls</div>
            <div className="mt-1 text-[var(--text-tertiary)]">Server, package, CVE, and severity correlation.</div>
          </div>
        </div>
      </div>

      {mode === "explorer" ? (
        <TraceExplorerPanel />
      ) : mode === "queue" ? (
        <HitlApprovalQueuePanel />
      ) : (
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-[var(--foreground)]">Trace intake</h2>
              <p className="mt-1 text-xs text-[var(--text-tertiary)]">Use a real OTLP export or the sample payload for a quick validation run.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-2 text-xs text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]">
                <FileUp className="h-3.5 w-3.5" />
                Upload JSON
                <input type="file" accept=".json,application/json" className="hidden" onChange={handleFile} />
              </label>
              <button
                onClick={() => setPayload(SAMPLE_PAYLOAD)}
                className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-2 text-xs text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]"
              >
                <PlayCircle className="h-3.5 w-3.5" />
                Use sample
              </button>
            </div>
          </div>

          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            rows={18}
            className="mt-4 w-full resize-none rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3 font-mono text-xs leading-6 text-[var(--text-secondary)] focus:outline-none focus:ring-1 focus:ring-emerald-500"
            spellCheck={false}
          />

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              onClick={submit}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              Run correlation
            </button>
            <p className="text-xs text-[var(--text-tertiary)]">
              Endpoint: <code className="rounded bg-[var(--background)] px-1.5 py-0.5 font-mono text-[var(--text-secondary)]">POST /v1/traces</code>
            </p>
          </div>
        </section>

        <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-[var(--foreground)]">Correlation result</h2>
              <p className="mt-1 text-xs text-[var(--text-tertiary)]">Review flagged calls with mapped server, package, and CVE context.</p>
            </div>
          </div>

          {!result && !error && (
            <div className="mt-4 rounded-2xl border border-dashed border-[var(--border-subtle)] py-16 text-center">
              <Activity className="mx-auto mb-3 h-8 w-8 text-[var(--text-tertiary)]" />
              <p className="text-sm text-[var(--text-tertiary)]">No trace run yet.</p>
              <p className="mt-1 text-xs text-[var(--text-tertiary)]">Submit a payload to validate correlation against known vulnerable assets.</p>
            </div>
          )}

          {error && (
            <div className="mt-4 rounded-2xl border border-red-900/50 bg-red-950/30 px-4 py-3">
              <div className="flex items-center gap-2 text-sm text-red-400">
                <AlertTriangle className="h-4 w-4" />
                {error}
              </div>
            </div>
          )}

          {result && (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3">
                  <div className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Traces parsed</div>
                  <div className="mt-2 text-2xl font-semibold text-[var(--foreground)]">{result.traces}</div>
                </div>
                <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3">
                  <div className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Flagged calls</div>
                  <div className={`mt-2 text-2xl font-semibold ${result.flagged.length > 0 ? "text-red-400" : "text-emerald-400"}`}>
                    {result.flagged.length}
                  </div>
                </div>
              </div>

              {result.message ? (
                <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3 text-xs text-[var(--text-tertiary)]">
                  {result.message}
                </div>
              ) : null}

              {result.flagged.length === 0 ? (
                <div className="rounded-2xl border border-emerald-900/40 bg-emerald-950/20 px-4 py-3">
                  <div className="flex items-center gap-2 text-sm text-emerald-400">
                    <CheckCircle2 className="h-4 w-4" />
                    No vulnerable tool calls were flagged in this payload.
                  </div>
                </div>
              ) : (
                <div className="overflow-hidden rounded-2xl border border-[var(--border-subtle)]">
                  <table className="w-full text-sm">
                    <thead className="bg-[var(--surface)] border-b border-[var(--border-subtle)]">
                      <tr>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Tool</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Server</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Package</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">CVEs</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-subtle)] bg-[var(--background)]">
                      {result.flagged.map((flagged) => (
                        <tr key={`${flagged.span_id}-${flagged.tool_name}`} className="align-top hover:bg-[var(--surface)]/70">
                          <td className="px-4 py-3">
                            <div className="font-mono text-xs text-[var(--foreground)]">{flagged.tool_name}</div>
                            <div className="mt-1 text-xs text-[var(--text-tertiary)]">{flagged.reason}</div>
                          </td>
                          <td className="px-4 py-3 text-xs text-[var(--text-secondary)]">{flagged.server || "N/A"}</td>
                          <td className="px-4 py-3 text-xs text-[var(--text-secondary)]">{flagged.package_name || "N/A"}</td>
                          <td className="px-4 py-3">
                            {flagged.cve_ids.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {flagged.cve_ids.map((cve) => (
                                  <span
                                    key={cve}
                                    className="rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]"
                                  >
                                    {cve}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-xs text-[var(--text-tertiary)]">N/A</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium capitalize ${
                                flagged.severity === "high"
                                  ? "border-red-800 bg-red-950 text-red-300"
                                  : "border-yellow-800 bg-yellow-950 text-yellow-300"
                              }`}
                            >
                              <ShieldAlert className="h-3 w-3" />
                              {flagged.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
      )}
    </div>
  );
}
