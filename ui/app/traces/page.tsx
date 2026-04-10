"use client";

import { useState, type ChangeEvent } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  FileUp,
  Loader2,
  PlayCircle,
  Send,
  ShieldAlert,
} from "lucide-react";

import { api, type TraceIngestResponse } from "@/lib/api";

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
  const [payload, setPayload] = useState(SAMPLE_PAYLOAD);
  const [result, setResult] = useState<TraceIngestResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      <div className="flex flex-col gap-4 rounded-3xl border border-zinc-800 bg-zinc-950/70 p-6 shadow-2xl shadow-black/20 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-3xl">
          <p className="text-[11px] uppercase tracking-[0.22em] text-emerald-400">Trace review</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-zinc-100">Runtime tool-call correlation</h1>
          <p className="mt-3 text-sm leading-6 text-zinc-400">
            Review OTLP traces against vulnerable packages and servers already known to agent-bom. This page is for inspection and replay.
            Production collectors should send OTLP JSON to <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-zinc-200">POST /v1/traces</code>.
          </p>
        </div>
        <div className="grid gap-3 text-xs text-zinc-400 sm:grid-cols-2 lg:w-[360px]">
          <div className="rounded-2xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">Input</div>
            <div className="mt-2 text-sm text-zinc-200">OTLP JSON export</div>
            <div className="mt-1 text-zinc-500">Paste, upload, or send directly from a collector.</div>
          </div>
          <div className="rounded-2xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">Output</div>
            <div className="mt-2 text-sm text-zinc-200">Flagged tool calls</div>
            <div className="mt-1 text-zinc-500">Server, package, CVE, and severity correlation.</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <section className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-200">Trace intake</h2>
              <p className="mt-1 text-xs text-zinc-500">Use a real OTLP export or the sample payload for a quick validation run.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-xs text-zinc-200 transition-colors hover:bg-zinc-700">
                <FileUp className="h-3.5 w-3.5" />
                Upload JSON
                <input type="file" accept=".json,application/json" className="hidden" onChange={handleFile} />
              </label>
              <button
                onClick={() => setPayload(SAMPLE_PAYLOAD)}
                className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-xs text-zinc-200 transition-colors hover:bg-zinc-700"
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
            className="mt-4 w-full resize-none rounded-2xl border border-zinc-800 bg-zinc-950 px-4 py-3 font-mono text-xs leading-6 text-zinc-300 focus:outline-none focus:ring-1 focus:ring-emerald-500"
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
            <p className="text-xs text-zinc-500">
              Endpoint: <code className="rounded bg-zinc-950 px-1.5 py-0.5 font-mono text-zinc-300">POST /v1/traces</code>
            </p>
          </div>
        </section>

        <section className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-200">Correlation result</h2>
              <p className="mt-1 text-xs text-zinc-500">Review flagged calls with mapped server, package, and CVE context.</p>
            </div>
          </div>

          {!result && !error && (
            <div className="mt-4 rounded-2xl border border-dashed border-zinc-800 py-16 text-center">
              <Activity className="mx-auto mb-3 h-8 w-8 text-zinc-700" />
              <p className="text-sm text-zinc-500">No trace run yet.</p>
              <p className="mt-1 text-xs text-zinc-600">Submit a payload to validate correlation against known vulnerable assets.</p>
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
                <div className="rounded-2xl border border-zinc-800 bg-zinc-950 px-4 py-3">
                  <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">Traces parsed</div>
                  <div className="mt-2 text-2xl font-semibold text-zinc-100">{result.traces}</div>
                </div>
                <div className="rounded-2xl border border-zinc-800 bg-zinc-950 px-4 py-3">
                  <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">Flagged calls</div>
                  <div className={`mt-2 text-2xl font-semibold ${result.flagged.length > 0 ? "text-red-400" : "text-emerald-400"}`}>
                    {result.flagged.length}
                  </div>
                </div>
              </div>

              {result.message ? (
                <div className="rounded-xl border border-zinc-800 bg-zinc-950 px-4 py-3 text-xs text-zinc-500">
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
                <div className="overflow-hidden rounded-2xl border border-zinc-800">
                  <table className="w-full text-sm">
                    <thead className="bg-zinc-900 border-b border-zinc-800">
                      <tr>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Tool</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Server</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Package</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">CVEs</th>
                        <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                      {result.flagged.map((flagged) => (
                        <tr key={`${flagged.span_id}-${flagged.tool_name}`} className="align-top hover:bg-zinc-900/70">
                          <td className="px-4 py-3">
                            <div className="font-mono text-xs text-zinc-200">{flagged.tool_name}</div>
                            <div className="mt-1 text-xs text-zinc-500">{flagged.reason}</div>
                          </td>
                          <td className="px-4 py-3 text-xs text-zinc-400">{flagged.server || "N/A"}</td>
                          <td className="px-4 py-3 text-xs text-zinc-400">{flagged.package_name || "N/A"}</td>
                          <td className="px-4 py-3">
                            {flagged.cve_ids.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {flagged.cve_ids.map((cve) => (
                                  <span
                                    key={cve}
                                    className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300"
                                  >
                                    {cve}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-xs text-zinc-600">N/A</span>
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
    </div>
  );
}
