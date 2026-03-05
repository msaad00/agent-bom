"use client";

import { useState } from "react";
import { Activity, AlertTriangle, CheckCircle2, Loader2, Send } from "lucide-react";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

interface FlaggedCall {
  tool_name: string;
  server: string;
  package_name?: string;
  cve_ids: string[];
  severity: string;
}

interface TraceResult {
  traces: number;
  flagged: FlaggedCall[];
  message?: string;
}

export default function TracesPage() {
  const [payload, setPayload] = useState(
    JSON.stringify(
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
    ),
  );
  const [result, setResult] = useState<TraceResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`${BASE}/v1/traces`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      setResult(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Traces</h1>
        <p className="text-zinc-400 text-sm mt-1">
          OpenTelemetry trace ingestion — flag vulnerable tool calls in real time
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input */}
        <div className="space-y-3">
          <label className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            OTLP JSON Payload
          </label>
          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            rows={18}
            className="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-3 font-mono text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-emerald-500 resize-none"
            spellCheck={false}
          />
          <button
            onClick={submit}
            disabled={loading}
            className="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {loading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Send className="w-3.5 h-3.5" />
            )}
            Ingest Traces
          </button>
        </div>

        {/* Result */}
        <div className="space-y-3">
          <label className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Response
          </label>

          {!result && !error && (
            <div className="border border-dashed border-zinc-800 rounded-xl py-16 text-center">
              <Activity className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
              <p className="text-zinc-500 text-sm">
                Submit OTLP traces to flag vulnerable tool calls.
              </p>
              <p className="text-zinc-600 text-xs mt-1">
                POST /v1/traces with spans containing adk.tool.* attributes.
              </p>
            </div>
          )}

          {error && (
            <div className="border border-red-900/50 bg-red-950/30 rounded-xl px-4 py-3">
              <div className="flex items-center gap-2 text-red-400 text-sm">
                <AlertTriangle className="w-4 h-4" />
                {error}
              </div>
            </div>
          )}

          {result && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="border border-zinc-800 rounded-xl px-4 py-3">
                  <div className="text-xs text-zinc-500">Traces parsed</div>
                  <div className="text-xl font-semibold text-zinc-100 mt-1">
                    {result.traces}
                  </div>
                </div>
                <div className="border border-zinc-800 rounded-xl px-4 py-3">
                  <div className="text-xs text-zinc-500">Flagged calls</div>
                  <div className={`text-xl font-semibold mt-1 ${result.flagged.length > 0 ? "text-red-400" : "text-emerald-400"}`}>
                    {result.flagged.length}
                  </div>
                </div>
              </div>

              {result.flagged.length > 0 && (
                <div className="border border-zinc-800 rounded-xl overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-zinc-900 border-b border-zinc-800">
                      <tr>
                        <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Tool</th>
                        <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Server</th>
                        <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">CVEs</th>
                        <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Severity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                      {result.flagged.map((f, i) => (
                        <tr key={i} className="hover:bg-zinc-900 transition-colors">
                          <td className="px-4 py-2.5 font-mono text-xs text-zinc-300">{f.tool_name}</td>
                          <td className="px-4 py-2.5 text-xs text-zinc-400">{f.server}</td>
                          <td className="px-4 py-2.5 text-xs text-zinc-400">{f.cve_ids?.join(", ") || "-"}</td>
                          <td className="px-4 py-2.5">
                            <span className={`text-xs font-medium ${
                              f.severity === "critical" ? "text-red-400" :
                              f.severity === "high" ? "text-orange-400" :
                              f.severity === "medium" ? "text-yellow-400" :
                              "text-zinc-400"
                            }`}>
                              {f.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {result.flagged.length === 0 && (
                <div className="border border-emerald-900/30 bg-emerald-950/20 rounded-xl px-4 py-3">
                  <div className="flex items-center gap-2 text-emerald-400 text-sm">
                    <CheckCircle2 className="w-4 h-4" />
                    No vulnerable tool calls detected in traces.
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
