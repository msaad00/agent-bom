"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ChevronRight, Loader2, ShieldAlert } from "lucide-react";

import { api } from "@/lib/api";
import type { TraceExplorerResponse } from "@/lib/api-types";

export function TraceExplorerPanel() {
  const [data, setData] = useState<TraceExplorerResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedSpanId, setSelectedSpanId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await api.getTraceExplorer(120);
        if (!cancelled) {
          setData(response);
          const firstSession = response.sessions[0];
          const firstSpan = firstSession?.spans[0];
          setSelectedSessionId(firstSession?.session_id ?? null);
          setSelectedSpanId(firstSpan?.span_id ?? null);
        }
      } catch (e: unknown) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const selectedSession = useMemo(
    () => data?.sessions.find((session) => session.session_id === selectedSessionId) ?? null,
    [data, selectedSessionId],
  );
  const selectedSpan = useMemo(
    () => selectedSession?.spans.find((span) => span.span_id === selectedSpanId) ?? null,
    [selectedSession, selectedSpanId],
  );

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 px-4 py-10 text-sm text-[var(--text-secondary)]">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading runtime trace explorer…
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-2xl border border-red-900/50 bg-red-950/30 px-4 py-3 text-sm text-red-300">
        {error}
      </div>
    );
  }

  if (!data || data.sessions.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-[var(--border-subtle)] bg-[var(--surface)]/40 px-4 py-10 text-center text-sm text-[var(--text-tertiary)]">
        No runtime sessions yet. Gateway/proxy blocks and authorized tool calls will appear here once enforcement traffic is flowing.
      </div>
    );
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1fr)_320px]">
      <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
        <h2 className="text-sm font-semibold text-[var(--foreground)]">Sessions</h2>
        <p className="mt-1 text-xs text-[var(--text-tertiary)]">{data.session_count} sessions · {data.blocked_count} blocked spans</p>
        <div className="mt-4 space-y-2">
          {data.sessions.map((session) => (
            <button
              key={session.session_id}
              type="button"
              onClick={() => {
                setSelectedSessionId(session.session_id);
                setSelectedSpanId(session.spans[0]?.span_id ?? null);
              }}
              className={`w-full rounded-xl border px-3 py-2 text-left transition-colors ${
                selectedSessionId === session.session_id
                  ? "border-emerald-700/60 bg-emerald-950/30"
                  : "border-[var(--border-subtle)] bg-[var(--background)]/60 hover:border-[var(--border-subtle)]"
              }`}
            >
              <div className="text-sm font-medium text-[var(--foreground)]">{session.agent || session.session_id}</div>
              <div className="mt-1 text-xs text-[var(--text-tertiary)]">
                {session.spans.length} spans · {session.blocked_count} blocked
              </div>
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
        <h2 className="text-sm font-semibold text-[var(--foreground)]">Flow</h2>
        <p className="mt-1 text-xs text-[var(--text-tertiary)]">Tool-call timeline for the selected session.</p>
        <div className="mt-4 space-y-2">
          {(selectedSession?.spans ?? []).map((span) => (
            <button
              key={span.span_id}
              type="button"
              onClick={() => setSelectedSpanId(span.span_id)}
              className={`flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left transition-colors ${
                selectedSpanId === span.span_id
                  ? "border-sky-700/60 bg-sky-950/20"
                  : "border-[var(--border-subtle)] bg-[var(--background)]/60 hover:border-[var(--border-subtle)]"
              }`}
            >
              <span
                className={`inline-flex h-8 w-8 items-center justify-center rounded-full border ${
                  span.verdict === "blocked"
                    ? "border-rose-800 bg-rose-950 text-rose-300"
                    : "border-sky-800 bg-sky-950 text-sky-300"
                }`}
              >
                {span.verdict === "blocked" ? <ShieldAlert className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-xs text-[var(--foreground)]">{span.tool || span.action_type}</span>
                <span className="mt-1 block text-[11px] text-[var(--text-tertiary)]">{span.timestamp || "—"} · {span.verdict}</span>
              </span>
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
        <h2 className="text-sm font-semibold text-[var(--foreground)]">Detail</h2>
        {!selectedSpan ? (
          <p className="mt-4 text-sm text-[var(--text-tertiary)]">Select a span to inspect policy and finding joins.</p>
        ) : (
          <div className="mt-4 space-y-4 text-sm">
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">Tool call</div>
              <div className="mt-1 font-mono text-[var(--foreground)]">{selectedSpan.tool || "unknown"}</div>
              <div className="mt-2 text-xs text-[var(--text-secondary)]">{selectedSpan.detail}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className={`rounded border px-2 py-0.5 text-xs uppercase ${
                selectedSpan.verdict === "blocked"
                  ? "border-rose-800 bg-rose-950 text-rose-300"
                  : "border-sky-800 bg-sky-950 text-sky-300"
              }`}>
                {selectedSpan.verdict}
              </span>
              <span className="rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-0.5 text-xs text-[var(--text-secondary)]">
                {selectedSpan.agent}
              </span>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">Linked findings</div>
              {selectedSpan.linked_findings.length === 0 ? (
                <p className="mt-2 text-xs text-[var(--text-tertiary)]">No correlated CVE findings for this agent/tool path.</p>
              ) : (
                <div className="mt-2 space-y-2">
                  {selectedSpan.linked_findings.map((finding) => (
                    <div key={String(finding.finding_id)} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--background)]/70 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <Link href={`/findings?cve=${encodeURIComponent(String(finding.vulnerability_id || ""))}`} className="font-mono text-xs text-emerald-300 hover:underline">
                          {finding.vulnerability_id}
                        </Link>
                        {finding.effective_reach_band ? (
                          <span className="text-[10px] uppercase text-amber-300">{finding.effective_reach_band}</span>
                        ) : null}
                      </div>
                      {finding.policy_state ? (
                        <div className="mt-1 flex items-center gap-1 text-xs text-rose-300">
                          <AlertTriangle className="h-3 w-3" />
                          Runtime {finding.policy_state}
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </div>
            {selectedSpan.compliance_controls.length > 0 && (
              <div>
                <div className="text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">Compliance controls</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {selectedSpan.compliance_controls.map((tag) => (
                    <span key={tag} className="rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
