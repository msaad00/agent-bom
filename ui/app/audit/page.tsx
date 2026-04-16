"use client";

import { useEffect, useState, useCallback } from "react";
import {
  api,
  type AuditEntry,
  type AuditIntegrityResponse,
  formatDate,
} from "@/lib/api";
import {
  FileText,
  RefreshCw,
  Loader2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Search,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  Filter,
} from "lucide-react";

// ─── Constants ───────────────────────────────────────────────────────────────

const ACTION_COLORS: Record<string, string> = {
  scan: "bg-emerald-950 text-emerald-300 border-emerald-800",
  policy_eval: "bg-blue-950 text-blue-300 border-blue-800",
  fleet_change: "bg-purple-950 text-purple-300 border-purple-800",
  exception: "bg-yellow-950 text-yellow-300 border-yellow-800",
  alert: "bg-red-950 text-red-300 border-red-800",
  config: "bg-zinc-800 text-zinc-300 border-zinc-700",
};

const ACTION_TYPES = ["scan", "policy_eval", "fleet_change", "exception", "alert", "config"];

const PAGE_SIZE = 50;

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AuditLogPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [integrity, setIntegrity] = useState<AuditIntegrityResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  // Filters
  const [actionFilter, setActionFilter] = useState<string>("");
  const [resourceFilter, setResourceFilter] = useState<string>("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      api.listAuditEntries({
        action: actionFilter || undefined,
        resource: resourceFilter || undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
      api.getAuditIntegrity(),
    ])
      .then(([log, integ]) => {
        setEntries(log.entries);
        setTotal(log.total);
        setIntegrity(integ);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [actionFilter, resourceFilter, page]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      load();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <FileText className="w-6 h-6 text-blue-400" />
            Audit Log
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            HMAC-signed, tamper-evident log of all system actions
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Integrity banner + stats */}
      {integrity && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <FileText className="w-4 h-4 mb-2 text-blue-400" />
            <div className="text-2xl font-bold font-mono">{total.toLocaleString()}</div>
            <div className="text-xs text-zinc-500 mt-0.5">Total Entries</div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <CheckCircle2 className="w-4 h-4 mb-2 text-emerald-400" />
            <div className="text-2xl font-bold font-mono">{integrity.verified.toLocaleString()}</div>
            <div className="text-xs text-zinc-500 mt-0.5">HMAC Verified</div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            {integrity.tampered > 0 ? (
              <ShieldAlert className="w-4 h-4 mb-2 text-red-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 mb-2 text-emerald-400" />
            )}
            <div className={`text-2xl font-bold font-mono ${integrity.tampered > 0 ? "text-red-400" : ""}`}>
              {integrity.tampered}
            </div>
            <div className="text-xs text-zinc-500 mt-0.5">Tampered</div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <Search className="w-4 h-4 mb-2 text-zinc-400" />
            <div className="text-2xl font-bold font-mono">{integrity.checked.toLocaleString()}</div>
            <div className="text-xs text-zinc-500 mt-0.5">Checked</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs text-zinc-500">
          <Filter className="w-3.5 h-3.5" />
          Filter:
        </div>
        <div className="flex gap-1">
          <button
            onClick={() => { setActionFilter(""); setPage(0); }}
            className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
              !actionFilter ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800"
            }`}
          >
            All
          </button>
          {ACTION_TYPES?.map((a) => (
            <button
              key={a}
              onClick={() => { setActionFilter(a); setPage(0); }}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                actionFilter === a ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800"
              }`}
            >
              {a}
            </button>
          ))}
        </div>
        <input
          value={resourceFilter}
          onChange={(e) => { setResourceFilter(e.target.value); setPage(0); }}
          placeholder="Filter by resource…"
          className="bg-zinc-800 border border-zinc-700 rounded px-2.5 py-1 text-xs text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-blue-600 w-48"
        />
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-zinc-500" />
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="text-center py-10 border border-dashed border-red-900/50 rounded-xl space-y-3">
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto" />
          <p className="text-red-400 text-sm">Failed to load audit log</p>
          <p className="text-zinc-500 text-xs">{error}</p>
          <button
            onClick={load}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Retry
          </button>
        </div>
      )}

      {/* Entries */}
      {!loading && !error && (
        <>
          {entries.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
              <FileText className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
              <p className="text-zinc-500 text-sm">No audit log entries</p>
              <p className="text-zinc-600 text-xs mt-1">
                Entries will appear as scan, policy, and fleet actions are performed.
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              {entries?.map((entry) => {
                const isExpanded = expanded.has(entry.entry_id);
                return (
                  <div
                    key={entry.entry_id}
                    className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden"
                  >
                    <button
                      onClick={() => toggleExpand(entry.entry_id)}
                      className="w-full px-4 py-2.5 flex items-center justify-between hover:bg-zinc-800/50 transition-colors"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded border shrink-0 ${
                            ACTION_COLORS[entry.action] ?? ACTION_COLORS.config
                          }`}
                        >
                          {entry.action}
                        </span>
                        <span className="text-xs text-zinc-300 font-mono shrink-0">
                          {entry.actor}
                        </span>
                        <span className="text-xs text-zinc-500 truncate">
                          {entry.resource}
                        </span>
                      </div>
                      <span className="text-[10px] text-zinc-600 shrink-0 ml-3">
                        {formatDate(entry.timestamp)}
                      </span>
                    </button>
                    {isExpanded && (
                      <div className="border-t border-zinc-800 px-4 py-3 space-y-2">
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                          <div>
                            <span className="text-zinc-500">Entry ID</span>
                            <div className="text-zinc-300 mt-0.5 font-mono text-[10px] break-all">
                              {entry.entry_id}
                            </div>
                          </div>
                          <div>
                            <span className="text-zinc-500">Timestamp</span>
                            <div className="text-zinc-300 mt-0.5">
                              {formatDate(entry.timestamp)}
                            </div>
                          </div>
                          <div>
                            <span className="text-zinc-500">Actor</span>
                            <div className="text-zinc-300 mt-0.5 font-mono">
                              {entry.actor}
                            </div>
                          </div>
                          <div>
                            <span className="text-zinc-500">HMAC</span>
                            <div className="text-zinc-300 mt-0.5 font-mono text-[10px] truncate">
                              {entry.hmac_signature.slice(0, 16)}…
                            </div>
                          </div>
                        </div>
                        {Object.keys(entry.details).length > 0 && (
                          <div>
                            <span className="text-xs text-zinc-500 block mb-1">
                              Details
                            </span>
                            <pre className="text-[11px] text-zinc-400 bg-zinc-800 border border-zinc-700 rounded-lg p-3 overflow-x-auto max-h-48">
                              {JSON.stringify(entry.details, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-zinc-500">
                Page {page + 1} of {totalPages} ({total.toLocaleString()} entries)
              </span>
              <div className="flex gap-1">
                <button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 text-xs text-zinc-300 transition-colors"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  Prev
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 text-xs text-zinc-300 transition-colors"
                >
                  Next
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
