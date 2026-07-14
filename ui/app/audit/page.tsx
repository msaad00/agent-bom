"use client";

import { useEffect, useState, useCallback } from "react";
import {
  api,
  type ApiKeyRecord,
  type AuditEntry,
  type AuditIntegrityResponse,
  type AuthPolicyResponse,
  formatDate,
} from "@/lib/api";
import { PaginationBar } from "@/components/pagination-bar";
import {
  FileText,
  RefreshCw,
  Loader2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Search,
  CheckCircle2,
  Filter,
} from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { KeyLifecyclePanel } from "@/components/key-lifecycle-panel";
import { PageLaneHeader } from "@/components/page-lane";

// ─── Constants ───────────────────────────────────────────────────────────────

const ACTION_COLORS: Record<string, string> = {
  scan: "bg-emerald-950 text-emerald-300 border-emerald-800",
  policy_eval: "bg-blue-950 text-blue-300 border-blue-800",
  fleet_change: "bg-purple-950 text-purple-300 border-purple-800",
  exception: "bg-yellow-950 text-yellow-300 border-yellow-800",
  alert: "bg-red-950 text-red-300 border-red-800",
  config: "bg-[var(--surface-elevated)] text-[var(--text-secondary)] border-[var(--border-subtle)]",
};

const ACTION_TYPES = ["scan", "policy_eval", "fleet_change", "exception", "alert", "config"];

const PAGE_SIZE = 50;

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AuditLogPage() {
  const { session, loading: authSessionLoading, hasCapability } = useAuthState();
  const { counts } = useDeploymentContext();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [integrity, setIntegrity] = useState<AuditIntegrityResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [authPolicy, setAuthPolicy] = useState<AuthPolicyResponse | null>(null);
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);
  const [adminLoading, setAdminLoading] = useState(true);
  const [adminError, setAdminError] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  // Filters
  const [actionFilter, setActionFilter] = useState<string>("");
  const [resourceFilter, setResourceFilter] = useState<string>("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const roleLabel = session?.role_summary?.display_name ?? session?.role ?? "Unknown";
  const canManageKeys = hasCapability("keys.manage");
  const auditUnavailable = counts ? !(counts.has_proxy || counts.has_gateway || counts.has_traces) : false;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [log, integ] = await Promise.all([
        api.listAuditEntries({
          action: actionFilter || undefined,
          resource: resourceFilter || undefined,
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        }),
        api.getAuditIntegrity(),
      ]);
      setEntries(log.entries);
      setTotal(log.total);
      setIntegrity(integ);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Failed to load audit log";
      if (/forbidden|analyst|viewer/i.test(message)) {
        setError(
          `Audit log requires analyst role or higher. You're signed in as ${roleLabel}. Sign in with a higher role to view entries.`
        );
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  }, [actionFilter, resourceFilter, page, roleLabel]);

  const loadAdmin = useCallback(async () => {
    if (authSessionLoading) {
      return;
    }
    setAdminLoading(true);
    setAdminError(null);
    if (!canManageKeys) {
      setAuthPolicy(null);
      setKeys([]);
      setAdminError(`${roleLabel} access can review audit state but cannot manage API keys or auth policy.`);
      setAdminLoading(false);
      return;
    }
    try {
      const [policy, keyList] = await Promise.all([api.getAuthPolicy(), api.listKeys()]);
      setAuthPolicy(policy);
      setKeys(keyList.keys);
    } catch (e) {
      setAdminError(e instanceof Error ? e.message : "Failed to load key lifecycle state");
    } finally {
      setAdminLoading(false);
    }
  }, [authSessionLoading, canManageKeys, roleLabel]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
      if (!authSessionLoading && canManageKeys) {
        void loadAdmin();
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [authSessionLoading, canManageKeys, load, loadAdmin]);

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
      <PageLaneHeader
        lane="governance"
        title="Audit Log"
        subtitle="HMAC-signed, tamper-evident log of scan, policy, and fleet actions."
        actions={
          <button
            onClick={() => {
              void load();
              if (canManageKeys) {
                void loadAdmin();
              }
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--surface-elevated)] hover:bg-[var(--surface-muted)] border border-[var(--border-subtle)] rounded-lg text-xs text-[var(--text-secondary)] transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        }
      />

      {canManageKeys ? (
        <KeyLifecyclePanel
          loading={adminLoading}
          error={adminError}
          policy={authPolicy}
          keys={keys}
          onRefresh={loadAdmin}
          roleLabel={roleLabel}
        />
      ) : null}

      {/* Integrity banner + stats */}
      {integrity && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-4">
            <FileText className="w-4 h-4 mb-2 text-blue-400" />
            <div className="text-2xl font-bold font-mono">{total.toLocaleString()}</div>
            <div className="text-xs text-[var(--text-tertiary)] mt-0.5">Total Entries</div>
          </div>
          <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-4">
            <CheckCircle2 className="w-4 h-4 mb-2 text-emerald-400" />
            <div className="text-2xl font-bold font-mono">{integrity.verified.toLocaleString()}</div>
            <div className="text-xs text-[var(--text-tertiary)] mt-0.5">HMAC Verified</div>
          </div>
          <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-4">
            {integrity.tampered > 0 ? (
              <ShieldAlert className="w-4 h-4 mb-2 text-red-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 mb-2 text-emerald-400" />
            )}
            <div className={`text-2xl font-bold font-mono ${integrity.tampered > 0 ? "text-red-400" : ""}`}>
              {integrity.tampered}
            </div>
            <div className="text-xs text-[var(--text-tertiary)] mt-0.5">Tampered</div>
          </div>
          <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-4">
            <Search className="w-4 h-4 mb-2 text-[var(--text-secondary)]" />
            <div className="text-2xl font-bold font-mono">{integrity.checked.toLocaleString()}</div>
            <div className="text-xs text-[var(--text-tertiary)] mt-0.5">Checked</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs text-[var(--text-tertiary)]">
          <Filter className="w-3.5 h-3.5" />
          Filter:
        </div>
        <div className="flex min-w-0 flex-wrap gap-1">
          <button
            onClick={() => { setActionFilter(""); setPage(0); }}
            className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
              !actionFilter ? "bg-[var(--surface-muted)] text-[var(--foreground)]" : "text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:bg-[var(--surface-elevated)]"
            }`}
          >
            All
          </button>
          {ACTION_TYPES?.map((a) => (
            <button
              key={a}
              onClick={() => { setActionFilter(a); setPage(0); }}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                actionFilter === a ? "bg-[var(--surface-muted)] text-[var(--foreground)]" : "text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:bg-[var(--surface-elevated)]"
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
          className="w-full min-w-0 rounded border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-2.5 py-1 text-xs text-[var(--foreground)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-blue-600 sm:w-48"
        />
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-[var(--text-tertiary)]" />
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="text-center py-10 border border-dashed border-red-900/50 rounded-xl space-y-3">
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto" />
          <p className="text-red-400 text-sm">Failed to load audit log</p>
          <p className="text-[var(--text-tertiary)] text-xs">{error}</p>
          <button
            onClick={load}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[var(--surface-elevated)] hover:bg-[var(--surface-muted)] border border-[var(--border-subtle)] rounded-lg text-xs text-[var(--text-secondary)] transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Retry
          </button>
        </div>
      )}

      {/* Entries */}
      {!loading && !error && (
        <>
          {entries.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-[var(--border-subtle)] rounded-xl">
              <FileText className="w-8 h-8 text-[var(--text-tertiary)] mx-auto mb-3" />
              <p className="text-[var(--text-tertiary)] text-sm">
                {auditUnavailable ? "No runtime audit surfaces enabled" : "No audit log entries"}
              </p>
              <p className="text-[var(--text-tertiary)] text-xs mt-1">
                {auditUnavailable
                  ? "Enable proxy, gateway, or trace ingest to populate runtime audit history."
                  : "Entries will appear as scan, policy, and fleet actions are performed."}
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              {entries?.map((entry) => {
                const isExpanded = expanded.has(entry.entry_id);
                return (
                  <div
                    key={entry.entry_id}
                    className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-lg overflow-hidden"
                  >
                    <button
                      onClick={() => toggleExpand(entry.entry_id)}
                      className="w-full px-4 py-2.5 flex items-center justify-between hover:bg-[var(--surface-elevated)]/50 transition-colors"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded border shrink-0 ${
                            ACTION_COLORS[entry.action] ?? ACTION_COLORS.config
                          }`}
                        >
                          {entry.action}
                        </span>
                        <span className="text-xs text-[var(--text-secondary)] font-mono shrink-0">
                          {entry.actor}
                        </span>
                        <span className="text-xs text-[var(--text-tertiary)] truncate">
                          {entry.resource}
                        </span>
                      </div>
                      <span className="text-[10px] text-[var(--text-tertiary)] shrink-0 ml-3">
                        {formatDate(entry.timestamp)}
                      </span>
                    </button>
                    {isExpanded && (
                      <div className="border-t border-[var(--border-subtle)] px-4 py-3 space-y-2">
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                          <div>
                            <span className="text-[var(--text-tertiary)]">Entry ID</span>
                            <div className="text-[var(--text-secondary)] mt-0.5 font-mono text-[10px] break-all">
                              {entry.entry_id}
                            </div>
                          </div>
                          <div>
                            <span className="text-[var(--text-tertiary)]">Timestamp</span>
                            <div className="text-[var(--text-secondary)] mt-0.5">
                              {formatDate(entry.timestamp)}
                            </div>
                          </div>
                          <div>
                            <span className="text-[var(--text-tertiary)]">Actor</span>
                            <div className="text-[var(--text-secondary)] mt-0.5 font-mono">
                              {entry.actor}
                            </div>
                          </div>
                          <div>
                            <span className="text-[var(--text-tertiary)]">HMAC</span>
                            <div className="text-[var(--text-secondary)] mt-0.5 font-mono text-[10px] truncate">
                              {entry.hmac_signature.slice(0, 16)}…
                            </div>
                          </div>
                        </div>
                        {Object.keys(entry.details).length > 0 && (
                          <div>
                            <span className="text-xs text-[var(--text-tertiary)] block mb-1">
                              Details
                            </span>
                            <pre className="text-[11px] text-[var(--text-secondary)] bg-[var(--surface-elevated)] border border-[var(--border-subtle)] rounded-lg p-3 overflow-x-auto max-h-48">
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

          {totalPages > 1 && (
            <PaginationBar
              page={page + 1}
              totalPages={totalPages}
              totalItems={total}
              itemLabel="entries"
              onPrevious={() => setPage((p) => Math.max(0, p - 1))}
              onNext={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              previousDisabled={page === 0}
              nextDisabled={page >= totalPages - 1}
              className="pt-2"
            />
          )}
        </>
      )}
    </div>
  );
}
