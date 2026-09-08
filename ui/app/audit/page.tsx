"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import {
  api,
  type ApiKeyRecord,
  type AuditEntry,
  type AuditIntegrityResponse,
  type AuthPolicyResponse,
  formatDate,
} from "@/lib/api";
import { PaginationBar } from "@/components/pagination-bar";
import { RefreshCw, ChevronDown, ChevronRight } from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { KeyLifecyclePanel } from "@/components/key-lifecycle-panel";
import { AuditEvidencePanel } from "@/components/audit-evidence-panel";
import { PageLaneHeader } from "@/components/page-lane";
import { Collapsible } from "@/components/collapsible";

const PAGE_SIZE = 50;
const FIELD = "min-w-0 rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-2 text-sm";
const textDetail = (entry: AuditEntry, key: string) => typeof entry.details?.[key] === "string" ? entry.details[key] as string : "";

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AuditLogPage() {
  const { session, loading: authSessionLoading, hasCapability } = useAuthState();
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

  const requestId = useRef(0);
  const [since, setSince] = useState("");
  const [range, setRange] = useState("all");

  // Filters
  const [actionFilter, setActionFilter] = useState<string>("");
  const [resourceFilter, setResourceFilter] = useState<string>("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const roleLabel = session?.role_summary?.display_name ?? session?.role ?? "Unknown";
  const canManageKeys = hasCapability("keys.manage");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const id = ++requestId.current;
    const [log, integ] = await Promise.allSettled([
      api.listAuditEntries({
        action: actionFilter || undefined,
        resource: resourceFilter || undefined,
        since: since || undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
      api.getAuditIntegrity(1000, false),
    ]);
    if (id !== requestId.current) return;
    if (log.status === "fulfilled") {
      setEntries(log.value.entries);
      setTotal(log.value.total);
    } else {
      setEntries([]);
      setTotal(0);
      setError("Audit events are unavailable. Check your connection and audit access, then retry.");
    }
    setIntegrity(integ.status === "fulfilled" ? integ.value : null);
    setLoading(false);
  }, [actionFilter, resourceFilter, since, page]);

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
    const timer = window.setTimeout(() => { void load(); }, 150);
    return () => { window.clearTimeout(timer); requestId.current += 1; };
  }, [load]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!authSessionLoading && canManageKeys) void loadAdmin();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [authSessionLoading, canManageKeys, loadAdmin]);

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
    <div className="space-y-5">
      <PageLaneHeader lane="governance" title="Audit Log"
        subtitle="Trace human and agent actions to their recorded evidence."
        actions={<button onClick={() => { void load(); }} className={`${FIELD} flex items-center gap-2`}>
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>}
      />

      <section aria-label="Control-plane integrity" className="border-y border-[var(--border-subtle)] py-3 text-sm">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <strong className={integrity?.tampered ? "text-red-600 dark:text-red-400" : ""}>
            {loading ? "Checking integrity…" : !integrity ? "Integrity unavailable" : integrity.tampered
              ? `${integrity.tampered.toLocaleString()} integrity exceptions need review`
              : integrity.checked ? "No integrity exceptions detected" : "No records checked"}
          </strong>
          {integrity && !loading && <span className="text-[var(--text-secondary)]">
            {integrity.verified.toLocaleString()} verified / {integrity.checked.toLocaleString()} checked
          </span>}
        </div>
        <p className="mt-1 text-xs text-[var(--text-tertiary)]">Current tenant · Control-plane records across all actions and dates. Independent of the event filters below; runtime logs are excluded.</p>
      </section>

      <section aria-label="Audit trail" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-base font-semibold">Audit trail</h2>
          <span aria-live="polite" className="text-sm text-[var(--text-secondary)]">
            {loading ? "Loading events…" : error ? "Events unavailable" : `${total.toLocaleString()} matching events`}
          </span>
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          <label className="grid gap-1 text-xs text-[var(--text-secondary)]">Time range
            <select className={FIELD} value={range} onChange={(e) => {
              const value = e.target.value;
              setRange(value);
              setSince(value === "all" ? "" : new Date(Date.now() - Number(value) * 86400000).toISOString());
              setPage(0);
            }}>
              <option value="all">All retained events</option><option value="1">Last 24 hours</option>
              <option value="7">Last 7 days</option><option value="30">Last 30 days</option>
            </select>
          </label>
          <label className="grid gap-1 text-xs text-[var(--text-secondary)]">Action (exact name)
            <input aria-label="Action (exact name)" className={FIELD} value={actionFilter} list="audit-actions" placeholder="All actions"
              onChange={(e) => { setActionFilter(e.target.value); setPage(0); }} />
            <datalist id="audit-actions">{Array.from(new Set(entries.map((e) => e.action))).map((action) => <option key={action} value={action}>{action}</option>)}</datalist>
          </label>
          <label className="grid gap-1 text-xs text-[var(--text-secondary)]">Resource prefix
            <input className={FIELD} value={resourceFilter} placeholder="Filter by resource…"
              onChange={(e) => { setResourceFilter(e.target.value); setPage(0); }} />
          </label>
        </div>
        {error && !loading && <p role="alert" className="py-4 text-sm text-red-600 dark:text-red-400">{error}</p>}
        {!loading && !error && entries.length === 0 && <p className="py-6 text-sm text-[var(--text-secondary)]">No events match this scope. Adjust the filters or record an action to begin an audit trail.</p>}
        {!loading && !error && entries.length > 0 && <div className="divide-y divide-[var(--border-subtle)] border-y border-[var(--border-subtle)]">
          <div aria-hidden="true" className="hidden grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)_minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.4fr)_1rem] gap-3 py-2 text-xs text-[var(--text-tertiary)] lg:grid">
            <span>Action</span><span>Actor</span><span>Resource</span><span>Recorded outcome</span><span>Time</span><span />
          </div>
          {entries.map((entry) => {
            const isExpanded = expanded.has(entry.entry_id);
            const outcome = textDetail(entry, "outcome") || textDetail(entry, "decision") || textDetail(entry, "status") || "Not recorded";
            const finding = textDetail(entry, "finding_id");
            const cve = textDetail(entry, "cve");
            const node = textDetail(entry, "node_id");
            const scan = textDetail(entry, "scan_id");
            const graphParams = new URLSearchParams({ ...(scan ? { scan } : {}), ...(node ? { node } : {}), ...(cve ? { cve } : {}), ...(finding ? { finding } : {}) });
            const Chevron = isExpanded ? ChevronDown : ChevronRight;
            return <div key={entry.entry_id}>
              <button aria-expanded={isExpanded} aria-controls={`evidence-${entry.entry_id}`} onClick={() => toggleExpand(entry.entry_id)}
                className="grid w-full grid-cols-[minmax(0,1fr)_1rem] gap-2 py-4 text-left text-sm hover:bg-[var(--surface-elevated)] focus-visible:outline-2 focus-visible:outline-emerald-500 lg:grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)_minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.4fr)_1rem] lg:gap-3">
                <span className="break-words font-medium">{entry.action}</span>
                <span className="col-start-1 break-words text-[var(--text-secondary)] lg:col-auto"><span className="lg:hidden">Actor: </span>{entry.actor}</span>
                <span className="col-start-1 break-all text-[var(--text-secondary)] lg:col-auto">{entry.resource}</span>
                <span className="col-start-1 text-[var(--text-secondary)] lg:col-auto"><span className="lg:hidden">Outcome: </span>{outcome}</span>
                <time dateTime={entry.timestamp} className="col-start-1 text-xs text-[var(--text-tertiary)] lg:col-auto">{formatDate(entry.timestamp)}</time>
                <Chevron className="col-start-2 row-start-1 h-4 w-4 self-center lg:col-auto" />
              </button>
              {isExpanded && <div id={`evidence-${entry.entry_id}`} className="space-y-3 border-l-2 border-emerald-600 pb-4 pl-4 text-sm">
                <p className="break-all text-xs text-[var(--text-secondary)]">Event ID: {entry.entry_id} · {entry.hmac_signature ? "Signature recorded; the aggregate check does not provide a per-event verdict." : "No signature recorded."}</p>
                <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
                  {([["agent_id", "Agent"], ["owner", "Owner"], ["reason", "Reason"], ["rotated_from", "Previous identity"], ["source_receipt_id", "Source receipt"]] as const).map(([key, label]) => textDetail(entry, key) && <div key={key}>
                    <dt className="text-xs text-[var(--text-tertiary)]">{label}</dt><dd className="break-all">{textDetail(entry, key)}</dd>
                  </div>)}
                </dl>
                {["before", "after"].some((key) => entry.details?.[key] !== undefined) && <div className="grid items-start gap-3 sm:grid-cols-2">
                  {["before", "after"].map((key) => entry.details?.[key] !== undefined && <div key={key}>
                    <h3 className="mb-1 font-medium capitalize">{key}</h3>
                    <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(entry.details[key], null, 2)}</pre>
                  </div>)}
                </div>}
                <div className="flex flex-wrap gap-4 text-emerald-700 dark:text-emerald-400">
                  {graphParams.size > 0 && <a href={`/security-graph?${graphParams}`}>Open in security graph →</a>}
                  {(finding || cve) && <a href={`/findings?${new URLSearchParams(finding ? { finding } : { cve })}`}>Open finding →</a>}
                </div>
                <details><summary className="cursor-pointer text-[var(--text-secondary)]">Structured event evidence</summary>
                  <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs text-[var(--text-secondary)]">{JSON.stringify(entry, null, 2)}</pre>
                </details>
              </div>}
            </div>;
          })}
        </div>}
        {!loading && !error && totalPages > 1 && <PaginationBar page={page + 1} totalPages={totalPages} totalItems={total} itemLabel="events"
          onPrevious={() => setPage((p) => Math.max(0, p - 1))} onNext={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
          previousDisabled={page === 0} nextDisabled={page >= totalPages - 1} />}
      </section>

      <div className="divide-y divide-[var(--border-subtle)] border-y border-[var(--border-subtle)]">
        <Collapsible bare title="Export and verify evidence" defaultOpen={false} titleClassName="text-sm font-medium">
          <AuditEvidencePanel />
        </Collapsible>
        {canManageKeys && <Collapsible bare title="Key management and revocation" defaultOpen={false} titleClassName="text-sm font-medium">
          <KeyLifecyclePanel loading={adminLoading} error={adminError} policy={authPolicy} keys={keys} onRefresh={loadAdmin} roleLabel={roleLabel} />
        </Collapsible>}
      </div>
    </div>
  );
}
