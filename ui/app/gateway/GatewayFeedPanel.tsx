"use client";

import { useEffect, useRef, useState } from "react";
import { Activity, Clock, RefreshCw } from "lucide-react";
import { formatDate } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { producerEvidenceLabel, PRODUCER_EVIDENCE_HINT } from "@/lib/gateway-feed";
import { ActivityStreamError, gatewayActivityPage, mergeActivity, streamGatewayActivity, type GatewayActivity, type ActivityPage } from "@/lib/gateway-activity";

const activityLabels: Record<string, string> = {
  "gateway.tool_call.allowed": "Tool call allowed", "gateway.tool_call.blocked": "Tool call blocked",
  "gateway.dlp.arguments_redacted": "Arguments redacted", "gateway.dlp.result_redacted": "Result redacted",
  "gateway.dlp.result_blocked": "Result blocked", "gateway.visual.redacted": "Visual data redacted",
  "gateway.visual_leak_blocked": "Visual leak blocked", "gateway.runtime_profile.blocked": "Profile blocked",
  "gateway.runtime_profile.warned": "Profile warning", "gateway.runtime_profile.dev_bypass": "Development bypass",
  "gateway.enforcement.warned": "Enforcement warning", "gateway.enforcement.observed": "Enforcement observation",
  "gateway.enforcement.blocked": "Enforcement blocked",
};

const messages = {
  connecting: "Connecting to durable activity…",
  live: "Connected to durable activity",
  reconnecting: "Reconnecting from the last complete batch…",
  gap: "Activity gap: retained history moved or the cursor is invalid. The last complete batch is preserved.",
  auth: "Sign in with permission to read gateway activity.",
  unavailable: "Durable activity is unavailable. The last complete batch is preserved.",
  invalid: "Activity response could not be verified. The last complete batch is preserved.",
};
type StreamState = keyof typeof messages;

export function GatewayFeedPanel({ onActivity }: { onActivity?: () => void }) {
  const { session } = useAuthState();
  return <ActivityFeed key={`${session?.tenant_id ?? ""}:${session?.subject ?? ""}`} onActivity={onActivity} tenantId={session?.tenant_id ?? undefined} />;
}

function ActivityFeed({ onActivity, tenantId }: { onActivity: (() => void) | undefined; tenantId: string | undefined }) {
  const [events, setEvents] = useState<GatewayActivity[]>([]);
  const [state, setState] = useState<StreamState>("connecting");
  const [filter, setFilter] = useState("");
  const [epoch, setEpoch] = useState(0);
  const [history, setHistory] = useState(false);
  const [latest, setLatest] = useState<number | null>(null);
  const cursor = useRef<string | undefined>(undefined);
  const tenant = useRef<string | undefined>(undefined);
  const rows = useRef<GatewayActivity[]>([]);
  const notify = useRef(onActivity);
  useEffect(() => { notify.current = onActivity; }, [onActivity]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let notifiedAt = 0;
    const connect = async () => {
      try {
        for await (const page of streamGatewayActivity(cursor.current, controller.signal, tenantId)) {
          if (controller.signal.aborted) return;
          if (tenant.current && tenant.current !== page.tenant_id) {
            rows.current = []; cursor.current = undefined; setEvents([]);
            setState("auth"); return;
          }
          tenant.current = page.tenant_id;
          rows.current = mergeActivity(rows.current, page.events);
          setEvents(rows.current);
          // Advance only after the entire batch is merged into the local view.
          cursor.current = page.next_cursor;
          setLatest(page.latest_ordinal);
          setState("live");
          failures = 0;
          if (page.events.length && Date.now() - notifiedAt > 3000) {
            notifiedAt = Date.now(); notify.current?.();
          }
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        const kind = error instanceof ActivityStreamError ? error.kind : "transport";
        if (kind !== "transport") { setState(kind); return; }
        failures += 1;
        if (failures > 5) { setState("unavailable"); return; }
      }
      if (!controller.signal.aborted) {
        setState("reconnecting");
        timer = setTimeout(() => void connect(), Math.min(1000 * 2 ** failures, 30000));
      }
    };
    const start = setTimeout(() => void connect(), 0);
    return () => { clearTimeout(start); clearTimeout(timer); controller.abort(); };
  }, [epoch, tenantId]);

  const reconnect = (restart = false) => {
    if (restart) { cursor.current = undefined; rows.current = []; tenant.current = undefined; setEvents([]); setLatest(null); }
    setState("connecting"); setEpoch(value => value + 1);
  };
  const receiptTime = events[0]?.ingested_at;
  const staleReceipt = Boolean(receiptTime && Date.now() - Date.parse(receiptTime) > 120000);
  const visible = events.filter(row => !filter || (filter === "deny" ? row.decision === "deny" : filter === "data" ? /dlp|visual/.test(row.event_type) : row.event_type.includes(filter)));

  return <section className="min-w-0 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4 sm:p-5" aria-label="Gateway activity">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h3 className="flex items-center gap-2 text-sm font-semibold"><Activity className="h-4 w-4" />Gateway activity</h3>
        <p className="mt-1 text-xs text-[var(--text-secondary)]">Canonical tool calls, data filters, profile and enforcement decisions.</p>
        <p className="mt-1 text-xs text-[var(--text-secondary)]" role="status">{messages[state]}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <button className="graph-page-action" onClick={() => setHistory(value => !value)}>{history ? "Return to recent activity" : "Browse retained history"}</button>
        {state === "gap" ? <button className="graph-page-action" onClick={() => reconnect(true)}>Start a new retained window</button> :
          <button className="graph-page-action" onClick={() => reconnect()}><RefreshCw className="h-3 w-3" />Reconnect</button>}
      </div>
    </div>
    <p className="my-3 text-xs text-[var(--text-tertiary)]">Newest {events.length} events in this view · ledger position {latest ?? "unavailable"}. History is paged separately; reconnects do not reset the cursor.</p>
    {staleReceipt && <p className="mb-3 text-xs text-amber-800 dark:text-amber-200">Latest receipt is older than 2 minutes. A connected transport does not prove current producer activity.</p>}
    {history ? <RetainedHistory tenantId={tenant.current ?? tenantId} /> : <>
      <div className="mb-3 flex flex-wrap gap-2" aria-label="Activity filters">
        {[["", "All"], ["deny", "Blocked"], ["data", "Data filters"], ["runtime_profile", "Profile decisions"], ["enforcement", "Enforcement"]].map(([value, label]) =>
          <button key={label} onClick={() => setFilter(value ?? "")} aria-pressed={filter === value} className={`rounded px-2 py-1 text-xs ${filter === value ? "bg-[var(--surface-muted)] text-[var(--foreground)]" : "text-[var(--text-secondary)]"}`}>{label}</button>)}
      </div>
      {!visible.length && <p className="py-6 text-sm text-[var(--text-secondary)]">{events.length ? "No activity matches this filter." : state === "live" ? "No retained gateway activity yet." : "No verified activity loaded."}</p>}
      <ActivityRows events={visible} />
    </>}
  </section>;
}

function RetainedHistory({ tenantId }: { tenantId: string | undefined }) {
  const [page, setPage] = useState<ActivityPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    void gatewayActivityPage(cursor, controller.signal, tenantId).then(result => {
      if (!controller.signal.aborted) { setPage(result); setError(null); setLoading(false); }
    }).catch(caught => {
      if (controller.signal.aborted) return;
      setError(caught instanceof ActivityStreamError && caught.kind === "gap" ? "History expired. Choose Restart history to read the currently retained window." : "Retained history is unavailable. Retry without advancing the page.");
      setLoading(false);
    });
    return () => controller.abort();
  }, [cursor, epoch, tenantId]);
  return <div>
    <div className="mb-3 flex flex-wrap items-center gap-3">
      <span className="text-xs text-[var(--text-secondary)]">Retained history · oldest pages first</span>
      <button className="graph-page-action" disabled={loading} onClick={() => { setLoading(true); setCursor(undefined); setEpoch(n => n + 1); }}>Restart history</button>
      {error ? <button className="graph-page-action" onClick={() => { setLoading(true); setEpoch(n => n + 1); }}>Retry history</button> : null}
      <button className="graph-page-action" disabled={loading || !page?.has_more || Boolean(error)} onClick={() => { setLoading(true); setCursor(page?.next_cursor); }}>Next retained page</button>
    </div>
    {loading ? <p role="status">Loading retained page…</p> : null}
    {error ? <p role="alert" className="text-sm text-amber-800 dark:text-amber-200">{error}</p> : null}
    {page && <ActivityRows events={[...page.events].reverse()} />}
  </div>;
}

function ActivityRows({ events }: { events: GatewayActivity[] }) {
  return <div className="max-h-[36rem] space-y-1 overflow-y-auto">
    {events.map(event => <article key={event.event_id} className="min-w-0 border-b border-[var(--border-subtle)] py-3 text-xs" data-testid="gateway-activity-row">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="min-w-0 break-all font-medium">{event.agent_id || "Unattributed agent"} → {event.upstream || "Gateway"}{event.tool ? ` / ${event.tool}` : ""}</p>
        <span className={event.decision === "deny" ? "text-red-700 dark:text-red-300" : "text-[var(--text-secondary)]"}>{activityLabels[event.event_type] ?? "Gateway decision"}</span>
      </div>
      <p className="mt-1 break-all text-[var(--text-secondary)]">Profile {event.profile_id || "unavailable"} · revision {event.profile_revision || "unavailable"} · blueprint {event.blueprint_id || "unavailable"} / {event.blueprint_revision || "unavailable"}</p>
      <p className="mt-1 break-all text-[var(--text-secondary)]">Policies: {event.policy_ids?.length ? event.policy_ids.join(", ") : event.policy_id || "unavailable"} · Evidence: {event.evidence_id || "unavailable"}</p>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[var(--text-tertiary)]">
        <span title={PRODUCER_EVIDENCE_HINT}>{producerEvidenceLabel(event.submission_provenance?.producer_assurance)}</span>
        <span>{(event.reason_code || event.data_action || "No reason recorded").replaceAll("_", " ")}</span>
        {event.development_mode ? <strong className="text-amber-800 dark:text-amber-200">Development bypass</strong> : null}
        <span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" />Received {event.ingested_at ? formatDate(event.ingested_at) : "unavailable"}</span>
        {event.trace_id ? <a className="text-sky-800 underline dark:text-sky-200" href={`/security-graph?${new URLSearchParams({ trace: event.trace_id, agent: event.agent_id })}`}>Pin trace</a> : null}
      </div>
      <details className="mt-2 text-[var(--text-secondary)]"><summary className="cursor-pointer">Receipt details</summary><p className="mt-1 break-all">{event.event_type} · event {event.event_id} · identity {event.identity_id || "unavailable"} · receipt trace {event.receipt_trace_id || "unavailable"} · reported time {event.event_timestamp || "unavailable"}</p></details>
    </article>)}
  </div>;
}
