"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, CircleAlert, Search } from "lucide-react";

import { Drawer } from "@/components/drawer";
import {
  api,
  formatDate,
  type ActivityTimeline,
  type GatewayFeedEvent,
  type GatewayFeedHealth,
} from "@/lib/api";

type ObservabilityEvent = ActivityTimeline["observability_events"][number];

interface ActivityEvent {
  id: string;
  source: "Gateway" | "AI observability";
  timestamp: string;
  actor: string;
  target: string;
  kind: string;
  decision: string | null;
  policy: string | null;
  latencyMs: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  cost: string | null;
  traceId: string | null;
  provenance: string | null;
  detail: string | null;
  blocked: boolean;
}

function gatewayDecision(event: GatewayFeedEvent): string | null {
  if (event.decision?.trim()) return event.decision.trim();
  if (event.action_type === "tool_call_blocked") return "Blocked";
  if (event.action_type === "tool_call_authorized") return "Allowed";
  if (event.action_type === "data_filter_applied") return "Filtered";
  if (event.action_type === "llm_call") return "Routed";
  return null;
}

function normalizeGatewayEvent(event: GatewayFeedEvent, index: number): ActivityEvent {
  return {
    id: event.event_id ?? `${event.ts}-${event.agent}-${event.target}-${index}`,
    source: "Gateway",
    timestamp: event.ts,
    actor: event.agent || "Unavailable",
    target: event.target || "Unavailable",
    kind: event.action_type.replaceAll("_", " "),
    decision: gatewayDecision(event),
    policy: event.policy_source?.trim() || null,
    latencyMs: null,
    inputTokens: null,
    outputTokens: null,
    cost: null,
    traceId: event.trace_id?.trim() || null,
    provenance: event.source?.trim() || null,
    detail: event.detail?.trim() || null,
    blocked: event.action_type === "tool_call_blocked",
  };
}

function finiteMeasurement(value: number): number | null {
  return Number.isFinite(value) && value >= 0 ? value : null;
}

function normalizeObservabilityEvent(event: ObservabilityEvent): ActivityEvent {
  return {
    id: event.event_id,
    source: "AI observability",
    timestamp: event.timestamp,
    actor: event.agent_name || "Unavailable",
    target: event.tool_name || event.model_name || event.event_type || "Unavailable",
    kind: event.event_type || "Observability event",
    decision: event.status?.trim() || null,
    policy: null,
    latencyMs: finiteMeasurement(event.duration_ms),
    inputTokens: finiteMeasurement(event.input_tokens),
    outputTokens: finiteMeasurement(event.output_tokens),
    cost: null,
    traceId: event.trace_id?.trim() || null,
    provenance: event.trace_id?.trim() ? "Trace telemetry" : null,
    detail: null,
    blocked: event.status === "FAILED" || event.status === "DENIED",
  };
}

function timestampValue(value: string): number {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function healthLabel(health: GatewayFeedHealth | null): string {
  if (health?.state === "live" && health.live === true) return "Live gateway";
  if (health?.state === "sample") return "Sample gateway";
  if (health?.state === "stale") return "Stale gateway";
  return "Gateway unavailable";
}

function display(value: string | number | null): string {
  if (value === null || value === "") return "Unavailable";
  return typeof value === "number" ? value.toLocaleString() : value;
}

export interface ActivityEventStreamProps {
  observabilityEvents: ObservabilityEvent[];
}

export function ActivityEventStream({
  observabilityEvents,
}: ActivityEventStreamProps) {
  const [gatewayEvents, setGatewayEvents] = useState<GatewayFeedEvent[]>([]);
  const [gatewayHealth, setGatewayHealth] = useState<GatewayFeedHealth | null>(null);
  const [gatewayLoading, setGatewayLoading] = useState(true);
  const [selected, setSelected] = useState<ActivityEvent | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const response = await api.getGatewayFeed(100);
        if (cancelled) return;
        setGatewayEvents(response.events);
        setGatewayHealth(response.health);
      } catch {
        if (cancelled) return;
        setGatewayEvents([]);
        setGatewayHealth(null);
      } finally {
        if (!cancelled) setGatewayLoading(false);
      }
    };

    const timer = window.setTimeout(() => void load(), 0);
    const interval = window.setInterval(() => void load(), 15000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      window.clearInterval(interval);
    };
  }, []);

  const events = useMemo(() => {
    const normalized = [
      ...gatewayEvents.map(normalizeGatewayEvent),
      ...observabilityEvents.map(normalizeObservabilityEvent),
    ].sort((left, right) => timestampValue(right.timestamp) - timestampValue(left.timestamp));
    const query = search.trim().toLowerCase();
    if (!query) return normalized;
    return normalized.filter((event) =>
      [
        event.actor,
        event.target,
        event.kind,
        event.decision,
        event.policy,
        event.source,
        event.traceId,
      ].some((value) => value?.toLowerCase().includes(query)),
    );
  }, [gatewayEvents, observabilityEvents, search]);

  const liveGateway = gatewayHealth?.state === "live" && gatewayHealth.live === true;

  return (
    <section className="overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)]">
      <div className="flex flex-col gap-3 border-b border-[var(--border-subtle)] px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-[var(--foreground)]">Event stream</h2>
            <span
              className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                liveGateway
                  ? "border-emerald-800 bg-emerald-950 text-emerald-400"
                  : "border-[var(--border-subtle)] bg-[var(--surface-elevated)] text-[var(--text-secondary)]"
              }`}
            >
              {healthLabel(gatewayHealth)}
            </span>
          </div>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            Gateway decisions and AI telemetry ordered by recorded observation time.
          </p>
        </div>
        <label className="relative w-full md:w-72">
          <span className="sr-only">Search activity</span>
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-tertiary)]" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search actor, target, policy…"
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-muted)] py-1.5 pl-9 pr-3 text-sm text-[var(--text-secondary)] placeholder:text-[var(--text-tertiary)]"
          />
        </label>
      </div>

      {gatewayLoading && events.length === 0 ? (
        <p className="px-4 py-8 text-center text-xs text-[var(--text-tertiary)]">
          Loading activity…
        </p>
      ) : events.length === 0 ? (
        <div className="flex items-center justify-center gap-2 px-4 py-8 text-xs text-[var(--text-tertiary)]">
          <CircleAlert className="h-4 w-4" />
          No observed activity matches this view.
        </div>
      ) : (
        <ul className="max-h-[34rem] divide-y divide-[var(--border-subtle)] overflow-y-auto">
          {events.map((event) => (
            <li key={`${event.source}-${event.id}`}>
              <button
                type="button"
                onClick={() => setSelected(event)}
                className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[var(--surface-elevated)]/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-emerald-500"
              >
                <span
                  className={`mt-1.5 h-2 w-2 rounded-full ${event.blocked ? "bg-red-500" : "bg-emerald-500"}`}
                  aria-label={event.blocked ? "blocked or failed" : "allowed or successful"}
                />
                <span className="min-w-0">
                  <span className="block truncate text-sm font-medium text-[var(--foreground)]">
                    {event.actor} → {event.target}
                  </span>
                  <span className="mt-0.5 block truncate text-xs text-[var(--text-tertiary)]">
                    {event.source} · {event.kind} · {display(event.decision)}
                  </span>
                </span>
                <time className="whitespace-nowrap text-[10px] tabular-nums text-[var(--text-tertiary)]">
                  {event.timestamp ? formatDate(event.timestamp) : "Unavailable"}
                </time>
              </button>
            </li>
          ))}
        </ul>
      )}

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        ariaLabel="Activity event details"
        eyebrow={selected?.source}
        title={selected ? `${selected.actor} → ${selected.target}` : "Activity event"}
        subtitle={selected?.kind}
        size="lg"
      >
        {selected ? (
          <div className="space-y-5">
            <dl className="grid grid-cols-2 gap-x-5 gap-y-4">
              <Detail label="Actor" value={selected.actor} />
              <Detail label="Target" value={selected.target} />
              <Detail label="Decision" value={selected.decision} />
              <Detail label="Policy" value={selected.policy} />
              <Detail
                label="Latency"
                value={selected.latencyMs === null ? null : `${selected.latencyMs.toLocaleString()} ms`}
              />
              <Detail
                label="Tokens"
                value={
                  selected.inputTokens === null || selected.outputTokens === null
                    ? null
                    : `${(selected.inputTokens + selected.outputTokens).toLocaleString()} total`
                }
              />
              <Detail label="Cost" value={selected.cost} />
              <Detail
                label="Observed"
                value={selected.timestamp ? formatDate(selected.timestamp) : null}
              />
              <Detail label="Trace" value={selected.traceId} />
              <Detail label="Provenance" value={selected.provenance} />
            </dl>
            {selected.detail ? (
              <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-muted)] p-4">
                <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
                  Recorded detail
                </h3>
                <p className="mt-2 text-sm text-[var(--text-secondary)]">{selected.detail}</p>
              </div>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </section>
  );
}

function Detail({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
        {label}
      </dt>
      <dd className="mt-1 break-words text-sm text-[var(--foreground)]">{display(value)}</dd>
    </div>
  );
}
