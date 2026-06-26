"use client";

/**
 * Gateway Live Feed card (#54).
 *
 * One self-contained card that renders the most recent gateway decisions as a
 * compact, glanceable stream. Each row is:
 *   • a status dot — green = allowed, red = blocked/denied
 *   • a decision title (e.g. "Tool call authorized", "Shadow AI detected")
 *   • the agent → tool.action path in monospace
 *   • a muted sub-label — the calling profile (tenant) or the decision note
 * with an aggregate footer summarising the day.
 *
 * Data source: the live gateway feed (`/v1/gateway/feed` + `/v1/gateway/feed/kpis`)
 * already exposed by `api.getGatewayFeed` / `api.getGatewayFeedKpis`. When the
 * API is unreachable or returns no events (e.g. a fresh install with no proxy
 * traffic), the card falls back to a clearly-labelled sample so the surface is
 * never blank; the fallback is marked "sample data" so it is never mistaken for
 * live fleet activity.
 */

import { useEffect, useState } from "react";
import { Activity } from "lucide-react";
import {
  api,
  formatDate,
  type GatewayFeedEvent,
  type GatewayFeedKpis,
} from "@/lib/api";

// ── Sample fallback (illustrative only — never live data) ────────────────────

const SAMPLE_FEED_EVENTS: GatewayFeedEvent[] = [
  {
    ts: "2026-06-26T14:31:07Z",
    agent: "payroll-agent",
    action_type: "data_filter_applied",
    target: "snowflake.query",
    detail: "Resume data masked",
    tenant: "eng-team",
    shadow: false,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:30:52Z",
    agent: "unknown-mcp-client",
    action_type: "tool_call_blocked",
    target: "github.create_pull_request",
    detail: "Shadow AI detected",
    tenant: "platform",
    shadow: true,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:30:41Z",
    agent: "support-copilot",
    action_type: "tool_call_authorized",
    target: "zendesk.update_ticket",
    detail: "authorized",
    tenant: "support",
    shadow: false,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:30:18Z",
    agent: "finance-reconciliation-agent",
    action_type: "tool_call_blocked",
    target: "stripe.create_refund",
    detail: "Amount exceeds policy ceiling",
    tenant: "finance",
    shadow: false,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:29:55Z",
    agent: "data-analyst-agent",
    action_type: "llm_call",
    target: "anthropic/claude-opus-4",
    detail: "$0.0142 · 3,210 tokens",
    tenant: "analytics",
    shadow: false,
    source: "observability",
  },
  {
    ts: "2026-06-26T14:29:30Z",
    agent: "recruiting-agent",
    action_type: "data_filter_applied",
    target: "workday.search_candidates",
    detail: "PII redacted",
    tenant: "people-ops",
    shadow: false,
    source: "proxy",
  },
];

const SAMPLE_KPIS: GatewayFeedKpis = {
  schema_version: "1.0",
  tenant_id: "sample",
  generated_at: "2026-06-26T14:31:07Z",
  calls_today: 4485,
  blocked_today: 312,
  shadow_ai_blocked: 247,
  data_filters_applied: 1893,
  tool_calls_authorized: 4173,
  llm_calls: 1204,
  uptime_seconds: 18732,
};

// ── Presentation helpers ─────────────────────────────────────────────────────

function isBlocked(event: GatewayFeedEvent): boolean {
  return event.action_type === "tool_call_blocked";
}

function decisionTitle(event: GatewayFeedEvent): string {
  if (event.shadow) return "Shadow AI detected";
  switch (event.action_type) {
    case "tool_call_authorized":
      return "Tool call authorized";
    case "tool_call_blocked":
      return event.detail && event.detail !== "blocked by gateway policy"
        ? capitalize(event.detail)
        : "Tool call blocked";
    case "data_filter_applied":
      return event.detail ? capitalize(event.detail) : "Sensitive data masked";
    case "llm_call":
      return "LLM call routed";
    default:
      return "Gateway decision";
  }
}

function subLabel(event: GatewayFeedEvent): string {
  const tenant = event.tenant?.trim();
  if (tenant && tenant !== "unknown" && tenant !== "default") {
    return `${tenant} profile`;
  }
  return event.detail?.trim() || "—";
}

function capitalize(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

function eventTime(ts: string): string {
  if (!ts) return "—";
  try {
    return formatDate(ts);
  } catch {
    return ts;
  }
}

function footerText(kpis: GatewayFeedKpis | null): string {
  if (!kpis) return "Awaiting gateway telemetry";
  const parts = [`${kpis.calls_today.toLocaleString()} calls today`];
  if (kpis.uptime_seconds != null) {
    parts.push(`${formatUptime(kpis.uptime_seconds)} uptime`);
  }
  parts.push(`${kpis.shadow_ai_blocked.toLocaleString()} shadow AIs blocked`);
  return parts.join(" · ");
}

// ── Component ────────────────────────────────────────────────────────────────

interface GatewayLiveFeedCardProps {
  maxItems?: number;
  className?: string;
}

export function GatewayLiveFeedCard({
  maxItems = 8,
  className,
}: GatewayLiveFeedCardProps) {
  const [events, setEvents] = useState<GatewayFeedEvent[]>([]);
  const [kpis, setKpis] = useState<GatewayFeedKpis | null>(null);
  const [loading, setLoading] = useState(true);
  const [isSample, setIsSample] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      const [feedResult, kpiResult] = await Promise.allSettled([
        api.getGatewayFeed(maxItems),
        api.getGatewayFeedKpis(),
      ]);
      if (cancelled) return;

      const liveEvents =
        feedResult.status === "fulfilled" ? feedResult.value.events : [];
      const liveKpis = kpiResult.status === "fulfilled" ? kpiResult.value : null;

      if (liveEvents.length > 0) {
        setEvents(liveEvents);
        setKpis(liveKpis);
        setIsSample(false);
      } else {
        // No live traffic (or API unreachable): show a labelled sample so the
        // card always renders something meaningful.
        setEvents(SAMPLE_FEED_EVENTS);
        setKpis(liveKpis ?? SAMPLE_KPIS);
        setIsSample(true);
      }
      setLoading(false);
    };

    const timer = window.setTimeout(() => void load(), 0);
    const interval = window.setInterval(() => void load(), 15000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      window.clearInterval(interval);
    };
  }, [maxItems]);

  const rows = events.slice(0, maxItems);

  return (
    <div
      data-testid="gateway-live-feed"
      className={`flex flex-col overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900 ${
        className ?? ""
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
        <h3 className="flex min-w-0 items-center gap-2 text-sm font-semibold text-zinc-200">
          <Activity className="h-4 w-4 shrink-0 text-emerald-400" />
          <span className="truncate">Gateway Live Feed</span>
        </h3>
        {isSample ? (
          <span className="shrink-0 rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-[10px] font-medium text-zinc-400">
            sample data
          </span>
        ) : (
          <span className="flex shrink-0 items-center gap-1.5 text-[10px] font-medium text-emerald-400">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
            </span>
            live
          </span>
        )}
      </div>

      {/* Rows */}
      {loading ? (
        <div className="px-4 py-8 text-center text-xs text-zinc-600">
          Loading gateway activity…
        </div>
      ) : rows.length === 0 ? (
        <div className="px-4 py-8 text-center text-xs text-zinc-600">
          No gateway activity yet.
        </div>
      ) : (
        <ul className="divide-y divide-zinc-800">
          {rows.map((event, i) => {
            const blocked = isBlocked(event);
            return (
              <li
                key={`${event.ts}-${event.agent}-${i}`}
                className="flex items-start gap-3 px-4 py-3 transition-colors hover:bg-zinc-800/40"
              >
                {/* Status dot */}
                <span
                  className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                    blocked ? "bg-red-500" : "bg-emerald-500"
                  }`}
                  aria-label={blocked ? "blocked" : "allowed"}
                />

                {/* Text column — min-w-0 lets children truncate instead of overflow */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="truncate text-sm font-medium text-zinc-100">
                      {decisionTitle(event)}
                    </span>
                    <time className="shrink-0 text-[10px] tabular-nums text-zinc-600">
                      {eventTime(event.ts)}
                    </time>
                  </div>
                  <code
                    className="mt-0.5 block truncate font-mono text-xs text-zinc-400"
                    title={`${event.agent} → ${event.target}`}
                  >
                    {event.agent} → {event.target}
                  </code>
                  <p className="mt-0.5 truncate text-xs text-zinc-500">
                    {subLabel(event)}
                  </p>
                </div>
              </li>
            );
          })}
        </ul>
      )}

      {/* Aggregate footer */}
      <div className="mt-auto border-t border-zinc-800 px-4 py-2.5">
        <p className="truncate text-center text-[11px] tabular-nums text-zinc-500">
          {footerText(kpis)}
        </p>
      </div>
    </div>
  );
}
