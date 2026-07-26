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
 * Data source: the gateway feed (`/v1/gateway/feed` +
 * `/v1/gateway/feed/kpis`) already exposed by `api.getGatewayFeed` /
 * `api.getGatewayFeedKpis`. Empty and unreachable feeds stay empty; only the
 * server may identify a response as synthetic sample data.
 */

import { useEffect, useState } from "react";
import {
  api,
  formatDate,
  type GatewayFeedEvent,
  type GatewayFeedHealth,
  type GatewayFeedKpis,
} from "@/lib/api";

// ── Presentation helpers ─────────────────────────────────────────────────────

function decisionTitle(event: GatewayFeedEvent): string {
  if (event.shadow) return "Shadow AI detected";
  switch (event.action_type) {
    case "tool_call_authorized":
      return "Tool call authorized";
    case "tool_call_blocked":
      return event.detail && event.detail !== "blocked by gateway policy"
        ? event.detail
        : "Tool call blocked";
    case "data_filter_applied":
      return event.detail || "Sensitive data masked";
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
  const [health, setHealth] = useState<GatewayFeedHealth | null>(null);

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

      setEvents(liveEvents);
      setKpis(liveKpis);
      setHealth(
        feedResult.status === "fulfilled" ? feedResult.value.health : null,
      );
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
  const healthState = health?.state ?? "unavailable";
  const isLive = healthState === "live" && health?.live === true;
  const healthLabel = healthState.charAt(0).toUpperCase() + healthState.slice(1);

  return (
    <div
      data-testid="gateway-live-feed"
      className={`flex flex-col overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] ${
        className ?? ""
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between gap-3 border-b border-[var(--border-subtle)] px-4 py-3">
        <h3 className="flex min-w-0 items-center gap-2 text-sm font-semibold text-[var(--foreground)]">
          <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-400" />
          <span className="truncate">Gateway activity</span>
        </h3>
        {healthState === "sample" ? (
          <span className="shrink-0 rounded-full border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-2 py-0.5 text-[10px] font-medium text-[var(--text-secondary)]">
            sample data
          </span>
        ) : isLive ? (
          <span className="flex shrink-0 items-center gap-1.5 text-[10px] font-medium text-emerald-400">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
            </span>
            live
          </span>
        ) : (
          <span className="shrink-0 rounded-full border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-2 py-0.5 text-[10px] font-medium capitalize text-[var(--text-secondary)]">
            {healthLabel}
          </span>
        )}
      </div>

      {/* Rows */}
      {loading ? (
        <div className="px-4 py-8 text-center text-xs text-[var(--text-tertiary)]">
          Loading gateway activity…
        </div>
      ) : rows.length === 0 ? (
        <div className="px-4 py-8 text-center text-xs text-[var(--text-tertiary)]">
          No gateway activity yet.
        </div>
      ) : (
        <ul className="divide-y divide-[var(--border-subtle)]">
          {rows.map((event, i) => {
            const blocked = event.action_type === "tool_call_blocked";
            return (
              <li
                key={`${event.ts}-${event.agent}-${i}`}
                className="flex items-start gap-3 px-4 py-3 transition-colors hover:bg-[var(--surface-elevated)]/40"
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
                    <span className="truncate text-sm font-medium text-[var(--foreground)]">
                      {decisionTitle(event)}
                    </span>
                    <time className="shrink-0 text-[10px] tabular-nums text-[var(--text-tertiary)]">
                      {eventTime(event.ts)}
                    </time>
                  </div>
                  <code
                    className="mt-0.5 block truncate font-mono text-xs text-[var(--text-secondary)]"
                    title={`${event.agent} → ${event.target}`}
                  >
                    {event.agent} → {event.target}
                  </code>
                  <p className="mt-0.5 truncate text-xs text-[var(--text-tertiary)]">
                    {subLabel(event)}
                  </p>
                </div>
              </li>
            );
          })}
        </ul>
      )}

      {/* Aggregate footer */}
      <div className="mt-auto border-t border-[var(--border-subtle)] px-4 py-2.5">
        <p className="truncate text-center text-[11px] tabular-nums text-[var(--text-tertiary)]">
          {footerText(kpis)}
        </p>
      </div>
    </div>
  );
}
