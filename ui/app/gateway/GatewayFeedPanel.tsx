"use client";

import { useEffect, useRef, useState } from "react";
import {
  api,
  type GatewayFeedActionType,
  type GatewayFeedEvent,
  formatDate,
} from "@/lib/api";
import { getSessionWebSocketToken } from "@/lib/auth";
import { getConfiguredApiUrl } from "@/lib/runtime-config";
import {
  Activity,
  Ban,
  Clock,
  EyeOff,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Wifi,
  WifiOff,
} from "lucide-react";

// ─── Action badge styling ─────────────────────────────────────────────────────

const ACTION_META: Record<
  GatewayFeedActionType,
  { label: string; badge: string; icon: React.ElementType; tone: string }
> = {
  tool_call_authorized: {
    label: "authorized",
    badge: "bg-emerald-950 text-emerald-300 border-emerald-800",
    icon: ShieldCheck,
    tone: "text-emerald-400",
  },
  tool_call_blocked: {
    label: "blocked",
    badge: "bg-red-950 text-red-300 border-red-800",
    icon: Ban,
    tone: "text-red-400",
  },
  data_filter_applied: {
    label: "data filter",
    badge: "bg-amber-950 text-amber-300 border-amber-800",
    icon: EyeOff,
    tone: "text-amber-400",
  },
  llm_call: {
    label: "LLM call",
    badge: "bg-blue-950 text-blue-300 border-blue-800",
    icon: Sparkles,
    tone: "text-blue-400",
  },
};

// Live counters streamed by the existing /ws/proxy/metrics WebSocket. We use it
// only to drive the "Live" indicator and refresh the KPI header in near-real
// time; the authoritative fused feed is fetched from /v1/gateway/feed.
interface LiveMetrics {
  ts: number;
  total_tool_calls: number;
  total_blocked: number;
}

function formatEventTime(ts: string): string {
  if (!ts) return "—";
  try {
    return formatDate(ts);
  } catch {
    return ts;
  }
}

// ─── Panel ────────────────────────────────────────────────────────────────────

export function GatewayFeedPanel({ onActivity }: { onActivity?: () => void }) {
  const [events, setEvents] = useState<GatewayFeedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState<GatewayFeedActionType | "">("");
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    void Promise.allSettled([api.getGatewayFeed(200)])
      .then(([feedResult]) => {
        const failures: string[] = [];
        if (feedResult.status === "fulfilled") {
          setEvents(feedResult.value.events);
        } else {
          failures.push(`feed: ${feedResult.reason?.message ?? "request failed"}`);
        }
        setError(failures.length === 0 ? null : failures.join("; "));
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = window.setTimeout(() => load(), 0);
    return () => window.clearTimeout(timer);
  }, []);

  // Reuse the existing proxy metrics WebSocket for a live indicator + a light
  // periodic refresh. When new total_tool_calls/total_blocked counters tick we
  // re-pull the fused feed (the WS itself does not carry fused events).
  useEffect(() => {
    const base = getConfiguredApiUrl() || window.location.origin;
    const wsTarget = new URL(base.replace(/^http/, "ws") + "/ws/proxy/metrics");
    const token = getSessionWebSocketToken();
    const wsUrl = wsTarget.toString();

    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;
    let lastSeen = -1;
    let lastRefresh = 0;

    const connect = () => {
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => {
        if (token) ws.send(JSON.stringify({ type: "auth", token }));
        setWsConnected(true);
      };
      ws.onclose = () => {
        setWsConnected(false);
        reconnectTimer = setTimeout(connect, 5000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data) as { type?: string } & LiveMetrics;
          if (payload?.type === "auth") return;
          const total = (payload.total_tool_calls ?? 0) + (payload.total_blocked ?? 0);
          const now = Date.now();
          // Refresh the fused feed when the counter advances, throttled to at
          // most once every 3s so a busy fleet doesn't hammer the API.
          if (total !== lastSeen && now - lastRefresh > 3000) {
            lastSeen = total;
            lastRefresh = now;
            void api.getGatewayFeed(200).then((feedResult) => {
              setEvents(feedResult.events);
              onActivity?.();
            });
          }
        } catch {
          // ignore parse errors
        }
      };
    };

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [onActivity]);

  const filtered = actionFilter ? events.filter((e) => e.action_type === actionFilter) : events;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
              <Activity className="h-4 w-4 text-emerald-400" />
              Gateway live feed
            </h3>
            <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]">
              Tool-call authorization, data filters, and blocks — per agent and target
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs">
              {wsConnected ? (
                <>
                  <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Live</span>
                </>
              ) : (
                <>
                  <WifiOff className="w-3.5 h-3.5 text-zinc-500" />
                  <span className="text-zinc-500">Disconnected</span>
                </>
              )}
            </div>
            <button
              onClick={load}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Refresh
            </button>
          </div>
        </div>

        {/* Action filter */}
        <div className="flex flex-wrap gap-1 mb-4">
          {(
            [
              ["", "All"],
              ["tool_call_authorized", "Authorized"],
              ["tool_call_blocked", "Blocked"],
              ["data_filter_applied", "Data filters"],
              ["llm_call", "LLM calls"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value || "all"}
              onClick={() => setActionFilter(value as GatewayFeedActionType | "")}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                actionFilter === value
                  ? "bg-zinc-700 text-zinc-100"
                  : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {loading && (
          <div className="flex items-center justify-center py-10">
            <Loader2 className="w-5 h-5 animate-spin text-zinc-500" />
          </div>
        )}

        {error && !loading && (
          <div className="text-center py-8 text-xs text-red-400">{error}</div>
        )}

        {!loading && !error && filtered.length === 0 && (
          <div className="text-center py-10">
            <ShieldCheck className="w-6 h-6 text-emerald-600 mx-auto mb-2" />
            <p className="text-zinc-600 text-xs">
              No gateway activity yet. Events appear as agents call tools through the gateway/proxy.
            </p>
          </div>
        )}

        {!loading && !error && filtered.length > 0 && (
          <div className="space-y-1 max-h-[32rem] overflow-y-auto">
            {filtered.map((event, i) => (
              <FeedRow key={`${event.ts}-${event.agent}-${i}`} event={event} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Feed row ─────────────────────────────────────────────────────────────────

function FeedRow({ event }: { event: GatewayFeedEvent }) {
  const meta = ACTION_META[event.action_type];
  const Icon = meta.icon;
  return (
    <div className="flex items-center justify-between px-3 py-2 bg-zinc-800/50 border border-zinc-800 rounded-lg">
      <div className="flex items-center gap-3 min-w-0">
        <Icon className={`w-3.5 h-3.5 shrink-0 ${meta.tone}`} />
        {/* Per-agent attribution → target */}
        <span className="text-xs text-zinc-200 font-mono shrink-0 max-w-[10rem] truncate" title={event.agent}>
          {event.agent}
        </span>
        <span className="text-zinc-600 shrink-0 text-xs">→</span>
        <span className="text-xs text-zinc-400 font-mono shrink-0 max-w-[12rem] truncate" title={event.target}>
          {event.target}
        </span>
        <span className={`shrink-0 rounded border px-1.5 py-0.5 text-xs ${meta.badge}`}>
          {meta.label}
        </span>
        {event.shadow && (
          <span className="shrink-0 rounded border border-orange-800 bg-orange-950 px-1.5 py-0.5 text-xs text-orange-300">
            shadow AI
          </span>
        )}
        <span className="text-xs text-zinc-500 truncate" title={event.detail}>
          {event.detail}
        </span>
      </div>
      <span className="ml-3 flex shrink-0 items-center gap-1 text-xs text-[color:var(--text-tertiary)]">
        <Clock className="w-3 h-3" />
        {formatEventTime(event.ts)}
      </span>
    </div>
  );
}
