"use client";

import { useEffect, useState } from "react";
import {
  Clock,
  Bot,
  Terminal,
  Wrench,
  Zap,
  Search,
  Loader2,
} from "lucide-react";
import { api, formatDate } from "@/lib/api";
import type { ActivitySource, ActivityTimeline } from "@/lib/api";
import { useChartTheme } from "@/lib/theme-colors";
import { IntegrationRequiredState } from "@/components/integration-required-state";
import { ActivityEventStream } from "@/components/activity-event-stream";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

export default function ActivityPage() {
  const chart = useChartTheme();
  const [timeline, setTimeline] = useState<ActivityTimeline | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(30);
  const [search, setSearch] = useState("");

  const load = () => {
    setLoading(true);
    setError(null);
    api
      .getActivity(days)
      .then(setTimeline)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      load();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [days]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) {
    return (
      <div className="space-y-6">
        <ActivityEventStream observabilityEvents={[]} />
        <div className="flex items-center justify-center py-20 text-[var(--text-secondary)]">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading activity timeline...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <ActivityEventStream observabilityEvents={[]} />
        <IntegrationRequiredState
        title="Activity timeline is unavailable"
        summary="This page shows agent and MCP tool activity from every connected source. Runtime activity needs no external warehouse — it comes from the proxy, gateway, and OTel ingest. Snowflake query history is an optional additional source."
        requirement="A reachable API host"
        command={"agent-bom proxy -- <your-mcp-server>\n# optional warehouse source:\nexport SNOWFLAKE_ACCOUNT=..."}
        capabilities={[
          "Agent and MCP tool calls with verdicts and severity",
          "Tool-call and model-usage activity over time",
          "Warehouse query history, when a warehouse is connected",
        ]}
          detail={error}
          onRetry={load}
        />
      </div>
    );
  }

  if (!timeline)
    return (
      <div className="space-y-6">
        <ActivityEventStream observabilityEvents={[]} />
      </div>
    );

  // Snowflake is one source of activity, not the definition of it. Its
  // query-history views render only when it is actually wired up; everything
  // above them comes from the runtime store, which every deployment has.
  const snowflake = timeline.sources.find((s) => s.source === "snowflake");
  const warehouse = snowflake?.timeline;

  const runtimeEvents = timeline.events.filter(
    (e) =>
      !search ||
      e.agent_name.toLowerCase().includes(search.toLowerCase()) ||
      e.tool_name.toLowerCase().includes(search.toLowerCase()) ||
      e.event_type.toLowerCase().includes(search.toLowerCase())
  );

  const filteredQueries = (warehouse?.query_history ?? []).filter(
    (q) =>
      !search ||
      q.query_text.toLowerCase().includes(search.toLowerCase()) ||
      q.agent_pattern.toLowerCase().includes(search.toLowerCase()) ||
      q.user_name.toLowerCase().includes(search.toLowerCase())
  );

  // Aggregate query patterns
  const patternCounts: Record<string, number> = {};
  for (const q of warehouse?.query_history ?? []) {
    if (q.agent_pattern) {
      patternCounts[q.agent_pattern] = (patternCounts[q.agent_pattern] || 0) + 1;
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--foreground)] flex items-center gap-2">
            <Clock className="w-6 h-6 text-emerald-400" />
            Agent Activity Timeline
          </h1>
          <p className="text-sm text-[var(--text-tertiary)] mt-1">
            {timeline.event_count.toLocaleString()} events across the last {timeline.window_days} days
            {timeline.truncated ? " (showing the most recent 500)" : ""}
          </p>
        </div>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-md px-3 py-1.5 text-sm text-[var(--text-secondary)]"
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
          <option value={365}>Last 365 days</option>
        </select>
      </div>

      <ActivityEventStream observabilityEvents={warehouse?.observability_events ?? []} />

      {/* Which sources are feeding this page, and which are not. An operator
          who cannot tell "quiet" from "unconfigured" cannot act on either. */}
      <SourceStrip sources={timeline.sources} />

      {/* Summary cards — runtime first, because that source needs no warehouse. */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          icon={Zap}
          label="Runtime Events"
          value={timeline.events.filter((e) => e.source === "runtime").length}
          color="text-emerald-400"
        />
        <StatCard
          icon={Bot}
          label="Agents Seen"
          value={new Set(timeline.events.map((e) => e.agent_name).filter(Boolean)).size}
          color="text-amber-400"
        />
        <StatCard
          icon={Wrench}
          label="Tools Called"
          value={new Set(timeline.events.map((e) => e.tool_name).filter(Boolean)).size}
          color="text-cyan-400"
        />
        <StatCard
          icon={Terminal}
          label="Warehouse Queries"
          value={warehouse?.summary.total_queries ?? 0}
          color="text-blue-400"
        />
        <StatCard
          icon={Bot}
          label="Agent Queries"
          value={warehouse?.summary.agent_queries ?? 0}
          color="text-purple-400"
        />
      </div>

      {/* Warnings */}
      {(warehouse?.warnings?.length ?? 0) > 0 && (
        <div className="rounded-lg border border-yellow-800/50 bg-yellow-950/20 p-4">
          <p className="text-xs font-medium text-yellow-400 mb-2">Warnings</p>
          {warehouse?.warnings?.map((w, i) => (
            <p key={i} className="text-xs text-yellow-300/70">{w}</p>
          ))}
        </div>
      )}

      {/* Runtime activity — the agent/MCP story, present without any warehouse. */}
      <div>
        <h2 className="text-sm font-semibold text-[var(--foreground)]">
          Runtime activity ({runtimeEvents.length})
        </h2>
        <p className="mt-1 text-xs text-[var(--text-tertiary)]">
          Agent and MCP tool calls observed by the proxy, gateway, and OTel ingest.
        </p>
      </div>
      <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[var(--text-tertiary)] border-b border-[var(--border-subtle)] bg-[var(--surface)]">
                <th className="text-left py-2 px-3">Time</th>
                <th className="text-left py-2 px-3">Agent</th>
                <th className="text-left py-2 px-3">Tool</th>
                <th className="text-left py-2 px-3">Event</th>
                <th className="text-left py-2 px-3">Verdict</th>
                <th className="text-left py-2 px-3">Severity</th>
              </tr>
            </thead>
            <tbody>
              {runtimeEvents.slice(0, 100).map((e, i) => (
                <tr
                  key={`${e.session_id ?? ""}-${e.observed_at}-${i}`}
                  className="border-b border-[var(--border-subtle)]/50 hover:bg-[var(--surface-elevated)]/30"
                >
                  <td className="py-1.5 px-3 text-[var(--text-tertiary)] whitespace-nowrap">
                    {formatDate(e.observed_at)}
                  </td>
                  <td className="py-1.5 px-3 text-[var(--text-secondary)] font-mono">{e.agent_name || "-"}</td>
                  <td className="py-1.5 px-3 text-[var(--text-secondary)] font-mono">{e.tool_name || "-"}</td>
                  <td className="py-1.5 px-3 text-[var(--text-secondary)]">{e.event_type}</td>
                  <td className="py-1.5 px-3">
                    <StatusBadge status={e.verdict} />
                  </td>
                  <td className="py-1.5 px-3 text-[var(--text-tertiary)]">{e.severity}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {runtimeEvents.length === 0 && (
            <div className="text-center py-8 text-[var(--text-tertiary)] text-sm">
              No runtime activity in this window.
            </div>
          )}
        </div>
      </div>

      {/* Activity bar chart */}
      {Object.keys(patternCounts).length > 0 && (
        <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] mb-1">Agent Query Patterns</h3>
          <p className="text-[10px] text-[var(--text-tertiary)] mb-4">Query count by detected agent pattern</p>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={Object.entries(patternCounts)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 12)
                  .map(([pattern, count]) => ({ pattern: pattern.length > 18 ? pattern.slice(0, 16) + "…" : pattern, count }))}
                margin={{ top: 4, right: 8, bottom: 4, left: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke={chart.grid} vertical={false} />
                <XAxis dataKey="pattern" tick={{ fontSize: 9, fill: chart.text }} tickLine={false} axisLine={{ stroke: chart.border }} />
                <YAxis tick={{ fontSize: 10, fill: chart.text }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                <Tooltip
                  contentStyle={{ background: chart.tooltip.bg, border: `1px solid ${chart.tooltip.border}`, borderRadius: 8, fontSize: 12 }}
                  itemStyle={{ color: chart.tooltip.text }}
                  labelStyle={{ color: chart.text, marginBottom: 4 }}
                />
                <Bar dataKey="count" name="queries" fill={chart.accent} radius={[4, 4, 0, 0]} fillOpacity={0.75} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Query history remains a distinct evidence type — and only renders when
          the warehouse it comes from is actually connected. */}
      {warehouse && (
      <>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-[var(--foreground)]">
            Query history ({warehouse.query_history.length})
          </h2>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            Warehouse query evidence is kept separate from runtime decisions and AI telemetry.
          </p>
        </div>
        <div className="relative flex-1 max-w-xs">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-tertiary)]" />
          <input
            type="text"
            placeholder="Search..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[var(--surface)] border border-[var(--border-subtle)] rounded-md pl-9 pr-3 py-1.5 text-sm text-[var(--text-secondary)] placeholder-[var(--text-tertiary)]"
          />
        </div>
      </div>

      <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[var(--text-tertiary)] border-b border-[var(--border-subtle)] bg-[var(--surface)]">
                  <th className="text-left py-2 px-3">Time</th>
                  <th className="text-left py-2 px-3">User</th>
                  <th className="text-left py-2 px-3">Role</th>
                  <th className="text-left py-2 px-3">Pattern</th>
                  <th className="text-left py-2 px-3">Query</th>
                  <th className="text-left py-2 px-3">Status</th>
                  <th className="text-right py-2 px-3">Time (ms)</th>
                </tr>
              </thead>
              <tbody>
                {filteredQueries.slice(0, 100).map((q) => (
                  <tr
                    key={q.query_id}
                    className="border-b border-[var(--border-subtle)]/50 hover:bg-[var(--surface-elevated)]/30"
                  >
                    <td className="py-1.5 px-3 text-[var(--text-tertiary)] whitespace-nowrap">
                      {formatDate(q.start_time)}
                    </td>
                    <td className="py-1.5 px-3 text-[var(--text-secondary)] font-mono">
                      {q.user_name}
                    </td>
                    <td className="py-1.5 px-3 text-[var(--text-secondary)] font-mono">
                      {q.role_name}
                    </td>
                    <td className="py-1.5 px-3">
                      {q.is_agent_query ? (
                        <span className="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-400 border border-emerald-800">
                          {q.agent_pattern}
                        </span>
                      ) : (
                        <span className="text-[var(--text-tertiary)]">-</span>
                      )}
                    </td>
                    <td className="py-1.5 px-3 text-[var(--text-secondary)] font-mono truncate max-w-[300px]">
                      {q.query_text}
                    </td>
                    <td className="py-1.5 px-3">
                      <StatusBadge status={q.execution_status} />
                    </td>
                    <td className="py-1.5 px-3 text-right text-[var(--text-tertiary)] font-mono">
                      {q.execution_time_ms.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredQueries.length === 0 && (
              <div className="text-center py-8 text-[var(--text-tertiary)] text-sm">
                No queries match the search.
              </div>
            )}
          </div>
        </div>
      </>
      )}
    </div>
  );
}

/** Per-source state, so an unconfigured source is visible rather than absent.
 *
 * Omitting a source that is not wired up would make a partial timeline look
 * complete — the operator would have no way to know what they are missing.
 */
function SourceStrip({ sources }: { sources: ActivitySource[] }) {
  const tone: Record<string, string> = {
    active: "text-emerald-400 bg-emerald-950/40 border-emerald-800",
    empty: "text-[var(--text-secondary)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]",
    not_configured: "text-amber-400 bg-amber-950/30 border-amber-800/60",
    unavailable: "text-red-400 bg-red-950/30 border-red-800/60",
  };
  const label: Record<string, string> = {
    active: "active",
    empty: "no events",
    not_configured: "not connected",
    unavailable: "unavailable",
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      {sources.map((s) => (
        <span
          key={s.source}
          title={s.detail || undefined}
          className={`px-2.5 py-1 rounded-md text-xs border ${tone[s.status] ?? tone.empty}`}
        >
          <span className="font-medium capitalize">{s.source}</span>
          <span className="opacity-70"> · {label[s.status] ?? s.status}</span>
          {s.event_count > 0 && <span className="opacity-70"> · {s.event_count.toLocaleString()}</span>}
        </span>
      ))}
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="text-xs text-[var(--text-tertiary)]">{label}</span>
      </div>
      <p className="text-2xl font-bold text-[var(--foreground)]">{value.toLocaleString()}</p>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color =
    status === "SUCCESS"
      ? "text-emerald-400 bg-emerald-950 border-emerald-800"
      : status === "FAIL" || status === "FAILED"
        ? "text-red-400 bg-red-950 border-red-800"
        : "text-[var(--text-secondary)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]";

  return (
    <span className={`px-2 py-0.5 rounded text-xs border ${color}`}>
      {status}
    </span>
  );
}
